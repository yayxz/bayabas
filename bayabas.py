#!/usr/bin/env python3
"""
Bayabas: authorized Nmap scan orchestration and configuration-audit framework.

Use only against systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import importlib.util
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from Core import resolve as core_resolve
from typing import Any, Iterable

APP = "Bayabas"
VERSION = "0.10.16"
ROOT = Path(__file__).resolve().parent
MODULES_DIR = ROOT / "Modules"

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
TIME_RE = re.compile(r"^\d+(?:ms|s|m|h)?$", re.I)


CURRENT_ASSESSMENT_PATH: Path | None = None


class GracefulInterrupt(Exception):
    """Raised when the operator requests a graceful Bayabas exit."""




@dataclass(frozen=True)
class PortPlan:
    args: list[str]
    tcp: bool
    udp: bool
    description: str
    tcp_ports: tuple[int, ...] = ()
    udp_ports: tuple[int, ...] = ()


@dataclass
class FamilyContext:
    family: int
    label: str
    targets: list[str]
    scan_root: Path
    db_root: Path
    discovery_dir: Path
    initial_dir: Path
    final_dir: Path
    original_targets_file: Path
    discovery_targets_file: Path
    initial_live_hosts_file: Path
    tcp_ports_file: Path
    udp_ports_file: Path
    db_path: Path
    flat_db_path: Path
    hostname_map_path: Path
    resolutions_path: Path
    hosts_path: Path
    scan_id: int | None = None
    final_output_base: Path | None = None


@dataclass(frozen=True)
class ModuleContext:
    root: Path
    family: int
    family_label: str
    db_path: Path
    flat_db_path: Path
    findings_dir: Path
    scans_dir: Path
    scan_id: int
    nmap_path: str

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def finding_dir(self, *parts: str) -> Path:
        path = self.findings_dir.joinpath(*parts)
        path.mkdir(parents=True, exist_ok=True)
        return path


def die(message: str, code: int = 1) -> None:
    print(f"[!] {message}", file=sys.stderr)
    raise SystemExit(code)


def prompt(label: str, default: str | None = None, validator=None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        value = value or (default if default is not None else "")
        if validator is None or validator(value):
            return value
        print("[!] Invalid value.")


def yes_no(label: str, default: bool = False) -> bool:
    marker = "Y/n" if default else "y/N"
    value = input(f"{label} [{marker}]: ").strip().lower()
    return default if not value else value in {"y", "yes"}


def positive_int(value: str) -> bool:
    return value.isdigit() and int(value) > 0


def nonnegative_int(value: str) -> bool:
    return value.isdigit() and int(value) >= 0


def valid_time(value: str) -> bool:
    return bool(TIME_RE.fullmatch(value))


def valid_mtu(value: str) -> bool:
    return value.isdigit() and 8 <= int(value) <= 65528 and int(value) % 8 == 0


def valid_rate(value: str) -> bool:
    try:
        return float(value) > 0
    except ValueError:
        return False


def valid_dns(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.fullmatch(value))



def valid_assessment_name(value: str) -> bool:
    """Allow readable directory names without path traversal or separators."""
    if not value or value in {".", ".."}:
        return False
    if "/" in value or "\\" in value or "\x00" in value:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,99}", value))


def resolve_assessment_root(base_output: str, assessment_name: str) -> Path:
    """
    Resolve and validate the user-selected assessment directory.

    The base output directory may already exist or may be created. The final
    assessment directory must not already exist, preventing accidental
    overwrite of prior scan data.
    """
    base = Path(base_output).expanduser().resolve()

    if base.exists() and not base.is_dir():
        die(f"Base output path is not a directory: {base}")

    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        die(f"Could not create base output directory {base}: {exc}")

    assessment_root = base / assessment_name
    if assessment_root.exists():
        die(
            "Assessment output already exists and will not be overwritten: "
            f"{assessment_root}"
        )

    return assessment_root


def ensure_dependencies() -> str:
    nmap = shutil.which("nmap")
    if not nmap:
        die("Nmap is not installed or available in PATH.")
    return nmap


LARGE_TARGET_THRESHOLD = 250


def estimate_target_scale(targets: list[str], cap: int = 1_000_000_000) -> int:
    """Estimate scope size without expanding CIDRs in memory."""
    total = 0
    for target in targets:
        try:
            total += ipaddress.ip_network(target, strict=False).num_addresses
        except ValueError:
            total += 1
        if total >= cap:
            return cap
    return total


def advise_terminal_multiplexer(target_count: int, non_interactive: bool) -> None:
    """Offer to run the whole program in Screen for large scopes."""
    if target_count < LARGE_TARGET_THRESHOLD or os.environ.get("STY") or os.environ.get("TMUX"):
        return

    argv = [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]
    command_text = " ".join(shlex.quote(x) for x in argv)
    rerun = "screen -S bayabas bash -lc " + shlex.quote(command_text)
    print(
        f"[!] Large target scope detected (estimated {target_count} addresses/targets). "
        "Long assessments are best run inside a terminal multiplexer such as GNU Screen "
        "or tmux so a terminal disconnect does not terminate Bayabas."
    )

    screen = shutil.which("screen")
    if not screen:
        print("[*] GNU Screen is not installed. Common install commands:")
        print("    Debian/Ubuntu/Kali: sudo apt update && sudo apt install -y screen")
        print("    RHEL/Fedora:        sudo dnf install -y screen")
        print("    Alpine:             sudo apk add screen")
        print("    macOS (Homebrew):   brew install screen")
        print(f"[*] After installation, run: {rerun}")
        if non_interactive:
            print("[*] Non-interactive mode: continuing in the current terminal.")
            return
        if not yes_no("Continue without GNU Screen?", False):
            raise SystemExit(0)
        return

    print(f"[*] Screen command: {rerun}")
    if non_interactive:
        print("[*] Non-interactive mode: continuing in the current terminal.")
        return

    if yes_no("Run the entire Bayabas process inside GNU Screen now?", True):
        # Replace this process with one attached Screen session. The child
        # Bayabas process sees $STY and therefore does not prompt again.
        os.execvp(screen, [screen, "-S", "bayabas", *argv])


def normalize_target(value: str) -> str:
    value = value.strip()
    if re.match(r"^https?://", value, re.I):
        parsed = urlsplit(value)
        if not parsed.hostname:
            raise ValueError(f"Invalid URL target: {value!r}")
        return parsed.hostname.rstrip(".").lower()
    return value


def classify_target(value: str) -> str:
    value = normalize_target(value)
    try:
        network = ipaddress.ip_network(value, strict=False)
        return f"ipv{network.version}"
    except ValueError:
        if HOSTNAME_RE.fullmatch(value):
            return "hostname"
    raise ValueError(f"Invalid target: {value!r}")


def load_targets(raw: str) -> list[str]:
    path = Path(raw).expanduser()
    values: list[str] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            clean = line.split("#", 1)[0].strip()
            if clean:
                values.extend(x.strip() for x in clean.split(",") if x.strip())
    else:
        values = [x.strip() for x in raw.split(",") if x.strip()]
    if not values:
        die("No targets supplied.")

    result: list[str] = []
    seen: set[str] = set()
    invalid: list[str] = []
    for original in values:
        try:
            value = normalize_target(original)
            classify_target(value)
        except ValueError:
            invalid.append(original)
            continue
        if value not in seen:
            seen.add(value)
            result.append(value)

    if invalid:
        print(f"[!] Skipped {len(invalid)} invalid target(s): " + ", ".join(repr(v) for v in invalid))
    if not result:
        die("No valid targets remained after filtering invalid entries.")
    return result


def infer_assessment_type(targets: list[str]) -> str:
    private = public = False
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            continue
        if network.is_private or network.is_link_local:
            private = True
        else:
            public = True
    if private and not public:
        return "internal"
    return "external"


def normalize_client_domains(values: list[str]) -> list[str]:
    result = []
    for raw in values:
        for item in raw.split(","):
            domain = item.strip().lower().rstrip(".")
            if domain and HOSTNAME_RE.fullmatch(domain) and domain not in result:
                result.append(domain)
    return result


def external_passive_tool_status() -> dict[str, str | None]:
    return {name: shutil.which(name) for name in ("subfinder", "amass", "assetfinder", "findomain")}


def passive_subdomain_enumeration(domains: list[str], database_root: Path) -> set[str]:
    """Run installed passive-only CLI enumerators and merge authorized-domain results."""
    status = external_passive_tool_status()
    print("[*] Passive external enumeration capability check:")
    install = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass": "sudo apt install -y amass",
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "findomain": "Install Findomain from its official GitHub release/package for your OS",
    }
    for name, path in status.items():
        print(f"    {'[+]' if path else '[-]'} {name:<12} {'FOUND' if path else 'MISSING'}")
        if not path:
            print(f"        install: {install[name]}")

    found: set[str] = set()
    provenance: dict[str, set[str]] = {}
    commands = {
        "subfinder": lambda d: [status["subfinder"], "-silent", "-d", d],
        "amass": lambda d: [status["amass"], "enum", "-passive", "-d", d],
        "assetfinder": lambda d: [status["assetfinder"], "--subs-only", d],
        "findomain": lambda d: [status["findomain"], "-q", "-t", d],
    }
    for domain in domains:
        for tool, path in status.items():
            if not path:
                continue
            try:
                cp = subprocess.run(commands[tool](domain), text=True, capture_output=True, timeout=300, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(f"[!] {tool} failed for {domain}: {exc}", file=sys.stderr)
                continue
            for line in cp.stdout.splitlines():
                host = line.strip().lower().rstrip(".")
                if HOSTNAME_RE.fullmatch(host) and (host == domain or host.endswith("." + domain)):
                    found.add(host)
                    provenance.setdefault(host, set()).add(tool)

    write_lines(database_root / "domain_discovery_list.txt", sorted(found))
    write_lines(database_root / "subdomain_sources.txt", [f"{h}\t{','.join(sorted(provenance[h]))}" for h in sorted(provenance)])
    print(f"[*] Passive enumeration merged {len(found)} unique in-scope hostname(s).")
    return found

def resolve_hostname(
    hostname: str,
    family: int,
    dns_server: str | None = None,
    timeout: float = 5.0,
) -> set[str]:
    """
    Resolve a hostname to addresses for the given IP family.

    If dns_server is set, queries it explicitly via the same `host`
    command Core/resolve.py already uses, so a custom engagement DNS
    server configured at the earlier prompt is actually honored here too
    -- not just during the separate preflight resolution pass. With no
    dns_server, falls back to the system resolver, which is what handles
    ordinary internet-accessible hostnames.

    Either path is bounded by `timeout`. A single slow or unreachable
    hostname must never be able to hang the whole run with no feedback --
    it's logged and treated as unresolved so the tool can keep going.
    """
    if dns_server:
        return _resolve_via_dns_server(hostname, family, dns_server, timeout)
    return _resolve_via_system_resolver(hostname, family, timeout)


def _resolve_via_system_resolver(hostname: str, family: int, timeout: float) -> set[str]:
    af = socket.AF_INET if family == 4 else socket.AF_INET6

    def lookup() -> set[str]:
        try:
            return {
                item[4][0]
                for item in socket.getaddrinfo(
                    hostname.rstrip("."), None, family=af, type=socket.SOCK_STREAM
                )
            }
        except socket.gaierror:
            return set()

    # socket.getaddrinfo() ignores socket.setdefaulttimeout() -- it's a
    # blocking libc call, not a socket read -- so the only reliable way
    # to bound it is to run it on a worker thread and give up waiting.
    # The worker itself is left to finish in the background; Python
    # cannot forcibly kill it, but the caller is no longer blocked on it.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(lookup)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            print(
                f"[!] DNS resolution timed out after {timeout:g}s for "
                f"{hostname} (system resolver); treating as unresolved."
            )
            return set()


_HOST_ADDRESS_RE = re.compile(r"has (?:address|IPv6 address) (\S+)")


def _resolve_via_dns_server(
    hostname: str, family: int, dns_server: str, timeout: float
) -> set[str]:
    record_type = "A" if family == 4 else "AAAA"
    command = ["host", "-t", record_type, hostname.rstrip("."), dns_server]
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(
            f"[!] DNS resolution timed out after {timeout:g}s for "
            f"{hostname} (server {dns_server}); treating as unresolved."
        )
        return set()
    except FileNotFoundError:
        print("[!] 'host' command not found; falling back to system resolver.")
        return _resolve_via_system_resolver(hostname, family, timeout)

    addresses: set[str] = set()
    for line in completed.stdout.splitlines():
        match = _HOST_ADDRESS_RE.search(line)
        if match:
            addresses.add(match.group(1).rstrip("."))
    return addresses


def split_targets(
    targets: list[str],
    ipv6_enabled: bool,
    dns_server: str | None = None,
    workers: int = 16,
) -> tuple[list[str], list[str], set[tuple[str, str, str, int]]]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    mappings: set[tuple[str, str, str, int]] = set()

    hostnames: list[str] = []
    for target in targets:
        kind = classify_target(target)
        if kind == "ipv4":
            ipv4.add(target)
        elif kind == "ipv6":
            if ipv6_enabled:
                ipv6.add(target)
        else:
            hostnames.append(target.rstrip(".").lower())

    if hostnames:
        families = [4, 6] if ipv6_enabled else [4]
        lookups = [(hostname, family) for hostname in hostnames for family in families]

        # A large target list (thousands of hostnames, common with
        # subdomain enumeration or cloud asset inventories) resolved one
        # at a time here was slow enough to look identical to a hang, with
        # zero feedback either way. Resolving concurrently -- the same
        # pattern Core/resolve.py already uses for its own preflight pass
        # -- and reporting progress along the way fixes both problems.
        family_word = "family" if len(families) == 1 else "families"
        print(
            f"[*] Resolving {len(hostnames)} hostname target(s) "
            f"({len(lookups)} lookup(s) across {len(families)} address {family_word})..."
        )

        def do_lookup(item: tuple[str, int]) -> tuple[str, int, set[str]]:
            hostname, family = item
            return hostname, family, resolve_hostname(hostname, family, dns_server)

        completed = 0
        report_every = max(1, len(lookups) // 20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(do_lookup, item) for item in lookups]
            for future in concurrent.futures.as_completed(futures):
                hostname, family, addresses = future.result()
                if family == 6 and addresses:
                    # Preserve the hostname for IPv6 scans. Nmap is invoked with
                    # -6 --resolve-all -n so every AAAA target address is scanned.
                    ipv6.add(hostname)
                for address in addresses:
                    if family == 4:
                        ipv4.add(address)
                    mappings.add((hostname, address, "forward-target", family))
                completed += 1
                if completed % report_every == 0 or completed == len(lookups):
                    print(f"[*] Resolved {completed}/{len(lookups)} hostname lookup(s)...")

    return sorted(ipv4), sorted(ipv6), mappings


def classify_hostname_ipv6(
    targets: list[str],
    dns_server: str | None = None,
    workers: int = 16,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Resolve AAAA records for hostname targets regardless of IPv6 scan choice."""
    hostnames = sorted({
        target.rstrip(".").lower()
        for target in targets
        if classify_target(target) == "hostname"
    })
    if not hostnames:
        return [], []

    print(f"[*] Checking AAAA records for {len(hostnames)} hostname target(s)...")
    with_ipv6: list[tuple[str, str]] = []
    without_ipv6: list[str] = []

    def lookup(hostname: str) -> tuple[str, set[str]]:
        return hostname, resolve_hostname(hostname, 6, dns_server)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(lookup, hostname) for hostname in hostnames]
        for future in concurrent.futures.as_completed(futures):
            hostname, addresses = future.result()
            if addresses:
                for address in sorted(addresses, key=ipaddress.ip_address):
                    with_ipv6.append((hostname, address))
            else:
                without_ipv6.append(hostname)

    with_ipv6.sort(key=lambda item: (item[0], ipaddress.ip_address(item[1])))
    without_ipv6.sort()
    print(
        f"[*] IPv6 DNS classification: {len({h for h, _ in with_ipv6})} hostname(s) with AAAA; "
        f"{len(without_ipv6)} without AAAA."
    )
    return with_ipv6, without_ipv6


def _expand_port_tokens(value: str) -> set[int]:
    ports: set[int] = set()
    for token in (part.strip() for part in value.split(",")):
        if not token:
            continue
        if "-" in token:
            left_text, right_text = token.split("-", 1)
            if not left_text.isdigit() or not right_text.isdigit():
                raise ValueError(f"Invalid port range: {token}")
            left, right = int(left_text), int(right_text)
            if not 1 <= left <= right <= 65535:
                raise ValueError(f"Invalid port range: {token}")
            ports.update(range(left, right + 1))
        else:
            if not token.isdigit() or not 1 <= int(token) <= 65535:
                raise ValueError(f"Invalid port: {token}")
            ports.add(int(token))
    return ports


def parse_port_plan(value: str) -> PortPlan:
    raw = value.strip()
    if raw == "-":
        return PortPlan(["-p-"], True, False, "all TCP ports")
    if raw.lower() in {"top100", "top-100", "100"}:
        return PortPlan(["--top-ports", "100"], True, False, "top 100 TCP ports")
    if raw.lower() in {"top1000", "top-1000", "1000"}:
        return PortPlan(["--top-ports", "1000"], True, False, "top 1000 TCP ports")
    if not raw:
        raise ValueError("Empty port selection.")

    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()

    matches = list(re.finditer(r"(?:^|,)([TU]):", raw, re.I))
    if not matches:
        tcp_ports = _expand_port_tokens(raw)
    else:
        for index, match in enumerate(matches):
            protocol = match.group(1).upper()
            payload_start = match.end()
            payload_end = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
            payload = raw[payload_start:payload_end].strip(",")
            values = _expand_port_tokens(payload)
            if protocol == "T":
                tcp_ports.update(values)
            else:
                udp_ports.update(values)

    if not tcp_ports and not udp_ports:
        raise ValueError("No valid ports supplied.")

    normalized_parts = []
    if tcp_ports:
        normalized_parts.append("T:" + ",".join(map(str, sorted(tcp_ports))))
    if udp_ports:
        normalized_parts.append("U:" + ",".join(map(str, sorted(udp_ports))))
    normalized = ",".join(normalized_parts)

    return PortPlan(
        ["-p", normalized],
        bool(tcp_ports),
        bool(udp_ports),
        normalized,
        tuple(sorted(tcp_ports)),
        tuple(sorted(udp_ports)),
    )

def collect_scan_options(args: argparse.Namespace) -> tuple[PortPlan, list[str]]:
    quick = args.quick if args.non_interactive else yes_no("Use quick scan (-F)?", False)
    if quick:
        plan = PortPlan(["-F"], True, False, "Nmap fast scan (-F)")
    else:
        raw = args.ports
        if not raw and not args.non_interactive:
            raw = prompt("Ports (T:22,80,U:53 | - | top100 | top1000)", "top1000")
        if not raw:
            die("--ports is required unless --quick is used.")
        try:
            plan = parse_port_plan(raw)
        except ValueError as exc:
            die(str(exc))

    values = {
        "max_retries": args.max_retries,
        "max_scan_delay": args.max_scan_delay,
        "min_parallelism": args.min_parallelism,
        "mtu": args.mtu,
        "min_rate": args.min_rate,
        "max_hostgroup": args.max_hostgroup,
    }
    defaults = {
        "max_retries": ("2", nonnegative_int),
        "max_scan_delay": ("1s", valid_time),
        "min_parallelism": ("10", positive_int),
        "mtu": ("24", valid_mtu),
        "min_rate": ("100", valid_rate),
        "max_hostgroup": ("64", positive_int),
    }
    for key, (default, validator) in defaults.items():
        if not values[key] and not args.non_interactive:
            values[key] = prompt(key.replace("_", "-"), default, validator)
        if values[key] is None or not validator(str(values[key])):
            die(f"Missing or invalid --{key.replace('_', '-')}.")
    return plan, [
        "--max-retries", str(values["max_retries"]),
        "--max-scan-delay", str(values["max_scan_delay"]),
        "--min-parallelism", str(values["min_parallelism"]),
        "--mtu", str(values["mtu"]),
        "--min-rate", str(values["min_rate"]),
        "--max-hostgroup", str(values["max_hostgroup"]),
    ]


def make_family_context(assessment_root: Path, family: int, targets: list[str]) -> FamilyContext:
    label = f"IPv{family}"
    scan_root = assessment_root / "Scans" / label
    db_root = assessment_root / "Database" / label
    discovery = scan_root / "Discovery"
    initial = scan_root / "Initial"
    final = scan_root / "Final"
    for path in (discovery, initial, final, db_root):
        path.mkdir(parents=True, exist_ok=True)
    return FamilyContext(
        family=family,
        label=label,
        targets=targets,
        scan_root=scan_root,
        db_root=db_root,
        discovery_dir=discovery,
        initial_dir=initial,
        final_dir=final,
        original_targets_file=scan_root / "original_targets.txt",
        discovery_targets_file=discovery / "discovered_hosts.txt",
        initial_live_hosts_file=initial / "ini_scan_live_hosts.txt",
        tcp_ports_file=initial / "tcp_ports.txt",
        udp_ports_file=initial / "udp_ports.txt",
        db_path=db_root / "hosts_ports.sqlite3",
        flat_db_path=db_root / "host_port.txt",
        hostname_map_path=db_root / "hostname_ip_mapping.txt",
        resolutions_path=db_root / "resolutions.txt",
        hosts_path=db_root / "hosts.txt",
    )


def write_lines(path: Path, values: Iterable[str]) -> None:
    values = list(values)
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def nmap_family_arg(family: int) -> list[str]:
    # For IPv6 hostname targets, --resolve-all ensures all AAAA addresses are
    # considered. -n suppresses reverse-DNS lookups while target resolution
    # still occurs for hostnames supplied on the command line/input file.
    return ["-6", "--resolve-all", "-n"] if family == 6 else []


def discovery_command(nmap: str, context: FamilyContext, dns: str | None) -> list[str]:
    # Layer several discovery probes in the same spirit as mature scanners:
    # ICMP plus TCP SYN/ACK and UDP probes. Nmap also uses ARP/ND automatically
    # for directly connected Ethernet targets. Avoid raw-packet-only probes for
    # unprivileged users, where Nmap's connect-based discovery is safer.
    probes: list[str]
    if os.geteuid() == 0:
        if context.family == 4:
            probes = [
                "-PE", "-PP", "-PM",
                "-PS22,80,135,139,443,445,3389",
                "-PA80,443,445",
                "-PU53,123,161",
            ]
        else:
            probes = [
                "-PE",
                "-PS22,80,135,139,443,445,3389",
                "-PA80,443,445",
                "-PU53,123,161",
            ]
    else:
        probes = ["-PS80,443", "-PA80,443"]

    command = [
        nmap, *nmap_family_arg(context.family), "-sn", *probes,
        "--reason", "-v", "-iL", str(context.original_targets_file),
        "-oA", str(context.discovery_dir / "host_discovery"),
    ]
    if dns:
        command += ["--dns-servers", dns]
    return command


def scan_modes(plan: PortPlan) -> list[str]:
    if plan.tcp and plan.udp:
        return ["-sS" if os.geteuid() == 0 else "-sT", "-sU"]
    if plan.udp:
        return ["-sU"]
    return ["-sS" if os.geteuid() == 0 else "-sT"]


def initial_command(
    nmap: str,
    context: FamilyContext,
    target_file: Path,
    plan: PortPlan,
    timing: list[str],
    dns: str | None,
    discovery_done: bool,
) -> list[str]:
    command = [nmap, *nmap_family_arg(context.family), "--open", "-v", "-iL", str(target_file)]
    if discovery_done:
        command.append("-Pn")
    command += scan_modes(plan) + plan.args + timing
    if dns:
        command += ["--dns-servers", dns]
    command += ["-oA", str(context.initial_dir / "initial_scan")]
    return command


def extract_up_hosts(xml_path: Path, family: int) -> list[str]:
    root = ET.parse(xml_path).getroot()
    addr_type = "ipv4" if family == 4 else "ipv6"
    values: set[str] = set()
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        node = next((x for x in host.findall("address") if x.get("addrtype") == addr_type), None)
        if node is not None and node.get("addr"):
            values.add(node.get("addr"))
    return sorted(values, key=ipaddress.ip_address)


def extract_initial(xml_path: Path, context: FamilyContext) -> tuple[list[int], list[int], list[str]]:
    root = ET.parse(xml_path).getroot()
    addr_type = "ipv4" if context.family == 4 else "ipv6"
    tcp: set[int] = set()
    udp: set[int] = set()
    hosts: set[str] = set()
    for host in root.findall("host"):
        address_node = next((x for x in host.findall("address") if x.get("addrtype") == addr_type), None)
        if address_node is None:
            continue
        address = address_node.get("addr", "")
        open_found = False
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number = int(port.get("portid", "0"))
            protocol = port.get("protocol")
            if protocol == "tcp":
                tcp.add(number)
                open_found = True
            elif protocol == "udp":
                udp.add(number)
                open_found = True
        if open_found:
            hosts.add(address)
    tcp_list = sorted(tcp)
    udp_list = sorted(udp)
    host_list = sorted(hosts, key=ipaddress.ip_address)
    context.tcp_ports_file.write_text(",".join(map(str, tcp_list)) + ("\n" if tcp_list else ""), encoding="utf-8")
    context.udp_ports_file.write_text(",".join(map(str, udp_list)) + ("\n" if udp_list else ""), encoding="utf-8")
    write_lines(context.initial_live_hosts_file, host_list)
    return tcp_list, udp_list, host_list


def port_expression(tcp: list[int], udp: list[int]) -> str:
    values = []
    if tcp:
        values.append("T:" + ",".join(map(str, tcp)))
    if udp:
        values.append("U:" + ",".join(map(str, udp)))
    if not values:
        raise ValueError("No open ports found.")
    return ",".join(values)


def validate_output_base(raw: str, default_dir: Path) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = default_dir / path
    path = path.resolve()
    if not path.parent.exists():
        die(f"Output directory does not exist: {path.parent}")
    conflicts = [Path(str(path) + suffix) for suffix in ("", ".nmap", ".xml", ".gnmap")]
    existing = [x for x in conflicts if x.exists()]
    if existing:
        die("Final output already exists: " + ", ".join(map(str, existing)))
    return path


def final_command(
    nmap: str,
    context: FamilyContext,
    timing: list[str],
    tcp: list[int],
    udp: list[int],
) -> list[str]:
    assert context.final_output_base is not None
    command = [
        nmap, *nmap_family_arg(context.family), "--open", "-v",
        "--resolve-all", "-n", "-Pn",
        "-iL", str(context.initial_live_hosts_file), "-sV",
    ]
    if tcp and udp:
        command += ["-sS" if os.geteuid() == 0 else "-sT", "-sU"]
    elif udp:
        command += ["-sU"]
    else:
        command += ["-sS" if os.geteuid() == 0 else "-sT"]
    command += ["-p", port_expression(tcp, udp), *timing, "-oA", str(context.final_output_base)]
    return command


def run_scan_command(label: str, command: list[str], work_dir: Path) -> int:
    """Run a scan in the foreground and tee combined output to a log file."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
    log_file = work_dir / f"{safe}.log"
    started = time.monotonic()
    print(f"[*] Running {label} in the current Bayabas process.")
    try:
        with log_file.open("w", encoding="utf-8", errors="replace") as log:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="")
                log.write(line)
                log.flush()
            code = process.wait()
    except KeyboardInterrupt as exc:
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        print(f"\n[!] Interrupted {label}; the scan process was stopped.", file=sys.stderr)
        raise GracefulInterrupt from exc

    elapsed = int(time.monotonic() - started)
    print(f"\a[*] {label} completed after {elapsed}s (exit {code}).")
    if code != 0:
        print(f"[!] Full output saved to: {log_file}")
    return code


def reverse_names(address: str) -> set[str]:
    try:
        primary, aliases, _ = socket.gethostbyaddr(address)
    except (socket.herror, socket.gaierror, OSError):
        return set()
    return {x.rstrip(".").lower() for x in [primary, *aliases] if x}


def collect_family_mappings(
    family: int,
    explicit: set[tuple[str, str, str, int]],
    live_hosts: list[str],
    dns_server: str | None = None,
) -> set[tuple[str, str, str]]:
    result = {(h, a, s) for h, a, s, f in explicit if f == family}
    for address in live_hosts:
        for hostname in reverse_names(address):
            result.add((hostname, address, "reverse-ptr"))
            for resolved in resolve_hostname(hostname, family, dns_server):
                result.add((hostname, resolved, "forward-ptr"))
    return result


def write_resolution_files(context: FamilyContext, pairs: set[tuple[str, str, str]]) -> None:
    by_name: dict[str, set[str]] = {}
    by_address: dict[str, set[str]] = {}
    for hostname, address, _ in pairs:
        by_name.setdefault(hostname, set()).add(address)
        by_address.setdefault(address, set()).add(hostname)

    context.resolutions_path.write_text(
        "".join(f"{hostname}, {address}, {source}\n" for hostname, address, source in sorted(pairs)),
        encoding="utf-8",
    )
    lines = ["ALL HOSTNAME/IP RELATIONSHIPS"]
    lines.extend(f"{h}, {a}, {s}" for h, a, s in sorted(pairs))
    lines += ["", "HOSTNAMES RESOLVING TO MULTIPLE IP ADDRESSES"]
    multi_names = [(h, a) for h, a in by_name.items() if len(a) > 1]
    lines.extend(f"{h}: {', '.join(sorted(a))}" for h, a in sorted(multi_names))
    if not multi_names:
        lines.append("none")
    lines += ["", "IP ADDRESSES ASSOCIATED WITH MULTIPLE HOSTNAMES"]
    multi_addresses = [(a, h) for a, h in by_address.items() if len(h) > 1]
    lines.extend(f"{a}: {', '.join(sorted(h))}" for a, h in sorted(multi_addresses))
    if not multi_addresses:
        lines.append("none")
    context.hostname_map_path.write_text("\n".join(lines) + "\n", encoding="utf-8")



def detect_nmap_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".xml":
        return "xml"
    if suffix == ".gnmap":
        return "gnmap"
    if suffix == ".nmap":
        return "nmap"
    raise ValueError("Supported Nmap files are .xml, .gnmap, and .nmap")


def parse_existing_nmap(path: Path, family: int, dns_server: str | None = None) -> list[dict[str, Any]]:
    """Normalize existing Nmap output into open host/service records."""
    fmt = detect_nmap_format(path)
    records: list[dict[str, Any]] = []

    if fmt == "xml":
        root = ET.parse(path).getroot()
        addr_type = "ipv4" if family == 4 else "ipv6"

        for host in root.findall("host"):
            address_node = next(
                (x for x in host.findall("address") if x.get("addrtype") == addr_type),
                None,
            )
            if address_node is None:
                continue

            address = address_node.get("addr", "")
            hostname_node = host.find("./hostnames/hostname")
            hostname = hostname_node.get("name", "") if hostname_node is not None else ""

            ports: list[dict[str, Any]] = []
            for port in host.findall("./ports/port"):
                state_node = port.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue

                service_node = port.find("service")
                ports.append({
                    "protocol": port.get("protocol", ""),
                    "port": int(port.get("portid", "0")),
                    "service": service_node.get("name", "") if service_node is not None else "",
                    "product": service_node.get("product", "") if service_node is not None else "",
                    "version": service_node.get("version", "") if service_node is not None else "",
                    "tunnel": service_node.get("tunnel", "") if service_node is not None else "",
                })

            if ports:
                records.append({"address": address, "hostname": hostname, "ports": ports})

        return records

    raw = path.read_text(encoding="utf-8", errors="replace")

    if fmt == "gnmap":
        for line in raw.splitlines():
            if not line.startswith("Host:") or "Ports:" not in line:
                continue

            match = re.match(r"Host:\s+(\S+)\s+\((.*?)\)\s+Ports:\s+(.*)", line)
            if not match:
                continue

            address, hostname, port_blob = match.groups()

            try:
                if ipaddress.ip_address(address).version != family:
                    continue
            except ValueError:
                continue

            ports = []
            for entry in port_blob.split(","):
                fields = entry.strip().split("/")
                if len(fields) < 5 or fields[1] != "open":
                    continue

                try:
                    number = int(fields[0])
                except ValueError:
                    continue

                ports.append({
                    "protocol": fields[2],
                    "port": number,
                    "service": fields[4],
                    "product": "",
                    "version": "",
                    "tunnel": "",
                })

            if ports:
                records.append({"address": address, "hostname": hostname, "ports": ports})

        return records

    current_address = ""
    current_hostname = ""
    current_ports: list[dict[str, Any]] = []

    def flush() -> None:
        nonlocal current_address, current_hostname, current_ports
        if current_address and current_ports:
            records.append({
                "address": current_address,
                "hostname": current_hostname,
                "ports": current_ports[:],
            })
        current_address = ""
        current_hostname = ""
        current_ports = []

    for line in raw.splitlines():
        if line.startswith("Nmap scan report for "):
            flush()
            target = line[len("Nmap scan report for "):].strip()
            match = re.match(r"(.+?)\s+\(([^)]+)\)$", target)

            if match:
                current_hostname, current_address = match.group(1), match.group(2)
            else:
                try:
                    ipaddress.ip_address(target)
                    current_address = target
                except ValueError:
                    current_hostname = target
                    resolved = resolve_hostname(target, family, dns_server)
                    current_address = sorted(resolved)[0] if resolved else ""
            continue

        port_match = re.match(
            r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$",
            line.strip(),
        )

        if port_match and current_address:
            number, protocol, service, extra = port_match.groups()
            current_ports.append({
                "protocol": protocol,
                "port": int(number),
                "service": service,
                "product": extra or "",
                "version": "",
                "tunnel": "",
            })

    flush()
    return records


def populate_imported_inventory(
    context: FamilyContext,
    records: list[dict[str, Any]],
    source_files: list[Path],
) -> tuple[int, int, int]:
    if context.db_path.exists():
        context.db_path.unlink()

    db = sqlite3.connect(context.db_path)
    initialize_db(db)
    cur = db.cursor()

    cur.execute(
        "INSERT INTO scans(started_at,xml_path,command_json) VALUES(?,?,?)",
        (
            datetime.now(timezone.utc).isoformat(),
            ",".join(str(path) for path in source_files),
            json.dumps(["import", *map(str, source_files)]),
        ),
    )

    scan_id = int(cur.lastrowid)
    host_count = 0
    port_count = 0

    for record in records:
        address = record["address"]
        hostname = record.get("hostname", "")

        cur.execute(
            "INSERT INTO hosts(scan_id,address,hostname,status) VALUES(?,?,?,?)",
            (scan_id, address, hostname, "up"),
        )
        host_id = int(cur.lastrowid)
        host_count += 1

        if hostname:
            cur.execute(
                """
                INSERT OR IGNORE INTO resolutions(
                    scan_id,hostname,address,source
                ) VALUES(?,?,?,?)
                """,
                (
                    scan_id,
                    hostname.rstrip(".").lower(),
                    address,
                    "imported-nmap",
                ),
            )

        for port in record["ports"]:
            cur.execute(
                """
                INSERT INTO ports(
                    host_id,protocol,port,state,service,product,version,tunnel
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    host_id,
                    port["protocol"],
                    port["port"],
                    "open",
                    port.get("service", ""),
                    port.get("product", ""),
                    port.get("version", ""),
                    port.get("tunnel", ""),
                ),
            )
            port_count += 1

    db.commit()
    db.close()
    context.scan_id = scan_id

    return scan_id, host_count, port_count



def preferred_live_identity(
    context: FamilyContext,
    address: str,
) -> str:
    """
    Prefer a verified FQDN for live-hosts.txt, then a bare computer name,
    then the IP address.

    Core/resolve.py already tries parent domains observed elsewhere in the
    engagement for bare computer names and only accepts the inferred FQDN
    when forward DNS resolves back to the same IP.
    """
    with sqlite3.connect(context.db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """
            SELECT hostname, source
            FROM resolutions
            WHERE scan_id = ?
              AND address = ?
              AND hostname IS NOT NULL
              AND hostname != ''
            ORDER BY
              CASE source
                WHEN 'forward-target' THEN 0
                WHEN 'core-resolve' THEN 1
                WHEN 'imported-nmap' THEN 2
                WHEN 'nmap-xml' THEN 3
                WHEN 'reverse-ptr' THEN 4
                WHEN 'reverse-ptr-supplemental' THEN 5
                ELSE 6
              END,
              hostname
            """,
            (context.scan_id, address),
        ).fetchall()

    names = []
    seen = set()

    for row in rows:
        name = (row["hostname"] or "").strip().rstrip(".").lower()
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)

    if not names:
        return address

    fqdns = [name for name in names if "." in name]
    if fqdns:
        return fqdns[0]

    return names[0]



def write_etc_hosts_ready(context: FamilyContext) -> int:
    """
    Generate an /etc/hosts-ready file using only FQDNs that resolve back to
    the associated IP. Bare names and unresolved IPs are excluded.
    """
    with sqlite3.connect(context.db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """
            SELECT address, hostname
            FROM resolutions
            WHERE scan_id = ?
              AND hostname IS NOT NULL
              AND hostname != ''
            ORDER BY address, hostname
            """,
            (context.scan_id,),
        ).fetchall()

    family = socket.AF_INET if context.family == 4 else socket.AF_INET6
    by_address: dict[str, list[str]] = {}

    for row in rows:
        address = (row["address"] or "").strip()
        hostname = (row["hostname"] or "").strip().rstrip(".").lower()

        if not address or "." not in hostname:
            continue

        try:
            infos = socket.getaddrinfo(
                hostname,
                None,
                family,
                socket.SOCK_STREAM,
            )
            resolved = {
                info[4][0].split("%", 1)[0]
                for info in infos
                if info and info[4]
            }
        except OSError:
            continue

        if address in resolved:
            by_address.setdefault(address, []).append(hostname)

    pairs: list[tuple[str, str]] = []

    for address in sorted(by_address, key=ipaddress.ip_address):
        # One clean verified FQDN per IP.
        hostname = sorted(
            set(by_address[address]),
            key=lambda value: (value.count("."), len(value), value),
        )[0]
        pairs.append((address, hostname))

    path = context.db_root / "etc-hosts.txt"

    if not pairs:
        if path.exists():
            path.unlink()
        return 0

    path.write_text(
        "".join(
            f"{address}\\t{hostname}\\n"
            for address, hostname in pairs
        ),
        encoding="utf-8",
    )

    return len(pairs)


def write_normalized_inventory(context: FamilyContext) -> dict[str, Any]:
    """
    Write standard inventory files.

    ports-per-host.txt:
        host-or-ip:port<TAB>protocol<TAB>service
    """
    with sqlite3.connect(context.db_path) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """
            SELECT h.address,h.hostname,p.protocol,p.port,p.service
            FROM hosts h
            JOIN ports p ON p.host_id=h.id
            WHERE h.scan_id=? AND p.state='open'
            ORDER BY h.address,p.protocol,p.port
            """,
            (context.scan_id,),
        ).fetchall()

    if not rows:
        return {}

    output = context.db_root
    output.mkdir(parents=True, exist_ok=True)

    per_host: list[str] = []
    live_hosts: set[str] = set()
    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()
    service_frequency: dict[str, int] = {}

    for row in rows:
        host = row["hostname"] or row["address"]
        protocol = row["protocol"]
        port = int(row["port"])
        service = row["service"] or "unknown"

        per_host.append(f"{host}:{port}\t{protocol}\t{service}")
        live_hosts.add(row["address"])
        service_frequency[service] = service_frequency.get(service, 0) + 1

        if protocol == "tcp":
            tcp_ports.add(port)
        elif protocol == "udp":
            udp_ports.add(port)

    (output / "ports-per-host.txt").write_text(
        "\n".join(per_host) + "\n",
        encoding="utf-8",
    )

    sorted_live_addresses = sorted(
        live_hosts,
        key=ipaddress.ip_address,
    )

    preferred_live_hosts = [
        preferred_live_identity(
            context,
            address,
        )
        for address in sorted_live_addresses
    ]

    (output / "live-hosts.txt").write_text(
        "\n".join(preferred_live_hosts) + "\n",
        encoding="utf-8",
    )

    context.hosts_path.write_text(
        "\n".join(sorted_live_addresses) + "\n",
        encoding="utf-8",
    )

    (output / "service-frequency.txt").write_text(
        "\n".join(
            f"{count:6d} {service}"
            for service, count in sorted(
                service_frequency.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ) + "\n",
        encoding="utf-8",
    )

    (output / "tcp-ports.txt").write_text(
        ("T:" + ",".join(map(str, sorted(tcp_ports))) + "\n")
        if tcp_ports else "",
        encoding="utf-8",
    )

    (output / "udp-ports.txt").write_text(
        ("U:" + ",".join(map(str, sorted(udp_ports))) + "\n")
        if udp_ports else "",
        encoding="utf-8",
    )

    context.flat_db_path.write_text(
        "".join(
            f"{row['hostname'] or row['address']}, {row['port']}\n"
            for row in rows
        ),
        encoding="utf-8",
    )

    etc_hosts_count = write_etc_hosts_ready(context)

    if etc_hosts_count:
        etc_hosts_path = context.db_root / "etc-hosts.txt"
        print(
            f"[*] {context.label}: {etc_hosts_count} verified FQDN/IP "
            "mapping(s) available for /etc/hosts."
        )
        print(f"[*] /etc/hosts-ready file: {etc_hosts_path}")
        print(
            "[i] Optional command: "
            f"sudo sh -c 'cat \"{etc_hosts_path}\" >> /etc/hosts'"
        )

    return {
        "live_hosts": len(live_hosts),
        "tcp_unique_ports": len(tcp_ports),
        "udp_unique_ports": len(udp_ports),
        "open_services": len(rows),
    }


def prompt_existing_scan_files() -> list[Path]:
    print("\nExisting Nmap scan import")
    print("-------------------------")
    print("Supported formats: .xml, .gnmap, .nmap")
    print("Multiple files may be comma-separated.")

    while True:
        raw = input("Nmap output file(s): ").strip()

        files = [
            Path(value.strip()).expanduser().resolve()
            for value in raw.split(",")
            if value.strip()
        ]

        if not files:
            print("[!] At least one file is required.")
            continue

        missing = [str(path) for path in files if not path.is_file()]

        if missing:
            print("[!] File(s) not found: " + ", ".join(missing))
            continue

        try:
            for path in files:
                detect_nmap_format(path)
        except ValueError as exc:
            print(f"[!] {exc}")
            continue

        return files


def initialize_db(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY,
            started_at TEXT NOT NULL,
            xml_path TEXT NOT NULL,
            command_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hosts(
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            address TEXT NOT NULL,
            hostname TEXT,
            status TEXT,
            UNIQUE(scan_id,address)
        );
        CREATE TABLE IF NOT EXISTS resolutions(
            id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            hostname TEXT NOT NULL,
            address TEXT NOT NULL,
            source TEXT NOT NULL,
            UNIQUE(scan_id,hostname,address,source)
        );
        CREATE TABLE IF NOT EXISTS ports(
            id INTEGER PRIMARY KEY,
            host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            product TEXT,
            version TEXT,
            tunnel TEXT,
            UNIQUE(host_id,protocol,port)
        );
        CREATE INDEX IF NOT EXISTS idx_hosts_address ON hosts(address);
        CREATE INDEX IF NOT EXISTS idx_ports_service ON ports(service);
        CREATE INDEX IF NOT EXISTS idx_resolutions_address ON resolutions(address);
        """
    )


def import_final(
    context: FamilyContext,
    xml_path: Path,
    command: list[str],
    mappings: set[tuple[str, str, str]],
) -> tuple[int, int, int]:
    if context.db_path.exists():
        context.db_path.unlink()
    root = ET.parse(xml_path).getroot()
    db = sqlite3.connect(context.db_path)
    initialize_db(db)
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans(started_at,xml_path,command_json) VALUES(?,?,?)",
        (datetime.now(timezone.utc).isoformat(), str(xml_path), json.dumps(command))
    )
    scan_id = int(cur.lastrowid)
    for hostname, address, source in sorted(mappings):
        cur.execute(
            "INSERT OR IGNORE INTO resolutions(scan_id,hostname,address,source) VALUES(?,?,?,?)",
            (scan_id, hostname, address, source),
        )

    by_address: dict[str, set[str]] = {}
    for hostname, address, _ in mappings:
        by_address.setdefault(address, set()).add(hostname)

    rows: set[tuple[str, int]] = set()
    host_count = port_count = 0
    addr_type = "ipv4" if context.family == 4 else "ipv6"
    for node in root.findall("host"):
        address_node = next((x for x in node.findall("address") if x.get("addrtype") == addr_type), None)
        if address_node is None:
            continue
        address = address_node.get("addr", "")
        status_node = node.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        xml_names = {
            x.get("name", "").rstrip(".").lower()
            for x in node.findall("./hostnames/hostname") if x.get("name")
        }
        for hostname in xml_names:
            cur.execute(
                "INSERT OR IGNORE INTO resolutions(scan_id,hostname,address,source) VALUES(?,?,?,?)",
                (scan_id, hostname, address, "nmap-xml"),
            )
        hostname = sorted(xml_names | by_address.get(address, set()))[0] if (xml_names or by_address.get(address)) else ""
        cur.execute(
            "INSERT INTO hosts(scan_id,address,hostname,status) VALUES(?,?,?,?)",
            (scan_id, address, hostname, status),
        )
        host_id = int(cur.lastrowid)
        host_count += 1
        for port in node.findall("./ports/port"):
            state_node = port.find("state")
            service = port.find("service")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            protocol = port.get("protocol", "")
            number = int(port.get("portid", "0"))
            service_name = service.get("name", "") if service is not None else ""
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            tunnel = service.get("tunnel", "") if service is not None else ""
            cur.execute(
                """INSERT INTO ports(host_id,protocol,port,state,service,product,version,tunnel)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (host_id, protocol, number, state, service_name, product, version, tunnel),
            )
            if state == "open":
                rows.add((hostname or address, number))
            port_count += 1
    db.commit()
    db.close()
    context.flat_db_path.write_text(
        "".join(f"{host}, {port}\n" for host, port in sorted(rows)),
        encoding="utf-8",
    )
    context.scan_id = scan_id
    return scan_id, host_count, port_count


def discover_modules() -> list[tuple[str, Any]]:
    modules = []
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f"bayabas_module_{path.stem}", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if callable(getattr(module, "run", None)):
            modules.append((path.stem, module))
    return modules


def parse_module_selection(
    value: str,
    modules: list[tuple[str, Any]],
) -> list[tuple[str, Any]]:
    lookup = {name.lower(): (name, module) for name, module in modules}
    clean = value.strip()
    if clean.upper() == "ALL":
        return modules
    if clean.upper() in {"NONE", "N", "NO", "Q", "QUIT", ""}:
        return []

    selected: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for token in (part.strip() for part in clean.split(",")):
        if not token:
            continue
        item: tuple[str, Any] | None = None
        if token.isdigit():
            index = int(token) - 1
            if 0 <= index < len(modules):
                item = modules[index]
        else:
            item = lookup.get(token.lower())
        if item is None:
            raise ValueError(f"Unknown module selection: {token}")
        if item[0] not in seen:
            seen.add(item[0])
            selected.append(item)
    return selected


def prompt_module_selection(
    modules: list[tuple[str, Any]],
    already_run: set[str],
) -> list[tuple[str, Any]]:
    print("\\nAvailable configuration-audit modules")
    print("-------------------------------------")
    for index, (name, _module) in enumerate(modules, 1):
        status = " (already run)" if name in already_run else ""
        print(f"{index}) {name}{status}")
    print("ALL) Run all modules")
    print("NONE) Exit module selection")
    while True:
        value = input(
            "Select modules by number or name (comma-separated), ALL, or NONE: "
        ).strip()
        try:
            return parse_module_selection(value, modules)
        except ValueError as exc:
            print(f"[!] {exc}")


def execute_module_batch(
    nmap: str,
    contexts: list[FamilyContext],
    assessment: dict[str, Any],
    selected: list[tuple[str, Any]],
) -> set[str]:
    assessment.setdefault("modules", {})
    completed_names: set[str] = set()

    for name, module in selected:
        record = {
            "started": datetime.now(timezone.utc).isoformat(),
            "families": {},
            "status": "running",
        }
        assessment["modules"][name] = record
        total = 0
        try:
            for family in contexts:
                if family.scan_id is None:
                    continue
                context = ModuleContext(
                    root=ROOT,
                    family=family.family,
                    family_label=family.label,
                    db_path=family.db_path,
                    flat_db_path=family.flat_db_path,
                    findings_dir=family.db_root.parent.parent / "Findings",
                    scans_dir=family.scan_root,
                    scan_id=family.scan_id,
                    nmap_path=nmap,
                )
                count = int(module.run(context))
                record["families"][family.label] = count
                total += count
            record["status"] = "completed"
            record["findings"] = total
            completed_names.add(name)
        except KeyboardInterrupt as exc:
            record["status"] = "interrupted"
            record["completed"] = datetime.now(timezone.utc).isoformat()
            raise GracefulInterrupt from exc
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = str(exc)
            print(f"[!] Module {name} failed: {exc}", file=sys.stderr)
        record["completed"] = datetime.now(timezone.utc).isoformat()
    return completed_names


def run_module_menu(
    nmap: str,
    contexts: list[FamilyContext],
    assessment: dict[str, Any],
    initial_selection: str | None = None,
    non_interactive: bool = False,
) -> None:
    modules = discover_modules()
    if not modules:
        print("[*] No configuration-audit modules are available.")
        return

    already_run: set[str] = set()
    first = True
    while True:
        if non_interactive:
            selection_text = initial_selection or "ALL"
            selected = parse_module_selection(selection_text, modules)
        elif first and initial_selection:
            selected = parse_module_selection(initial_selection, modules)
        else:
            selected = prompt_module_selection(modules, already_run)

        first = False
        if not selected:
            print("[*] No further modules selected.")
            return

        already_run.update(execute_module_batch(nmap, contexts, assessment, selected))

        if non_interactive:
            return
        if not yes_no("Would you like to run another module before exiting gracefully?", False):
            return

def write_assessment(path: Path, assessment: dict[str, Any]) -> None:
    path.write_text(json.dumps(assessment, indent=2, sort_keys=True), encoding="utf-8")



def save_command(
    assessment_root: Path,
    key: str,
    command: list[str],
    command_dir: Path,
    assessment: dict[str, Any],
) -> None:
    command_dir.mkdir(parents=True, exist_ok=True)
    command_path = command_dir / "command.txt"
    command_path.write_text(
        " ".join(shlex.quote(part) for part in command) + "\n",
        encoding="utf-8",
    )
    assessment["commands"][key] = {
        "file": str(command_path.relative_to(assessment_root)),
        "argument_count": len(command),
    }


def save_requested_port_scope(
    assessment_root: Path,
    plan: PortPlan,
    assessment: dict[str, Any],
) -> None:
    scope_dir = assessment_root / "Requested_Ports"
    scope_dir.mkdir()
    port_data: dict[str, Any] = {"description": plan.description}

    if plan.tcp_ports:
        path = scope_dir / "tcp_ports.txt"
        path.write_text(",".join(map(str, plan.tcp_ports)) + "\n", encoding="utf-8")
        port_data["tcp_count"] = len(plan.tcp_ports)
        port_data["tcp_file"] = str(path.relative_to(assessment_root))
    if plan.udp_ports:
        path = scope_dir / "udp_ports.txt"
        path.write_text(",".join(map(str, plan.udp_ports)) + "\n", encoding="utf-8")
        port_data["udp_count"] = len(plan.udp_ports)
        port_data["udp_file"] = str(path.relative_to(assessment_root))
    assessment["port_plan"] = port_data


def update_interrupted_assessment() -> None:
    if CURRENT_ASSESSMENT_PATH is None or not CURRENT_ASSESSMENT_PATH.exists():
        return
    try:
        data = json.loads(CURRENT_ASSESSMENT_PATH.read_text(encoding="utf-8"))
        data["status"] = "interrupted"
        data["end_time"] = datetime.now(timezone.utc).isoformat()
        CURRENT_ASSESSMENT_PATH.write_text(
            json.dumps(data, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except Exception:
        pass


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Authorized Nmap and configuration-audit framework.")
    p.add_argument("targets", nargs="?", help="Target file, comma-separated targets, or one target")
    p.add_argument("--dns-server")
    p.add_argument("--quick", action="store_true")
    p.add_argument("--host-discovery", action="store_true", help=argparse.SUPPRESS)
    p.add_argument(
        "--import-nmap",
        action="append",
        default=[],
        help=(
            "Import existing .xml/.gnmap/.nmap instead of running "
            "host discovery and port scans. May be repeated."
        ),
    )
    p.add_argument("--ipv6", action="store_true", help="Also resolve and scan IPv6 targets")
    p.add_argument("--assessment-type", choices=["internal", "external"], help="Targets-file assessment type")
    p.add_argument("--client-domain", action="append", default=[], help="Authorized client root domain for DNS enumeration (repeatable)")
    p.add_argument("--ports")
    p.add_argument("--max-retries")
    p.add_argument("--max-scan-delay")
    p.add_argument("--min-parallelism")
    p.add_argument("--mtu")
    p.add_argument("--min-rate")
    p.add_argument("--max-hostgroup")
    p.add_argument("--assessment-name", help=argparse.SUPPRESS)
    p.add_argument(
        "--output-dir",
        help="Engagement root directory (default: current working directory).",
    )
    p.add_argument("--run-modules", action="store_true")
    p.add_argument(
        "--modules",
        help="Comma-separated module names/numbers, ALL, or NONE.",
    )
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--print-command", action="store_true")
    return p



def check_resolver_dependencies() -> None:
    status = core_resolve.dependency_status()
    if not status["host"]:
        die(
            "Resolver dependency `host` is missing. Install bind9-dnsutils "
            "(Debian/Kali/Ubuntu) or bind-utils (RHEL/CentOS)."
        )
    if not status["nmblookup"]:
        print("[i] Optional nmblookup missing; NetBIOS enrichment skipped.", file=sys.stderr)
    if not status["nxc"]:
        print("[i] Optional nxc/NetExec missing; SMB banner enrichment skipped.", file=sys.stderr)


def run_core_resolution(entries: list[str], dns_server: str | None):
    concrete = [entry for entry in entries if "/" not in entry]
    if not concrete:
        return set()
    print(f"[*] Resolving {len(concrete)} concrete target(s) before scans/modules...")
    _rows, mappings = core_resolve.resolve_for_bayabas(
        concrete,
        dns_server=dns_server,
        workers=16,
    )
    print(f"[*] Resolution complete: {len(mappings)} hostname/IP mapping(s).")
    return mappings


def merge_resolution_mappings_into_db(context: FamilyContext, mappings):
    if not mappings or context.scan_id is None:
        return
    with sqlite3.connect(context.db_path) as db:
        for hostname, address, source in sorted(mappings):
            try:
                if ipaddress.ip_address(address).version != context.family:
                    continue
            except ValueError:
                continue
            db.execute(
                """
                INSERT OR IGNORE INTO resolutions(
                    scan_id,hostname,address,source
                ) VALUES(?,?,?,?)
                """,
                (context.scan_id, hostname.rstrip(".").lower(), address, source),
            )
        db.commit()


def read_db_resolution_mappings(context: FamilyContext):
    result = set()
    with sqlite3.connect(context.db_path) as db:
        db.row_factory = sqlite3.Row
        for row in db.execute(
            "SELECT hostname,address,source FROM resolutions WHERE scan_id=?",
            (context.scan_id,),
        ):
            result.add((row["hostname"], row["address"], row["source"]))
    return result


def main() -> int:
    global CURRENT_ASSESSMENT_PATH
    args = parser().parse_args()
    MODULES_DIR.mkdir(parents=True, exist_ok=True)
    nmap = ensure_dependencies()

    # Select import-vs-scan before requesting any targets.
    import_files = [
        Path(value).expanduser().resolve()
        for value in args.import_nmap
    ]

    if not args.non_interactive and not import_files:
        if yes_no("Do you have an existing completed Nmap scan?", False):
            import_files = prompt_existing_scan_files()

    import_mode = bool(import_files)

    check_resolver_dependencies()

    targets: list[str] = []
    ipv4_targets: list[str] = []
    ipv6_targets: list[str] = []
    explicit_mappings: set[tuple[str, str, str, int]] = set()
    import_resolution_mappings: set[tuple[str, str, str]] = set()
    ipv6_enabled = False
    dns = args.dns_server

    if not dns and not args.non_interactive:
        dns = prompt(
            "DNS server for target resolution (blank = system resolver)",
            "",
        ) or None

    if dns and not valid_dns(dns):
        die("Invalid DNS server.")

    host_discovery = False
    plan = PortPlan([], False, False, "pending scan configuration")
    timing: list[str] = []
    ipv6_dns_with: list[tuple[str, str]] = []
    ipv6_dns_without: list[str] = []
    assessment_type = "import"
    client_domains: list[str] = []

    if not import_mode:
        raw = args.targets

        if not raw and not args.non_interactive:
            raw = prompt(
                "Target file, comma-separated targets, or one target"
            )

        if not raw:
            die("Targets are required when an existing Nmap scan is not imported.")

        targets = load_targets(raw)
        advise_terminal_multiplexer(estimate_target_scale(targets), args.non_interactive)

        assessment_type = args.assessment_type or infer_assessment_type(targets)
        if not args.non_interactive:
            print(f"[*] Recommended assessment type: {assessment_type.upper()}")
            if not yes_no(f"Use {assessment_type.upper()} workflow?", True):
                assessment_type = "internal" if assessment_type == "external" else "external"
        client_domains = normalize_client_domains(args.client_domain)
        if not args.non_interactive and not client_domains:
            entered = prompt("Client domain(s) for authorized DNS enumeration (comma-separated, blank = skip)", "")
            client_domains = normalize_client_domains([entered]) if entered else []
        print(f"[*] Assessment workflow: {assessment_type.upper()}")
        if client_domains:
            print("[*] Authorized client domain(s): " + ", ".join(client_domains))

        # External passive enumeration is performed after the Database directory exists.
        preflight_mappings = run_core_resolution(targets, dns)
        ipv6_dns_with, ipv6_dns_without = classify_hostname_ipv6(targets, dns)

        ipv6_enabled = args.ipv6
        if not args.non_interactive:
            ipv6_enabled = yes_no("Run IPv6 scans (-6) as well?", False)

        ipv4_targets, ipv6_targets, explicit_mappings = split_targets(
            targets,
            ipv6_enabled,
            dns,
        )

        explicit_mappings.update(
            (
                hostname,
                address,
                source,
                ipaddress.ip_address(address).version,
            )
            for hostname, address, source in preflight_mappings
            if ipaddress.ip_address(address).version in (4, 6)
        )

        if not ipv4_targets and not ipv6_targets:
            die("No targets resolved for the selected address families.")

        # With raw targets and no imported Nmap inventory, discovery is a
        # mandatory pre-scan stage. This intentionally happens before port
        # and timing prompts so dead hosts are removed from scan scope first.
        host_discovery = True

    output_dir = args.output_dir

    if not args.non_interactive:
        output_dir = prompt(
            "Engagement output directory",
            output_dir or str(Path.cwd()),
        )

    if not output_dir:
        die("--output-dir is required in non-interactive mode.")

    assessment_root = Path(output_dir).expanduser().resolve()
    assessment_root.mkdir(parents=True, exist_ok=True)

    assessment_path = assessment_root / "assessment.json"
    if assessment_path.exists():
        die(
            "Engagement directory already contains assessment.json: "
            f"{assessment_root}"
        )

    CURRENT_ASSESSMENT_PATH = assessment_path

    # Imported Nmap results define their own targets/address families.
    imported_family_records: dict[int, list[dict[str, Any]]] = {4: [], 6: []}

    if import_mode:
        for import_path in import_files:
            for family in (4, 6):
                try:
                    imported_family_records[family].extend(
                        parse_existing_nmap(import_path, family, dns)
                    )
                except Exception as exc:
                    die(f"Could not import {import_path}: {exc}")

        ipv4_targets = sorted({
            record["address"]
            for record in imported_family_records[4]
        })
        ipv6_targets = sorted({
            record["address"]
            for record in imported_family_records[6]
        })
        targets = ipv4_targets + ipv6_targets

        if not targets:
            die("No hosts with open ports were found in the imported Nmap output.")

        resolution_entries = list(targets)
        resolution_entries.extend(
            record.get("hostname", "")
            for family_records in imported_family_records.values()
            for record in family_records
            if record.get("hostname")
        )
        resolution_entries = list(dict.fromkeys(x for x in resolution_entries if x))
        import_resolution_mappings = run_core_resolution(
            resolution_entries,
            dns,
        )

    assessment_id = assessment_root.name
    assessment: dict[str, Any] = {
        "assessment_id": assessment_id,
        "assessment_uuid": str(uuid.uuid4()),
        "project": APP,
        "version": VERSION,
        "start_time": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "targets": targets,
        "output_directory": str(assessment_root),
        "ipv4_enabled": bool(ipv4_targets),
        "ipv6_enabled": bool(ipv6_targets),
        "host_discovery": host_discovery,
        "intake_mode": "import" if import_mode else "scan",
        "assessment_type": assessment_type,
        "client_domains": client_domains,
        "port_plan": {},
        "commands": {},
        "statistics": {},
        "artifacts": {},
    }
    if import_mode:
        assessment["port_plan"] = {"description": "imported Nmap output"}
    write_assessment(assessment_path, assessment)

    contexts: list[FamilyContext] = []
    if ipv4_targets:
        contexts.append(make_family_context(assessment_root, 4, ipv4_targets))
    if ipv6_targets:
        contexts.append(make_family_context(assessment_root, 6, ipv6_targets))

    final_commands: dict[int, list[str]] = {}
    final_inventory: dict[int, tuple[list[int], list[int], list[str]]] = {}

    if import_mode:
        successful_contexts: list[FamilyContext] = []

        for context in contexts:
            combined: dict[str, dict[str, Any]] = {}

            for record in imported_family_records[context.family]:
                address = record["address"]

                if address not in combined:
                    combined[address] = {
                        "address": address,
                        "hostname": record.get("hostname", ""),
                        "ports": [],
                    }

                if not combined[address]["hostname"] and record.get("hostname"):
                    combined[address]["hostname"] = record["hostname"]

                existing = {
                    (port["protocol"], port["port"])
                    for port in combined[address]["ports"]
                }

                for port in record["ports"]:
                    key = (port["protocol"], port["port"])

                    if key not in existing:
                        combined[address]["ports"].append(port)
                        existing.add(key)

            records = list(combined.values())

            if not records:
                continue

            scan_id, hosts, ports = populate_imported_inventory(
                context,
                records,
                import_files,
            )

            merge_resolution_mappings_into_db(
                context,
                import_resolution_mappings,
            )
            write_resolution_files(
                context,
                read_db_resolution_mappings(context),
            )
            stats = write_normalized_inventory(context)
            successful_contexts.append(context)

            assessment["statistics"][f"{context.label}_hosts"] = hosts
            assessment["statistics"][f"{context.label}_port_records"] = ports
            assessment["statistics"][f"{context.label}_inventory"] = stats
            assessment["artifacts"][f"{context.label}_database"] = str(context.db_path)
            assessment["artifacts"][f"{context.label}_ports_per_host"] = str(
                context.db_root / "ports-per-host.txt"
            )

        write_assessment(assessment_path, assessment)

        run_selected = args.run_modules or bool(args.modules)

        if not args.non_interactive and not args.modules:
            run_selected = yes_no("Run configuration-audit modules now?", True)

        if run_selected and successful_contexts:
            run_module_menu(
                nmap,
                successful_contexts,
                assessment,
                initial_selection=args.modules,
                non_interactive=args.non_interactive,
            )

        assessment["status"] = "completed"
        assessment["end_time"] = datetime.now(timezone.utc).isoformat()
        write_assessment(assessment_path, assessment)

        print("\a[*] Bayabas assessment completed from imported Nmap output.")
        print(f"[*] Metadata: {assessment_path}")

        return 0

    # Scan intake: perform liveness discovery before asking about ports/timing.
    database_root = assessment_root / "Database"
    database_root.mkdir(parents=True, exist_ok=True)
    if assessment_type == "external" and client_domains:
        passive_names = passive_subdomain_enumeration(client_domains, database_root)
        if passive_names:
            passive_mappings = run_core_resolution(sorted(passive_names), dns)
            explicit_mappings.update((h, a, src, ipaddress.ip_address(a).version) for h, a, src in passive_mappings)
            resolved_v4 = sorted({a for _h, a, _s in passive_mappings if ipaddress.ip_address(a).version == 4}, key=ipaddress.ip_address)
            resolved_v6 = sorted({a for _h, a, _s in passive_mappings if ipaddress.ip_address(a).version == 6}, key=ipaddress.ip_address)
            write_lines(database_root / "domain_discovery_resolved_ipv4.txt", resolved_v4)
            write_lines(database_root / "domain_discovery_resolved_ipv6.txt", resolved_v6)
            # Passive findings are intelligence only in this revision: they do not silently expand Nmap scope.
            print("[*] Passive DNS findings recorded as intelligence; supplied target scope is unchanged.")
    write_lines(
        database_root / "hostnames_with_ipv6.txt",
        [f"{hostname}\t{address}" for hostname, address in ipv6_dns_with],
    )
    write_lines(database_root / "hostnames_without_ipv6.txt", ipv6_dns_without)

    discovered_all: set[str] = set()
    usable_contexts: list[FamilyContext] = []
    for context in contexts:
        write_lines(context.original_targets_file, context.targets)
        command = discovery_command(nmap, context, dns)
        save_command(
            assessment_root,
            f"{context.label}_discovery",
            command,
            context.discovery_dir,
            assessment,
        )
        print("[*] " + " ".join(shlex.quote(x) for x in command))
        if args.print_command:
            # Keep the downstream command plan printable even though discovery
            # output does not exist yet in command-only mode.
            usable_contexts.append(context)
            continue

        code = run_scan_command(f"{context.label} host discovery", command, context.discovery_dir)
        xml = context.discovery_dir / "host_discovery.xml"
        if code != 0 or not xml.exists():
            print(f"[!] {context.label} discovery failed; skipping this family.", file=sys.stderr)
            continue
        discovered = extract_up_hosts(xml, context.family)
        write_lines(context.discovery_targets_file, discovered)
        write_lines(context.db_root / "host_discovery_list.txt", discovered)
        discovered_all.update(discovered)
        if not discovered:
            print(f"[*] {context.label} discovery found no live hosts.")
            continue
        print(f"[*] {context.label} discovery identified {len(discovered)} live host(s).")
        usable_contexts.append(context)

    write_lines(
        database_root / "host_discovery_list.txt",
        sorted(discovered_all, key=lambda x: (ipaddress.ip_address(x).version, ipaddress.ip_address(x))),
    )
    assessment["artifacts"]["host_discovery_list"] = str(database_root / "host_discovery_list.txt")
    assessment["artifacts"]["hostnames_with_ipv6"] = str(database_root / "hostnames_with_ipv6.txt")
    assessment["artifacts"]["hostnames_without_ipv6"] = str(database_root / "hostnames_without_ipv6.txt")
    assessment["statistics"]["discovered_live_hosts"] = len(discovered_all)
    write_assessment(assessment_path, assessment)

    if not usable_contexts and not args.print_command:
        assessment["status"] = "completed-no-live-hosts"
        assessment["end_time"] = datetime.now(timezone.utc).isoformat()
        write_assessment(assessment_path, assessment)
        print("[*] Host discovery found no live hosts; no port-scan prompts were shown.")
        return 0

    # Only after discovery do we ask for the actual scan scope/timing.
    plan, timing = collect_scan_options(args)
    save_requested_port_scope(assessment_root, plan, assessment)
    write_assessment(assessment_path, assessment)

    successful_contexts: list[FamilyContext] = []
    for context in usable_contexts:
        initial_targets = (
            context.discovery_targets_file
            if context.discovery_targets_file.exists() and context.discovery_targets_file.stat().st_size
            else context.original_targets_file
        )
        command = initial_command(nmap, context, initial_targets, plan, timing, dns, True)
        save_command(
            assessment_root,
            f"{context.label}_initial",
            command,
            context.initial_dir,
            assessment,
        )
        print("[*] " + " ".join(shlex.quote(x) for x in command))
        if args.print_command:
            continue
        code = run_scan_command(f"{context.label} initial port scan", command, context.initial_dir)
        xml = context.initial_dir / "initial_scan.xml"
        if code != 0 or not xml.exists():
            print(f"[!] {context.label} initial scan failed; skipping final scan.", file=sys.stderr)
            continue
        tcp, udp, live = extract_initial(xml, context)
        if not live or (not tcp and not udp):
            print(f"[*] {context.label}: no open ports found; no final scan or findings will be produced.")
            continue
        final_inventory[context.family] = (tcp, udp, live)

        context.final_output_base = validate_output_base("final_scan", context.final_dir)
        command = final_command(nmap, context, timing, tcp, udp)
        final_commands[context.family] = command
        save_command(
            assessment_root,
            f"{context.label}_final",
            command,
            context.final_dir,
            assessment,
        )
        print("[*] " + " ".join(shlex.quote(x) for x in command))
        code = run_scan_command(f"{context.label} final service scan", command, context.final_dir)
        final_xml = Path(str(context.final_output_base) + ".xml")
        if code != 0 or not final_xml.exists():
            print(f"[!] {context.label} final scan failed.", file=sys.stderr)
            continue

        mappings = collect_family_mappings(context.family, explicit_mappings, live, dns)
        write_resolution_files(context, mappings)
        scan_id, hosts, ports = import_final(context, final_xml, command, mappings)
        inventory_stats = write_normalized_inventory(context)
        successful_contexts.append(context)
        assessment["statistics"][f"{context.label}_inventory"] = inventory_stats
        assessment["statistics"][f"{context.label}_hosts"] = hosts
        assessment["statistics"][f"{context.label}_port_records"] = ports
        assessment["artifacts"][f"{context.label}_final_xml"] = str(final_xml)
        assessment["artifacts"][f"{context.label}_database"] = str(context.db_path)
        print(f"[*] {context.label}: imported {hosts} hosts and {ports} port records (scan {scan_id}).")

    write_assessment(assessment_path, assessment)
    if args.print_command:
        return 0

    run_selected = args.run_modules or bool(args.modules)
    if not args.non_interactive and not args.modules:
        run_selected = yes_no("Run configuration-audit modules now?", True)
    if run_selected and successful_contexts:
        run_module_menu(
            nmap,
            successful_contexts,
            assessment,
            initial_selection=args.modules,
            non_interactive=args.non_interactive,
        )

    assessment["status"] = "completed"
    assessment["end_time"] = datetime.now(timezone.utc).isoformat()
    write_assessment(assessment_path, assessment)
    print("\a[*] Bayabas assessment completed.")
    print(f"[*] Metadata: {assessment_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, GracefulInterrupt):
        update_interrupted_assessment()
        print("\n[!] Bayabas exited gracefully; no detached scan sessions were left running.", file=sys.stderr)
        raise SystemExit(130)
