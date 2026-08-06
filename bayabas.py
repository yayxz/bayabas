#!/usr/bin/env python3
"""
bayabas: authorized Nmap scan orchestration and configuration-audit framework.

Use only against systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import ipaddress
import json
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP = "bayabas"
SCREEN_SESSION = "onePunch"
ROOT = Path(__file__).resolve().parent
HOST_DB_DIR = ROOT / "Host_DB"
MODULES_DIR = ROOT / "Modules"
FINDINGS_DIR = ROOT / "Findings"
SCANS_DIR = ROOT / "Scans"
SQLITE_DB = HOST_DB_DIR / "hosts_ports.sqlite3"
FLAT_DB = HOST_DB_DIR / "host_port.txt"

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
TIME_RE = re.compile(r"^\d+(?:ms|s|m|h)?$", re.I)


@dataclass(frozen=True)
class PortPlan:
    args: list[str]
    tcp: bool
    udp: bool
    description: str


@dataclass(frozen=True)
class ModuleContext:
    root: Path
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


def classify_target(value: str) -> str:
    value = value.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
        if "/" in value and network.num_addresses > 1:
            return "subnet"
        return "ip"
    except ValueError:
        if HOSTNAME_RE.fullmatch(value):
            return "hostname"
    raise ValueError(f"Invalid target: {value!r}")


def load_targets(raw: str) -> list[str]:
    candidate = Path(raw).expanduser()
    values: list[str] = []
    if candidate.is_file():
        for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                values.extend(x.strip() for x in line.split(",") if x.strip())
    else:
        values = [x.strip() for x in raw.split(",") if x.strip()]

    if not values:
        die("No targets supplied.")

    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        try:
            classify_target(value)
        except ValueError as exc:
            die(str(exc))
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def parse_port_plan(value: str) -> PortPlan:
    raw = value.strip()
    if raw == "-":
        return PortPlan(["-p-"], True, False, "all TCP ports")
    if raw.lower() in {"top100", "top-100", "100"}:
        return PortPlan(["--top-ports", "100"], True, False, "top 100 TCP ports")
    if raw.lower() in {"top1000", "top-1000", "1000"}:
        return PortPlan(["--top-ports", "1000"], True, False, "top 1000 TCP ports")

    tcp = bool(re.search(r"(?:^|,)T:", raw, re.I))
    udp = bool(re.search(r"(?:^|,)U:", raw, re.I))
    if not tcp and not udp:
        tcp = True

    pieces = re.split(r"(?:(?:^|,)[TU]:)", raw, flags=re.I)
    for piece in pieces:
        for token in filter(None, (x.strip() for x in piece.split(","))):
            if "-" in token:
                left, right = token.split("-", 1)
                if not left.isdigit() or not right.isdigit() or not 1 <= int(left) <= int(right) <= 65535:
                    raise ValueError(f"Invalid port range: {token}")
            elif not token.isdigit() or not 1 <= int(token) <= 65535:
                raise ValueError(f"Invalid port: {token}")
    if not raw:
        raise ValueError("Empty port selection.")
    return PortPlan(["-p", raw], tcp, udp, raw)


def ensure_dependencies() -> tuple[str, str]:
    nmap = shutil.which("nmap")
    screen = shutil.which("screen")
    if not nmap:
        die("Nmap is not installed or not available in PATH.")
    if not screen:
        die(
            "GNU Screen is not installed. Install it first, for example with "
            "'apt install screen', 'dnf install screen', or 'pacman -S screen'."
        )
    return nmap, screen


def screen_exists(screen: str) -> bool:
    result = subprocess.run(
        [screen, "-ls"], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False
    )
    return bool(re.search(rf"\d+\.{re.escape(SCREEN_SESSION)}\s", result.stdout))


def run_screen(screen: str, command: list[str], work_dir: Path, label: str) -> int:
    if screen_exists(screen):
        die(f"A Screen session named {SCREEN_SESSION!r} already exists.")

    safe_label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
    done = work_dir / f".{safe_label}.done"
    exit_code = work_dir / f".{safe_label}.exit"
    wrapper = work_dir / f"run_{safe_label}.sh"
    wrapper.write_text(
        "#!/usr/bin/env bash\nset +e\n"
        + " ".join(shlex.quote(x) for x in command)
        + "\ncode=$?\nprintf '%s\\n' \"$code\" > "
        + shlex.quote(str(exit_code))
        + "\ntouch "
        + shlex.quote(str(done))
        + "\nexit \"$code\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)

    print(f"[*] Starting {label} in Screen session {SCREEN_SESSION!r}")
    subprocess.run([screen, "-DmS", SCREEN_SESSION, "bash", str(wrapper)], check=True)

    try:
        while not done.exists():
            time.sleep(1)
    except KeyboardInterrupt:
        subprocess.run([screen, "-S", SCREEN_SESSION, "-X", "quit"], check=False)
        raise SystemExit(130)
    finally:
        subprocess.run(
            [screen, "-S", SCREEN_SESSION, "-X", "quit"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        )

    try:
        return int(exit_code.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return 1


def write_target_file(path: Path, targets: list[str]) -> None:
    path.write_text("\n".join(targets) + "\n", encoding="utf-8")


def extract_up_hosts(xml_path: Path) -> list[str]:
    root = ET.parse(xml_path).getroot()
    hosts: list[str] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = host.findall("address")
        addr = next((x.get("addr") for x in addresses if x.get("addrtype") in {"ipv4", "ipv6"}), None)
        if addr:
            hosts.append(addr)
    return sorted(set(hosts))


def discovery_command(
    nmap: str, target_file: Path, output_base: Path, dns: str | None
) -> list[str]:
    # Nmap's default privileged discovery is a balanced combination:
    # ICMP echo/timestamp, TCP SYN 443, TCP ACK 80; ARP/ND on local links.
    command = [
        nmap, "-sn", "--reason", "-v", "-iL", str(target_file),
        "-oA", str(output_base)
    ]
    if dns:
        command += ["--dns-servers", dns]
    return command


def collect_scan_options(args: argparse.Namespace) -> tuple[bool, PortPlan, list[str]]:
    if args.non_interactive:
        quick = args.quick
    else:
        quick = yes_no("Use quick scan (-F: approximately 100 common ports)?", False)

    if quick:
        port_plan = PortPlan(["-F"], True, False, "Nmap fast scan (-F)")
    else:
        raw_ports = args.ports
        if not raw_ports and not args.non_interactive:
            raw_ports = prompt(
                "Ports (T:22,80,U:53 | - | top100 | top1000)",
                "top1000",
            )
        if not raw_ports:
            die("--ports is required unless --quick is used.")
        try:
            port_plan = parse_port_plan(raw_ports)
        except ValueError as exc:
            die(str(exc))

    values: dict[str, str | None] = {
        "max_retries": args.max_retries,
        "max_scan_delay": args.max_scan_delay,
        "min_parallelism": args.min_parallelism,
        "mtu": args.mtu,
        "min_rate": args.min_rate,
        "max_hostgroup": args.max_hostgroup,
    }
    if not args.non_interactive:
        values["max_retries"] = values["max_retries"] or prompt("max-retries", "2", nonnegative_int)
        values["max_scan_delay"] = values["max_scan_delay"] or prompt("max-scan-delay", "1s", valid_time)
        values["min_parallelism"] = values["min_parallelism"] or prompt("min-parallelism", "10", positive_int)
        values["mtu"] = values["mtu"] or prompt("mtu (multiple of 8)", "24", valid_mtu)
        values["min_rate"] = values["min_rate"] or prompt("min-rate", "100", valid_rate)
        values["max_hostgroup"] = values["max_hostgroup"] or prompt("max-hostgroup", "64", positive_int)

    validators = {
        "max_retries": nonnegative_int,
        "max_scan_delay": valid_time,
        "min_parallelism": positive_int,
        "mtu": valid_mtu,
        "min_rate": valid_rate,
        "max_hostgroup": positive_int,
    }
    for name, validator in validators.items():
        value = values[name]
        if value is None:
            die(f"Missing --{name.replace('_', '-')}.")
        if not validator(str(value)):
            die(f"Invalid --{name.replace('_', '-')}: {value}")

    timing = [
        "--max-retries", str(values["max_retries"]),
        "--max-scan-delay", str(values["max_scan_delay"]),
        "--min-parallelism", str(values["min_parallelism"]),
        "--mtu", str(values["mtu"]),
        "--min-rate", str(values["min_rate"]),
        "--max-hostgroup", str(values["max_hostgroup"]),
    ]
    return quick, port_plan, timing


def initial_scan_command(
    nmap: str, target_file: Path, output_base: Path, dns: str | None,
    port_plan: PortPlan, timing: list[str], discovery_completed: bool
) -> list[str]:
    """Build the initial open-port scan without service/version detection."""
    command = [nmap, "--open", "-v", "-iL", str(target_file)]
    if discovery_completed:
        command.append("-Pn")

    if port_plan.tcp and port_plan.udp:
        command += ["-sS" if os.geteuid() == 0 else "-sT", "-sU"]
    elif port_plan.udp:
        command += ["-sU"]
    else:
        command += ["-sS" if os.geteuid() == 0 else "-sT"]

    command += port_plan.args + timing
    if dns:
        command += ["--dns-servers", dns]
    command += ["-oA", str(output_base)]
    return command


def extract_initial_scan_inventory(
    xml_path: Path, work_dir: Path
) -> tuple[Path, Path, Path, list[int], list[int], list[str]]:
    """Extract unique open ports and hosts having at least one open port."""
    root = ET.parse(xml_path).getroot()
    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()
    live_hosts: set[str] = set()

    for host in root.findall("host"):
        addresses = host.findall("address")
        address = next(
            (node.get("addr") for node in addresses if node.get("addrtype") in {"ipv4", "ipv6"}),
            None,
        )
        if not address:
            continue

        host_has_open_port = False
        for port_node in host.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            protocol = port_node.get("protocol", "").lower()
            port = int(port_node.get("portid", "0"))
            if protocol == "tcp":
                tcp_ports.add(port)
                host_has_open_port = True
            elif protocol == "udp":
                udp_ports.add(port)
                host_has_open_port = True

        if host_has_open_port:
            live_hosts.add(address)

    tcp_path = work_dir / "tcp_ports.txt"
    udp_path = work_dir / "udp_ports.txt"
    hosts_path = work_dir / "ini_scan_live_hosts.txt"
    tcp_sorted = sorted(tcp_ports)
    udp_sorted = sorted(udp_ports)
    hosts_sorted = sorted(live_hosts, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))

    tcp_path.write_text(",".join(map(str, tcp_sorted)) + ("\n" if tcp_sorted else ""), encoding="utf-8")
    udp_path.write_text(",".join(map(str, udp_sorted)) + ("\n" if udp_sorted else ""), encoding="utf-8")
    write_target_file(hosts_path, hosts_sorted)
    return tcp_path, udp_path, hosts_path, tcp_sorted, udp_sorted, hosts_sorted


def final_port_expression(tcp_ports: list[int], udp_ports: list[int]) -> str:
    components: list[str] = []
    if tcp_ports:
        components.append("T:" + ",".join(map(str, tcp_ports)))
    if udp_ports:
        components.append("U:" + ",".join(map(str, udp_ports)))
    if not components:
        raise ValueError("No open TCP or UDP ports were found in the initial scan.")
    return ",".join(components)


def final_scan_command(
    nmap: str, target_file: Path, output_base: Path, timing: list[str],
    tcp_ports: list[int], udp_ports: list[int]
) -> list[str]:
    """Build the final version-detection scan from initial-scan evidence."""
    command = [
        nmap, "--open", "-v", "--resolve-all", "-n", "-Pn",
        "-iL", str(target_file), "-sV",
    ]
    if tcp_ports and udp_ports:
        command += ["-sS" if os.geteuid() == 0 else "-sT", "-sU"]
    elif udp_ports:
        command += ["-sU"]
    else:
        command += ["-sS" if os.geteuid() == 0 else "-sT"]
    command += ["-p", final_port_expression(tcp_ports, udp_ports)]
    command += timing
    command += ["-oA", str(output_base)]
    return command


def validate_final_output_base(raw: str) -> Path:
    """Require a new Nmap -oA output base whose outputs do not already exist."""
    output_base = Path(raw).expanduser().resolve()
    if not output_base.name:
        die("Final scan output must include a file base name.")
    parent = output_base.parent
    if not parent.exists() or not parent.is_dir():
        die(f"Final scan output directory does not exist: {parent}")

    conflicts = [
        path for path in (
            output_base,
            Path(str(output_base) + ".nmap"),
            Path(str(output_base) + ".xml"),
            Path(str(output_base) + ".gnmap"),
        ) if path.exists()
    ]
    if conflicts:
        die("Final scan output already exists: " + ", ".join(str(path) for path in conflicts))
    return output_base

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
        CREATE INDEX IF NOT EXISTS idx_host_address ON hosts(address);
        CREATE INDEX IF NOT EXISTS idx_port_service ON ports(service);
        """
    )


def import_scan(xml_path: Path, command: list[str]) -> tuple[int, int, int]:
    root = ET.parse(xml_path).getroot()
    db = sqlite3.connect(SQLITE_DB)
    initialize_db(db)
    cur = db.cursor()
    cur.execute(
        "INSERT INTO scans(started_at,xml_path,command_json) VALUES(?,?,?)",
        (datetime.now(timezone.utc).isoformat(), str(xml_path), json.dumps(command))
    )
    scan_id = int(cur.lastrowid)
    host_count = port_count = 0
    rows: list[tuple[str, int]] = []

    for node in root.findall("host"):
        state_node = node.find("status")
        status = state_node.get("state", "unknown") if state_node is not None else "unknown"
        addresses = node.findall("address")
        address = next(
            (x.get("addr") for x in addresses if x.get("addrtype") in {"ipv4", "ipv6"}), None
        )
        if not address:
            continue
        hn_node = node.find("./hostnames/hostname")
        hostname = hn_node.get("name", "") if hn_node is not None else ""
        cur.execute(
            "INSERT INTO hosts(scan_id,address,hostname,status) VALUES(?,?,?,?)",
            (scan_id, address, hostname, status)
        )
        host_id = int(cur.lastrowid)
        host_count += 1

        for p in node.findall("./ports/port"):
            state = p.find("state")
            service = p.find("service")
            pstate = state.get("state", "unknown") if state is not None else "unknown"
            protocol = p.get("protocol", "")
            port = int(p.get("portid", "0"))
            service_name = service.get("name", "") if service is not None else ""
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            tunnel = service.get("tunnel", "") if service is not None else ""
            cur.execute(
                """INSERT INTO ports(host_id,protocol,port,state,service,product,version,tunnel)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (host_id, protocol, port, pstate, service_name, product, version, tunnel)
            )
            if pstate == "open":
                rows.append((hostname or address, port))
            port_count += 1

    db.commit()
    db.close()

    # Required flat format: host(or ip), port
    FLAT_DB.write_text(
        "".join(f"{host}, {port}\n" for host, port in sorted(set(rows))),
        encoding="utf-8"
    )
    return scan_id, host_count, port_count


def discover_modules() -> list[tuple[str, Any]]:
    modules: list[tuple[str, Any]] = []
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


def run_modules(context: ModuleContext) -> None:
    modules = discover_modules()
    if not modules:
        print("[*] No runnable modules found.")
        return
    for name, module in modules:
        print(f"[*] Running module: {name}")
        try:
            count = int(module.run(context))
            print(f"    findings: {count}")
        except Exception as exc:
            print(f"[!] Module {name} failed: {exc}", file=sys.stderr)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Authorized Nmap and configuration-audit framework.")
    p.add_argument("targets", nargs="?", help="File, comma-separated targets, or one IP/hostname/subnet")
    p.add_argument("--dns-server")
    p.add_argument("--quick", action="store_true", help="Use Nmap -F fast scan")
    p.add_argument("--host-discovery", action="store_true")
    p.add_argument("--ports")
    p.add_argument("--max-retries")
    p.add_argument("--max-scan-delay")
    p.add_argument("--min-parallelism")
    p.add_argument("--mtu")
    p.add_argument("--min-rate")
    p.add_argument("--max-hostgroup")
    p.add_argument("--final-output", help="Required Nmap -oA base path for the final scan")
    p.add_argument("--run-modules", action="store_true")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--print-command", action="store_true")
    return p


def main() -> int:
    args = parser().parse_args()
    for path in (HOST_DB_DIR, MODULES_DIR, FINDINGS_DIR, SCANS_DIR):
        path.mkdir(parents=True, exist_ok=True)
    nmap, screen = ensure_dependencies()

    raw_targets = args.targets
    if not raw_targets and not args.non_interactive:
        raw_targets = prompt("Target file, comma-separated targets, or one target")
    if not raw_targets:
        die("Targets are required.")
    targets = load_targets(raw_targets)
    types = {classify_target(x) for x in targets}

    dns = args.dns_server
    if {"ip", "subnet"} & types and not dns and not args.non_interactive:
        dns = prompt("Preferred DNS server (--dns-server)", "8.8.8.8", valid_dns)
    if dns and not valid_dns(dns):
        die("Invalid DNS server.")

    host_discovery = args.host_discovery
    if not args.non_interactive:
        host_discovery = yes_no("Run host discovery first and scan only responsive hosts?", True)

    quick, port_plan, timing = collect_scan_options(args)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work = SCANS_DIR / stamp
    work.mkdir()
    original_file = work / "original_targets.txt"
    write_target_file(original_file, targets)
    initial_target_file = original_file
    discovery_meta: dict[str, Any] | None = None

    if host_discovery:
        discovery_base = work / "host_discovery"
        discovery_cmd = discovery_command(nmap, original_file, discovery_base, dns)
        print("[*] Discovery command:\n    " + " ".join(shlex.quote(x) for x in discovery_cmd))
        if not args.print_command:
            discovery_exit = run_screen(screen, discovery_cmd, work, "host_discovery")
            discovery_xml = discovery_base.with_suffix(".xml")
            if not discovery_xml.exists():
                die(f"Host discovery did not produce XML output (exit {discovery_exit}).")
            live_hosts = extract_up_hosts(discovery_xml)
            if not live_hosts:
                die("Host discovery found no responsive hosts; initial scan was not started.")
            initial_target_file = work / "discovered_hosts.txt"
            write_target_file(initial_target_file, live_hosts)
            discovery_meta = {"exit_code": discovery_exit, "live_hosts": live_hosts}
            print(f"[*] Host discovery found {len(live_hosts)} responsive host(s).")

    initial_base = work / "initial_port_scan"
    initial_command = initial_scan_command(
        nmap, initial_target_file, initial_base, dns, port_plan, timing, host_discovery
    )
    print("[*] Initial port scan command (no -sV):\n    " + " ".join(shlex.quote(x) for x in initial_command))

    if args.print_command:
        print("[*] Final command depends on ports and hosts extracted from the initial XML.")
        return 0
    if not args.non_interactive and not yes_no("Run host discovery/initial scan stages?", False):
        print("[*] Cancelled.")
        return 0

    initial_exit = run_screen(screen, initial_command, work, "initial_port_scan")
    initial_xml = initial_base.with_suffix(".xml")
    if not initial_xml.exists():
        die(f"Initial scan did not produce XML output (exit {initial_exit}).")

    try:
        tcp_file, udp_file, final_targets, tcp_ports, udp_ports, initial_live_hosts = (
            extract_initial_scan_inventory(initial_xml, work)
        )
    except ET.ParseError as exc:
        die(f"Invalid initial-scan XML: {exc}")

    if not initial_live_hosts:
        die("The initial scan found no hosts with open TCP or UDP ports.")
    if not tcp_ports and not udp_ports:
        die("The initial scan found no open TCP or UDP ports.")

    print(f"[*] Initial scan hosts with open ports: {len(initial_live_hosts)}")
    print(f"[*] Unique TCP ports: {','.join(map(str, tcp_ports)) or 'none'}")
    print(f"[*] Unique UDP ports: {','.join(map(str, udp_ports)) or 'none'}")
    print(f"[*] Saved: {final_targets}")
    print(f"[*] Saved: {tcp_file}")
    print(f"[*] Saved: {udp_file}")

    final_output_raw = args.final_output
    if not final_output_raw and not args.non_interactive:
        final_output_raw = prompt(
            "Required final scan output base (directory and name, without extension)",
            str(work / "final_scan"),
        )
    if not final_output_raw:
        die("--final-output is required in non-interactive mode.")
    final_base = validate_final_output_base(final_output_raw)

    final_command = final_scan_command(
        nmap, final_targets, final_base, timing, tcp_ports, udp_ports
    )
    print("[*] Final service/version scan command:\n    " + " ".join(shlex.quote(x) for x in final_command))

    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "original_targets": targets,
        "host_discovery": discovery_meta,
        "quick_scan": quick,
        "initial_port_plan": port_plan.description,
        "initial_command": initial_command,
        "initial_exit_code": initial_exit,
        "initial_live_hosts_file": str(final_targets),
        "tcp_ports_file": str(tcp_file),
        "udp_ports_file": str(udp_file),
        "final_output_base": str(final_base),
        "final_command": final_command,
    }
    (work / "scan.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    if not args.non_interactive and not yes_no("Run the final authorized service/version scan?", False):
        print("[*] Final scan cancelled; initial scan artifacts were retained.")
        return 0

    final_exit = run_screen(screen, final_command, work, "final_service_scan")
    final_xml = Path(str(final_base) + ".xml")
    if not final_xml.exists():
        die(f"Final scan did not produce XML output (exit {final_exit}).")
    try:
        scan_id, hosts, ports = import_scan(final_xml, final_command)
    except ET.ParseError as exc:
        die(f"Invalid final-scan XML: {exc}")

    print(f"[*] Final scan ID: {scan_id}; hosts: {hosts}; port records: {ports}")
    print(f"[*] Host database: {FLAT_DB}")
    print(f"[*] SQLite database: {SQLITE_DB}")

    run_selected = args.run_modules
    if not args.non_interactive:
        run_selected = yes_no("Run available configuration-audit modules now?", True)
    if run_selected:
        context = ModuleContext(
            ROOT, SQLITE_DB, FLAT_DB, FINDINGS_DIR, SCANS_DIR, scan_id, nmap
        )
        run_modules(context)
    return final_exit


if __name__ == "__main__":
    raise SystemExit(main())
