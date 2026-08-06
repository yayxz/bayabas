#!/usr/bin/env python3
"""
Bayabas: authorized Nmap scan orchestration and configuration-audit framework.

Use only against systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
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
from typing import Any, Iterable

APP = "Bayabas"
VERSION = "0.7.0"
ROOT = Path(__file__).resolve().parent
MODULES_DIR = ROOT / "Modules"
SCANS_DIR = ROOT / "Scans"

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


@dataclass
class ScreenJob:
    session: str
    label: str
    command: list[str]
    work_dir: Path
    done_file: Path
    exit_file: Path
    wrapper: Path
    started: float


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


def ensure_dependencies() -> tuple[str, str]:
    nmap = shutil.which("nmap")
    screen = shutil.which("screen")
    if not nmap:
        die("Nmap is not installed or available in PATH.")
    if not screen:
        die("GNU Screen is not installed. Install it before running Bayabas.")
    return nmap, screen


def classify_target(value: str) -> str:
    value = value.strip()
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
    for value in values:
        classify_target(value)
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def resolve_hostname(hostname: str, family: int) -> set[str]:
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    try:
        return {
            item[4][0]
            for item in socket.getaddrinfo(hostname.rstrip("."), None, family=af, type=socket.SOCK_STREAM)
        }
    except socket.gaierror:
        return set()


def split_targets(targets: list[str], ipv6_enabled: bool) -> tuple[list[str], list[str], set[tuple[str, str, str, int]]]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    mappings: set[tuple[str, str, str, int]] = set()

    for target in targets:
        kind = classify_target(target)
        if kind == "ipv4":
            ipv4.add(target)
        elif kind == "ipv6":
            if ipv6_enabled:
                ipv6.add(target)
        else:
            hostname = target.rstrip(".").lower()
            for address in resolve_hostname(hostname, 4):
                ipv4.add(address)
                mappings.add((hostname, address, "forward-target", 4))
            if ipv6_enabled:
                for address in resolve_hostname(hostname, 6):
                    ipv6.add(address)
                    mappings.add((hostname, address, "forward-target", 6))

    return sorted(ipv4), sorted(ipv6), mappings


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

    tcp = bool(re.search(r"(?:^|,)T:", raw, re.I))
    udp = bool(re.search(r"(?:^|,)U:", raw, re.I))
    if not tcp and not udp:
        tcp = True
    for token in re.findall(r"\d+(?:-\d+)?", raw):
        if "-" in token:
            left, right = map(int, token.split("-", 1))
            if not 1 <= left <= right <= 65535:
                raise ValueError(f"Invalid port range: {token}")
        elif not 1 <= int(token) <= 65535:
            raise ValueError(f"Invalid port: {token}")
    return PortPlan(["-p", raw], tcp, udp, raw)


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
    scan_root = assessment_root / label
    db_root = assessment_root / "Host_DB" / label
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
    )


def write_lines(path: Path, values: Iterable[str]) -> None:
    values = list(values)
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")


def nmap_family_arg(family: int) -> list[str]:
    return ["-6"] if family == 6 else []


def discovery_command(nmap: str, context: FamilyContext, dns: str | None) -> list[str]:
    command = [nmap, *nmap_family_arg(context.family), "-sn", "--reason", "-v",
               "-iL", str(context.original_targets_file),
               "-oA", str(context.discovery_dir / "host_discovery")]
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


def make_job(screen: str, session: str, label: str, command: list[str], work_dir: Path) -> ScreenJob:
    result = subprocess.run([screen, "-ls"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if re.search(rf"\d+\.{re.escape(session)}\s", result.stdout):
        die(f"Screen session already exists: {session}")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
    done = work_dir / f".{safe}.done"
    exit_file = work_dir / f".{safe}.exit"
    wrapper = work_dir / f"run_{safe}.sh"
    wrapper.write_text(
        "#!/usr/bin/env bash\nset +e\n"
        + " ".join(shlex.quote(x) for x in command)
        + "\ncode=$?\nprintf '%s\\n' \"$code\" > "
        + shlex.quote(str(exit_file))
        + "\ntouch " + shlex.quote(str(done))
        + "\nexit \"$code\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    return ScreenJob(session, label, command, work_dir, done, exit_file, wrapper, time.monotonic())


def start_jobs(screen: str, jobs: list[ScreenJob]) -> None:
    for job in jobs:
        subprocess.run([screen, "-DmS", job.session, "bash", str(job.wrapper)], check=True)
        print(f"[*] Started {job.label} in Screen session {job.session!r}")


def wait_jobs(screen: str, jobs: list[ScreenJob]) -> dict[str, int]:
    remaining = {job.session: job for job in jobs}
    results: dict[str, int] = {}
    try:
        while remaining:
            for session, job in list(remaining.items()):
                if not job.done_file.exists():
                    continue
                try:
                    code = int(job.exit_file.read_text(encoding="utf-8").strip())
                except (FileNotFoundError, ValueError):
                    code = 1
                elapsed = int(time.monotonic() - job.started)
                results[session] = code
                print(f"\a[*] {job.label} completed after {elapsed}s (exit {code}).")
                remaining.pop(session)
            if remaining:
                time.sleep(2)
    except KeyboardInterrupt:
        for job in jobs:
            subprocess.run([screen, "-S", job.session, "-X", "quit"], check=False)
        raise SystemExit(130)
    finally:
        for job in jobs:
            subprocess.run(
                [screen, "-S", job.session, "-X", "quit"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            )
    return results


def run_one_screen(screen: str, session: str, label: str, command: list[str], work_dir: Path) -> int:
    job = make_job(screen, session, label, command, work_dir)
    start_jobs(screen, [job])
    return wait_jobs(screen, [job])[session]


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
) -> set[tuple[str, str, str]]:
    result = {(h, a, s) for h, a, s, f in explicit if f == family}
    for address in live_hosts:
        for hostname in reverse_names(address):
            result.add((hostname, address, "reverse-ptr"))
            for resolved in resolve_hostname(hostname, family):
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


def run_modules(nmap: str, contexts: list[FamilyContext], assessment: dict[str, Any]) -> None:
    modules = discover_modules()
    assessment["modules"] = {}
    for name, module in modules:
        record = {"started": datetime.now(timezone.utc).isoformat(), "families": {}, "status": "running"}
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
                    findings_dir=family.scan_root.parent / "Findings",
                    scans_dir=family.scan_root,
                    scan_id=family.scan_id,
                    nmap_path=nmap,
                )
                count = int(module.run(context))
                record["families"][family.label] = count
                total += count
            record["status"] = "completed"
            record["findings"] = total
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = str(exc)
            print(f"[!] Module {name} failed: {exc}", file=sys.stderr)
        record["completed"] = datetime.now(timezone.utc).isoformat()


def write_assessment(path: Path, assessment: dict[str, Any]) -> None:
    path.write_text(json.dumps(assessment, indent=2, sort_keys=True), encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Authorized Nmap and configuration-audit framework.")
    p.add_argument("targets", nargs="?", help="Target file, comma-separated targets, or one target")
    p.add_argument("--dns-server")
    p.add_argument("--quick", action="store_true")
    p.add_argument("--host-discovery", action="store_true")
    p.add_argument("--ipv6", action="store_true", help="Also resolve and scan IPv6 targets")
    p.add_argument("--ports")
    p.add_argument("--max-retries")
    p.add_argument("--max-scan-delay")
    p.add_argument("--min-parallelism")
    p.add_argument("--mtu")
    p.add_argument("--min-rate")
    p.add_argument("--max-hostgroup")
    p.add_argument("--ipv4-final-output")
    p.add_argument("--ipv6-final-output")
    p.add_argument("--run-modules", action="store_true")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--print-command", action="store_true")
    return p


def main() -> int:
    args = parser().parse_args()
    MODULES_DIR.mkdir(parents=True, exist_ok=True)
    nmap, screen = ensure_dependencies()

    raw = args.targets
    if not raw and not args.non_interactive:
        raw = prompt("Target file, comma-separated targets, or one target")
    if not raw:
        die("Targets are required.")
    targets = load_targets(raw)

    ipv6_enabled = args.ipv6
    if not args.non_interactive:
        ipv6_enabled = yes_no("Run IPv6 scans (-6) as well?", False)

    ipv4_targets, ipv6_targets, explicit_mappings = split_targets(targets, ipv6_enabled)
    if not ipv4_targets and not ipv6_targets:
        die("No targets resolved for the selected address families.")

    dns = args.dns_server
    if not dns and not args.non_interactive:
        dns = prompt("Preferred DNS server (--dns-server)", "8.8.8.8", valid_dns)
    if dns and not valid_dns(dns):
        die("Invalid DNS server.")

    host_discovery = args.host_discovery
    if not args.non_interactive:
        host_discovery = yes_no("Run host discovery first?", True)
    plan, timing = collect_scan_options(args)

    assessment_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    assessment_root = SCANS_DIR / assessment_id
    assessment_root.mkdir(parents=True, exist_ok=False)

    # Runtime-only assessment content. These paths do not exist in the repository.
    (assessment_root / "Host_DB").mkdir()
    (assessment_root / "Findings").mkdir()

    assessment_path = assessment_root / "assessment.json"
    assessment: dict[str, Any] = {
        "assessment_id": assessment_id,
        "assessment_uuid": str(uuid.uuid4()),
        "project": APP,
        "version": VERSION,
        "start_time": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "targets": targets,
        "ipv4_enabled": bool(ipv4_targets),
        "ipv6_enabled": bool(ipv6_targets),
        "host_discovery": host_discovery,
        "port_plan": plan.description,
        "commands": {},
        "statistics": {},
        "artifacts": {},
    }
    write_assessment(assessment_path, assessment)

    contexts: list[FamilyContext] = []
    if ipv4_targets:
        contexts.append(make_family_context(assessment_root, 4, ipv4_targets))
    if ipv6_targets:
        contexts.append(make_family_context(assessment_root, 6, ipv6_targets))

    final_jobs: list[ScreenJob] = []
    final_commands: dict[int, list[str]] = {}
    final_inventory: dict[int, tuple[list[int], list[int], list[str]]] = {}

    for context in contexts:
        write_lines(context.original_targets_file, context.targets)
        initial_targets = context.original_targets_file

        if host_discovery:
            command = discovery_command(nmap, context, dns)
            assessment["commands"][f"{context.label}_discovery"] = command
            print("[*] " + " ".join(shlex.quote(x) for x in command))
            if not args.print_command:
                code = run_one_screen(
                    screen, f"bayabas-{context.label.lower()}-discovery",
                    f"{context.label} host discovery", command, context.discovery_dir
                )
                xml = context.discovery_dir / "host_discovery.xml"
                if code != 0 or not xml.exists():
                    print(f"[!] {context.label} discovery failed; skipping this family.", file=sys.stderr)
                    continue
                discovered = extract_up_hosts(xml, context.family)
                if not discovered:
                    print(f"[*] {context.label} discovery found no live hosts.")
                    continue
                write_lines(context.discovery_targets_file, discovered)
                initial_targets = context.discovery_targets_file

        command = initial_command(nmap, context, initial_targets, plan, timing, dns, host_discovery)
        assessment["commands"][f"{context.label}_initial"] = command
        print("[*] " + " ".join(shlex.quote(x) for x in command))
        if args.print_command:
            continue
        code = run_one_screen(
            screen, f"bayabas-{context.label.lower()}-initial",
            f"{context.label} initial port scan", command, context.initial_dir
        )
        xml = context.initial_dir / "initial_scan.xml"
        if code != 0 or not xml.exists():
            print(f"[!] {context.label} initial scan failed; skipping final scan.", file=sys.stderr)
            continue
        tcp, udp, live = extract_initial(xml, context)
        if not live or (not tcp and not udp):
            print(f"[*] {context.label}: no open ports found; no final scan or findings will be produced.")
            continue
        final_inventory[context.family] = (tcp, udp, live)

        option_value = args.ipv4_final_output if context.family == 4 else args.ipv6_final_output
        if not option_value and not args.non_interactive:
            option_value = prompt(
                f"Required {context.label} final Nmap output base (name or full path)",
                f"{context.label.lower()}_final_scan",
            )
        if not option_value:
            die(f"--{context.label.lower()}-final-output is required.")
        context.final_output_base = validate_output_base(option_value, context.final_dir)
        command = final_command(nmap, context, timing, tcp, udp)
        final_commands[context.family] = command
        assessment["commands"][f"{context.label}_final"] = command
        final_jobs.append(
            make_job(
                screen, f"bayabas-{context.label.lower()}-final",
                f"{context.label} final service scan", command, context.final_dir
            )
        )

    write_assessment(assessment_path, assessment)
    if args.print_command:
        return 0
    if not final_jobs:
        assessment["status"] = "completed-no-open-services"
        assessment["end_time"] = datetime.now(timezone.utc).isoformat()
        write_assessment(assessment_path, assessment)
        return 0

    # IPv4 and IPv6 final scans start concurrently and remain protected by Screen.
    start_jobs(screen, final_jobs)
    results = wait_jobs(screen, final_jobs)

    successful_contexts: list[FamilyContext] = []
    for context in contexts:
        command = final_commands.get(context.family)
        if command is None or context.final_output_base is None:
            continue
        session = f"bayabas-{context.label.lower()}-final"
        xml = Path(str(context.final_output_base) + ".xml")
        if results.get(session) != 0 or not xml.exists():
            print(f"[!] {context.label} final scan failed.", file=sys.stderr)
            continue
        _, _, live = final_inventory[context.family]
        mappings = collect_family_mappings(context.family, explicit_mappings, live)
        write_resolution_files(context, mappings)
        scan_id, hosts, ports = import_final(context, xml, command, mappings)
        successful_contexts.append(context)
        assessment["statistics"][f"{context.label}_hosts"] = hosts
        assessment["statistics"][f"{context.label}_port_records"] = ports
        assessment["artifacts"][f"{context.label}_final_xml"] = str(xml)
        assessment["artifacts"][f"{context.label}_database"] = str(context.db_path)
        print(f"[*] {context.label}: imported {hosts} hosts and {ports} port records (scan {scan_id}).")

    run_selected = args.run_modules
    if not args.non_interactive:
        run_selected = yes_no("Run configuration-audit modules now?", True)
    if run_selected and successful_contexts:
        run_modules(nmap, successful_contexts, assessment)

    assessment["status"] = "completed"
    assessment["end_time"] = datetime.now(timezone.utc).isoformat()
    write_assessment(assessment_path, assessment)
    print("\a[*] Bayabas assessment completed.")
    print(f"[*] Metadata: {assessment_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
