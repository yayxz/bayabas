"""Web TLS discovery and cipher configuration audit.

Workflow:
1. Build an httpx-compatible host:port list from the current scan database.
2. Verify ProjectDiscovery httpx is available; offer a user-local installation of
   the latest stable Go toolchain and latest httpx when it is missing.
3. Run httpx against every open TCP host/port and save its complete output.
4. Run Nmap TLS scripts only against endpoints httpx confirms as HTTPS/TLS web
   services.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

HTTPX_INSTALL = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
LEGACY_PROTOCOLS = ("SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1")


def yes_no(message: str, default: bool = False) -> bool:
    """Prompt only when an interactive terminal is available."""
    if not sys.stdin.isatty():
        return default
    marker = "Y/n" if default else "y/N"
    answer = input(f"{message} [{marker}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def display_host(host: str) -> str:
    """Bracket IPv6 literals for host:port input."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def all_tcp_targets(context) -> list[tuple[str, int]]:
    """Return every open TCP endpoint in the current parent scan."""
    with context.connect() as db:
        rows = db.execute(
            """
            SELECT h.address, h.hostname, p.port
            FROM hosts h
            JOIN ports p ON p.host_id = h.id
            WHERE h.scan_id=? AND p.state='open' AND p.protocol='tcp'
            ORDER BY h.address, p.port
            """,
            (context.scan_id,),
        ).fetchall()

    targets: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for row in rows:
        # Prefer the Nmap-resolved hostname for virtual hosting and TLS SNI.
        host = (row["hostname"] or row["address"]).rstrip(".")
        item = (host, int(row["port"]))
        if item not in seen:
            seen.add(item)
            targets.append(item)
    return targets


def write_httpx_input(path: Path, targets: list[tuple[str, int]]) -> None:
    path.write_text(
        "".join(f"{display_host(host)}:{port}\n" for host, port in targets),
        encoding="utf-8",
    )


def candidate_httpx_paths() -> list[Path]:
    paths: list[Path] = []
    discovered = shutil.which("httpx")
    if discovered:
        paths.append(Path(discovered))
    paths.extend(
        [
            Path.home() / "go" / "bin" / "httpx",
            Path.home() / ".local" / "bin" / "httpx",
        ]
    )
    return paths


def valid_httpx(path: Path) -> bool:
    if not path.is_file() or not os.access(path, os.X_OK):
        return False
    try:
        completed = subprocess.run(
            [str(path), "-version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = completed.stdout.lower()
    # ProjectDiscovery builds expose a version flag and identify httpx in output.
    return completed.returncode == 0 and "httpx" in output


def find_httpx() -> Path | None:
    for path in candidate_httpx_paths():
        if valid_httpx(path):
            return path.resolve()
    return None


def go_environment(go_root: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    path_parts: list[str] = []
    if go_root:
        env["GOROOT"] = str(go_root)
        path_parts.append(str(go_root / "bin"))
    path_parts.extend([str(Path.home() / "go" / "bin"), env.get("PATH", "")])
    env["PATH"] = os.pathsep.join(path_parts)
    return env


def find_go() -> tuple[Path | None, dict[str, str]]:
    system_go = shutil.which("go")
    if system_go:
        return Path(system_go), go_environment()

    local_root = Path.home() / ".local" / "go"
    local_go = local_root / "bin" / "go"
    if local_go.is_file() and os.access(local_go, os.X_OK):
        return local_go, go_environment(local_root)
    return None, go_environment()


def platform_go_arch() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    os_map = {"linux": "linux", "darwin": "darwin"}
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    if system not in os_map or machine not in arch_map:
        raise RuntimeError(
            f"Automatic Go installation is unsupported on {system}/{machine}. "
            "Install Go manually and rerun the module."
        )
    return os_map[system], arch_map[machine]


def install_latest_go(log) -> tuple[Path, dict[str, str]]:
    """Install the latest stable Go release under ~/.local/go.

    The release metadata supplies the archive SHA-256, which is verified before
    extraction. This avoids modifying /usr/local or invoking a package manager.
    """
    goos, goarch = platform_go_arch()
    metadata_url = "https://go.dev/dl/?mode=json"
    log.write(f"Fetching Go release metadata: {metadata_url}\n")
    with urllib.request.urlopen(metadata_url, timeout=30) as response:
        releases = json.load(response)

    archive_info: dict[str, Any] | None = None
    version = ""
    for release in releases:
        if not release.get("stable"):
            continue
        for file_info in release.get("files", []):
            if (
                file_info.get("os") == goos
                and file_info.get("arch") == goarch
                and file_info.get("kind") == "archive"
                and str(file_info.get("filename", "")).endswith(".tar.gz")
            ):
                archive_info = file_info
                version = str(release.get("version", ""))
                break
        if archive_info:
            break

    if not archive_info:
        raise RuntimeError(f"No stable Go archive found for {goos}/{goarch}.")

    filename = str(archive_info["filename"])
    expected_sha = str(archive_info["sha256"])
    download_url = f"https://go.dev/dl/{filename}"
    log.write(f"Downloading {version}: {download_url}\n")

    with tempfile.TemporaryDirectory(prefix="bayabas_go_") as temp_dir:
        archive = Path(temp_dir) / filename
        with urllib.request.urlopen(download_url, timeout=120) as response, archive.open("wb") as out:
            shutil.copyfileobj(response, out)

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest.lower() != expected_sha.lower():
            raise RuntimeError("Go archive SHA-256 verification failed.")

        install_parent = Path.home() / ".local"
        install_root = install_parent / "go"
        install_parent.mkdir(parents=True, exist_ok=True)
        if install_root.exists():
            shutil.rmtree(install_root)
        with tarfile.open(archive, "r:gz") as bundle:
            parent_resolved = install_parent.resolve()
            for member in bundle.getmembers():
                destination = (install_parent / member.name).resolve()
                if destination != parent_resolved and parent_resolved not in destination.parents:
                    raise RuntimeError("Unsafe path detected in the Go archive.")
            bundle.extractall(install_parent)

    go_binary = install_root / "bin" / "go"
    if not go_binary.is_file():
        raise RuntimeError("Go installation completed without a usable go binary.")
    env = go_environment(install_root)
    completed = subprocess.run(
        [str(go_binary), "version"], env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
    )
    log.write(completed.stdout)
    if completed.returncode != 0:
        raise RuntimeError("The newly installed Go toolchain failed its version check.")
    return go_binary, env


def install_httpx(ssl_dir: Path) -> Path | None:
    """Offer installation of Go (when needed) and latest ProjectDiscovery httpx."""
    log_path = ssl_dir / "httpx_install.log"
    if not yes_no(
        "ProjectDiscovery httpx is missing. Install Go if required and install the latest httpx?",
        default=False,
    ):
        log_path.write_text(
            "Installation declined. TLS cipher checks were not run because httpx is required.\n",
            encoding="utf-8",
        )
        return None

    with log_path.open("w", encoding="utf-8") as log:
        try:
            go_binary, env = find_go()
            if go_binary is None:
                go_binary, env = install_latest_go(log)
            else:
                version = subprocess.run(
                    [str(go_binary), "version"], env=env, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
                )
                log.write(version.stdout)

            log.write(f"Installing {HTTPX_INSTALL}\n")
            completed = subprocess.run(
                [str(go_binary), "install", "-v", HTTPX_INSTALL],
                env=env,
                text=True,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
            if completed.returncode != 0:
                log.write(f"httpx installation failed with exit code {completed.returncode}.\n")
                return None
        except Exception as exc:
            log.write(f"Installation failed: {exc}\n")
            return None

    installed = find_httpx()
    if installed is None:
        with log_path.open("a", encoding="utf-8") as log:
            log.write("httpx was installed but could not be located or validated.\n")
    return installed


def run_httpx(httpx: Path, input_path: Path, result_path: Path) -> tuple[int, list[dict[str, Any]]]:
    """Run httpx and preserve stdout plus stderr in the requested result file."""
    command = [
        str(httpx),
        "-l", str(input_path),
        "-json",
        "-probe",
        "-tls-grab",
        "-no-fallback",
        "-no-color",
        "-disable-update-check",
    ]
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    result_path.write_text(
        "COMMAND: " + " ".join(command) + "\n\n"
        "=== STDOUT (JSONL) ===\n"
        + completed.stdout
        + "\n=== STDERR ===\n"
        + completed.stderr
        + f"\n=== EXIT CODE: {completed.returncode} ===\n",
        encoding="utf-8",
    )

    records: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return completed.returncode, records


def parse_authority(value: str) -> tuple[str, int] | None:
    """Parse host:port or [IPv6]:port without accepting paths."""
    value = value.strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)]:(\d+)", value)
        if not match:
            return None
        return match.group(1), int(match.group(2))
    host, separator, port = value.rpartition(":")
    if not separator or not port.isdigit():
        return None
    return host, int(port)


def https_targets(records: list[dict[str, Any]]) -> list[tuple[str, int]]:
    """Extract endpoints that httpx positively identified with an HTTPS URL."""
    targets: set[tuple[str, int]] = set()
    for record in records:
        url = str(record.get("url") or record.get("final_url") or "")
        if not url.lower().startswith("https://"):
            continue
        authority = url.split("/", 3)[2]
        parsed = parse_authority(authority)
        if parsed:
            targets.add(parsed)
            continue
        # HTTPS without an explicit port implies 443.
        targets.add((authority.strip("[]"), 443))
    return sorted(targets)


def script_output(xml_path: Path) -> str:
    root = ET.parse(xml_path).getroot()
    outputs = [
        script.get("output", "")
        for script in root.findall(".//script")
        if script.get("id") in {"ssl-enum-ciphers", "ssl-dh-params"}
    ]
    return "\n\n".join(outputs)


def analyze(output: str) -> dict[str, Any]:
    upper = output.upper()
    protocols = {protocol for protocol in (*LEGACY_PROTOCOLS, "TLSV1.2", "TLSV1.3") if protocol in upper}
    ciphers = sorted(set(re.findall(r"\b(?:TLS|SSL)_[A-Z0-9_]+(?:_WITH_[A-Z0-9_]+)?\b", upper)))

    weak: dict[str, list[str]] = {
        "RC4": [], "DES": [], "3DES": [], "SHA1": [], "EXPORT": [],
        "LESS_THAN_128_BITS": [], "CBC": [], "WEAK_DH": [],
        "NON_EPHEMERAL_KEY_EXCHANGE": [],
    }
    for cipher in ciphers:
        if "RC4" in cipher:
            weak["RC4"].append(cipher)
        if re.search(r"(?:^|_)DES(?:_|$)", cipher) and "3DES" not in cipher:
            weak["DES"].append(cipher)
        if "3DES" in cipher or "DES_EDE" in cipher:
            weak["3DES"].append(cipher)
        if "SHA" in cipher and "SHA256" not in cipher and "SHA384" not in cipher:
            weak["SHA1"].append(cipher)
        if "EXPORT" in cipher or "_EXP_" in cipher:
            weak["EXPORT"].append(cipher)
        if any(marker in cipher for marker in ("_40_", "_56_", "RC2", "IDEA")):
            weak["LESS_THAN_128_BITS"].append(cipher)
        if "_CBC_" in cipher:
            weak["CBC"].append(cipher)
        if "_RSA_WITH_" in cipher:
            weak["NON_EPHEMERAL_KEY_EXCHANGE"].append(cipher)

    dh_lines = [
        line.strip() for line in output.splitlines()
        if re.search(r"(?i)(diffie-hellman|dh parameters?|modulus)", line)
    ]
    if any(re.search(r"(?<!\d)(512|768|1024)\s*(?:bits?|bit)", line, re.I) for line in dh_lines):
        weak["WEAK_DH"] = dh_lines

    return {
        "protocols": sorted(protocols),
        "ciphers": ciphers,
        "weak": {name: sorted(set(values)) for name, values in weak.items() if values},
    }


def run(context) -> int:
    ssl_dir = context.finding_dir("SSL")
    tls_dir = context.finding_dir("SSL", "TLSv10-11")
    insecure_dir = context.finding_dir("SSL", "Insecure_SSL")
    httpx_input = ssl_dir / "httpx_input.txt"
    httpx_result = ssl_dir / "httpx_result.txt"

    database_targets = all_tcp_targets(context)
    if not database_targets:
        httpx_result.write_text("No open TCP host/port records were available.\n", encoding="utf-8")
        return 0
    write_httpx_input(httpx_input, database_targets)

    httpx = find_httpx()
    if httpx is None:
        httpx = install_httpx(ssl_dir)
    if httpx is None:
        httpx_result.write_text(
            "ProjectDiscovery httpx is unavailable. Cipher checks were skipped. "
            "See httpx_install.log for details.\n",
            encoding="utf-8",
        )
        return 0

    httpx_exit, records = run_httpx(httpx, httpx_input, httpx_result)
    targets = https_targets(records)
    if not targets:
        with httpx_result.open("a", encoding="utf-8") as output:
            output.write("\nNo HTTPS/TLS web services were confirmed; Nmap cipher checks were skipped.\n")
        return 0

    old_protocol_hosts: list[tuple[str, int, list[str]]] = []
    insecure_hosts: list[dict[str, Any]] = []
    old_raw = ""
    insecure_raw = ""

    for host, port in targets:
        safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
        xml = insecure_dir / f".{safe_host}_{port}.xml"
        command = [
            context.nmap_path, "-Pn", "-sV", "-p", str(port),
            "--script", "ssl-enum-ciphers,ssl-dh-params", "-oX", str(xml), host,
        ]
        completed = subprocess.run(
            command, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False
        )
        if not xml.exists():
            continue
        output = script_output(xml)
        assessment = analyze(output)
        legacy = [protocol for protocol in LEGACY_PROTOCOLS if protocol in assessment["protocols"]]
        if legacy:
            old_protocol_hosts.append((host, port, legacy))
            if not old_raw:
                old_raw = completed.stdout + "\n" + output
        if assessment["weak"]:
            insecure_hosts.append({"host": host, "port": port, **assessment})
            if not insecure_raw:
                insecure_raw = completed.stdout + "\n" + output
        try:
            xml.unlink()
        except OSError:
            pass

    finding_count = 0
    if old_protocol_hosts:
        finding_count += len(old_protocol_hosts)
        labels = {
            "SSLV2": "SSLv2", "SSLV3": "SSLv3",
            "TLSV1.0": "TLSv1.0", "TLSV1.1": "TLSv1.1",
        }
        (tls_dir / "affected_hosts.txt").write_text(
            "".join(
                f"{host}, {port} [{' & '.join(labels[x] for x in versions)}]\n"
                for host, port, versions in old_protocol_hosts
            ),
            encoding="utf-8",
        )
        (tls_dir / "raw_output.txt").write_text(old_raw + "\n", encoding="utf-8")

    if insecure_hosts:
        finding_count += len(insecure_hosts)
        (insecure_dir / "affected_hosts.txt").write_text(
            "".join(f"{item['host']}, {item['port']}\n" for item in insecure_hosts),
            encoding="utf-8",
        )
        all_weak: dict[str, set[str]] = {}
        for host_result in insecure_hosts:
            for category, values in host_result["weak"].items():
                all_weak.setdefault(category, set()).update(values)
        lines: list[str] = []
        for category in sorted(all_weak):
            lines.append(f"{category}:")
            lines.extend(f"  - {cipher}" for cipher in sorted(all_weak[category]))
        (insecure_dir / "weak_ciphers.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
        (insecure_dir / "raw_output.txt").write_text(insecure_raw + "\n", encoding="utf-8")

    if httpx_exit != 0:
        print(
            f"[!] httpx exited with {httpx_exit}; results were partially processed. "
            f"Review {httpx_result}",
            file=sys.stderr,
        )
    return finding_count
