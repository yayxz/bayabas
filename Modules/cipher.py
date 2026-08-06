"""TLS web-service, cipher, protocol, and certificate configuration audit."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

HTTPX_INSTALL = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
LEGACY_PROTOCOLS = ("SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1")


def yes_no(message: str, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        return default
    marker = "Y/n" if default else "y/N"
    answer = input(f"{message} [{marker}]: ").strip().lower()
    return default if not answer else answer in {"y", "yes"}


def remove_stale(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def bracket(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def open_tcp_targets(context) -> list[tuple[str, int]]:
    with context.connect() as db:
        rows = db.execute(
            """
            SELECT h.address,p.port
            FROM hosts h JOIN ports p ON p.host_id=h.id
            WHERE h.scan_id=? AND p.state='open' AND p.protocol='tcp'
            ORDER BY h.address,p.port
            """,
            (context.scan_id,),
        ).fetchall()
    return [(row["address"], int(row["port"])) for row in rows]


def associated_names(context, address: str) -> list[str]:
    with context.connect() as db:
        rows = db.execute(
            """
            SELECT hostname,source FROM resolutions
            WHERE scan_id=? AND address=?
            ORDER BY CASE source
                WHEN 'forward-target' THEN 0
                WHEN 'nmap-xml' THEN 1
                WHEN 'reverse-ptr' THEN 2
                ELSE 3 END, hostname
            """,
            (context.scan_id, address),
        ).fetchall()
    return list(dict.fromkeys(row["hostname"] for row in rows if row["hostname"]))


def find_httpx() -> str | None:
    candidate = shutil.which("httpx")
    if candidate:
        try:
            result = subprocess.run([candidate, "-version"], text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=10, check=False)
            if "projectdiscovery" in result.stdout.lower() or "httpx" in result.stdout.lower():
                return candidate
        except Exception:
            pass
    local = Path.home() / "go" / "bin" / "httpx"
    return str(local) if local.exists() else None


def install_httpx(log_path: Path) -> str | None:
    if not yes_no("ProjectDiscovery httpx is missing. Install Go if needed and latest httpx?", False):
        return None
    go = shutil.which("go")
    with log_path.open("w", encoding="utf-8") as log:
        if not go:
            log.write("Go is not installed. Automatic Go bootstrap is intentionally not performed in this revision.\n")
            print("[!] Install Go from the official Go distribution, then rerun the module.")
            return None
        completed = subprocess.run(
            [go, "install", "-v", HTTPX_INSTALL],
            text=True, stdout=log, stderr=subprocess.STDOUT, check=False
        )
        if completed.returncode != 0:
            return None
    return find_httpx()


def run_httpx(binary: str, input_path: Path, result_path: Path) -> list[dict[str, Any]]:
    command = [
        binary, "-l", str(input_path), "-json", "-probe", "-tls-grab",
        "-no-fallback", "-no-color", "-disable-update-check",
    ]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False)
    result_path.write_text(
        "$ " + " ".join(command)
        + "\n\nSTDOUT\n" + completed.stdout
        + "\nSTDERR\n" + completed.stderr
        + f"\nEXIT_CODE\n{completed.returncode}\n",
        encoding="utf-8",
    )
    records = []
    for line in completed.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def https_endpoints(records: list[dict[str, Any]], family: int) -> list[tuple[str, int, str]]:
    endpoints: set[tuple[str, int, str]] = set()
    for record in records:
        url = str(record.get("url") or record.get("input") or "")
        if not url.lower().startswith("https://"):
            continue
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            continue
        try:
            if ipaddress.ip_address(host).version != family:
                continue
        except ValueError:
            pass
        endpoints.add((host, port, url))
    return sorted(endpoints)


def parse_nmap_tls(xml_path: Path) -> tuple[str, set[str], dict[str, set[str]]]:
    root = ET.parse(xml_path).getroot()
    outputs = []
    for script in root.findall(".//script"):
        if script.get("id") in {"ssl-enum-ciphers", "ssl-dh-params"}:
            outputs.append(script.get("output", ""))
    output = "\n\n".join(outputs)
    upper = output.upper()
    protocols = {p for p in LEGACY_PROTOCOLS if p in upper}
    ciphers = set(re.findall(r"\b(?:TLS|SSL)_[A-Z0-9_]+(?:_WITH_[A-Z0-9_]+)?\b", upper))
    weak: dict[str, set[str]] = {}
    def add(category: str, value: str) -> None:
        weak.setdefault(category, set()).add(value)
    for cipher in ciphers:
        if "RC4" in cipher:
            add("RC4", cipher)
        if re.search(r"(?:^|_)DES(?:_|$)", cipher) and "3DES" not in cipher:
            add("DES", cipher)
        if "3DES" in cipher or "DES_EDE" in cipher:
            add("3DES", cipher)
        if "SHA" in cipher and "SHA256" not in cipher and "SHA384" not in cipher:
            add("SHA1", cipher)
        if "EXPORT" in cipher or "_EXP_" in cipher:
            add("EXPORT", cipher)
        if any(x in cipher for x in ("_40_", "_56_", "RC2", "IDEA")):
            add("LESS_THAN_128_BITS", cipher)
        if "_CBC_" in cipher:
            add("CBC", cipher)
        if "_RSA_WITH_" in cipher:
            add("NON_EPHEMERAL_KEY_EXCHANGE", cipher)
    for line in output.splitlines():
        if re.search(r"(?i)(diffie-hellman|dh parameters?|modulus)", line) and re.search(
            r"(?<!\d)(512|768|1024)\s*(?:bits?|bit)", line, re.I
        ):
            add("WEAK_DH", line.strip())
    return output, protocols, weak


def openssl_probe(address: str, port: int, servername: str | None) -> tuple[str, str]:
    connect = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    command = ["openssl", "s_client", "-connect", connect, "-showcerts", "-verify_return_error"]
    if servername:
        command += ["-servername", servername, "-verify_hostname", servername]
    completed = subprocess.run(
        command, input="", text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=30, check=False
    )
    return " ".join(command), completed.stdout


def leaf_certificate_text(address: str, port: int, servername: str | None) -> str:
    connect = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    command = ["openssl", "s_client", "-connect", connect, "-showcerts"]
    if servername:
        command += ["-servername", servername]
    first = subprocess.run(command, input="", text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=30, check=False)
    match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", first.stdout, re.S)
    if not match:
        return ""
    second = subprocess.run(
        ["openssl", "x509", "-noout", "-text", "-dates", "-subject", "-issuer", "-ext", "subjectAltName"],
        input=match.group(0), text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=15, check=False
    )
    return second.stdout


def certificate_issues(context, address: str, port: int) -> dict[str, str]:
    names = associated_names(context, address)
    servername = names[0] if names else None
    try:
        command, verify_output = openssl_probe(address, port, servername)
        cert_text = leaf_certificate_text(address, port, servername)
    except (subprocess.TimeoutExpired, OSError):
        return {}
    evidence = f"$ {command}\n\n{verify_output}\n\nCERTIFICATE\n{cert_text}"
    issues: dict[str, str] = {}

    if re.search(r"verify error:num=(18|19|20|21|27|62|64|66|67|68|69|79)\b", verify_output, re.I) or \
       re.search(r"self[- ]signed|unable to get local issuer|unable to verify", verify_output, re.I):
        issues["untrusted_ca"] = evidence

    if re.search(r"certificate has expired|notAfter=.*", verify_output, re.I):
        if "certificate has expired" in verify_output.lower():
            issues["expired"] = evidence
    # OpenSSL verify_hostname is the decisive hostname evidence.
    if servername and re.search(r"hostname mismatch|does not match", verify_output, re.I):
        issues["no_valid_target_hostname"] = evidence

    san_names = re.findall(r"DNS:([^,\s]+)", cert_text)
    mismatched = []
    for name in san_names:
        try:
            addresses = {
                item[4][0] for item in socket.getaddrinfo(
                    name.rstrip("."), None,
                    family=socket.AF_INET if context.family == 4 else socket.AF_INET6,
                    type=socket.SOCK_STREAM,
                )
            }
        except socket.gaierror:
            continue
        if addresses and address not in addresses:
            mismatched.append(f"{name} -> {', '.join(sorted(addresses))}")
    if mismatched:
        issues["hostname_not_target"] = evidence + "\n\nMISMATCHED DNS NAMES\n" + "\n".join(mismatched)

    signature = re.search(r"Signature Algorithm:\s*([^\n]+)", cert_text, re.I)
    if signature and re.search(r"\b(md5|sha1)\b", signature.group(1), re.I):
        issues["deprecated_hash"] = evidence
    return issues


def run(context) -> int:
    ssl_family_root = context.findings_dir / "SSL" / context.family_label
    remove_stale(ssl_family_root)
    candidates = open_tcp_targets(context)
    if not candidates:
        return 0

    with tempfile.TemporaryDirectory(prefix=f"bayabas_tls_{context.family}_") as temporary:
        temp = Path(temporary)
        httpx_input = temp / "httpx_input.txt"
        httpx_result = temp / "httpx_result.txt"
        httpx_input.write_text(
            "".join(f"{bracket(host)}:{port}\n" for host, port in candidates),
            encoding="utf-8",
        )

        binary = find_httpx()
        install_log = temp / "httpx_install.log"
        if not binary:
            binary = install_httpx(install_log)
        if not binary:
            return 0

        records = run_httpx(binary, httpx_input, httpx_result)
        endpoints = https_endpoints(records, context.family)
        if not endpoints:
            return 0

        weak_hosts: set[tuple[str, int]] = set()
        weak_values: dict[str, set[str]] = {}
        weak_evidence = ""
        legacy_hosts: list[tuple[str, int, set[str]]] = []
        legacy_evidence = ""
        certificate_hosts: set[tuple[str, int]] = set()
        certificate_evidence: dict[str, str] = {}

        for address, port, _url in endpoints:
            xml = temp / f"tls_{address.replace(':', '_')}_{port}.xml"
            command = [
                context.nmap_path,
                *(["-6"] if context.family == 6 else []),
                "-Pn", "-sV", "-p", str(port),
                "--script", "ssl-enum-ciphers,ssl-dh-params",
                "-oX", str(xml), address,
            ]
            completed = subprocess.run(
                command, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False
            )
            if xml.exists():
                raw, protocols, weak = parse_nmap_tls(xml)
                if weak:
                    weak_hosts.add((address, port))
                    for category, values in weak.items():
                        weak_values.setdefault(category, set()).update(values)
                    if not weak_evidence:
                        weak_evidence = f"$ {' '.join(command)}\n\n{completed.stdout}\n{raw}"
                insecure = protocols & {"TLSV1.0", "TLSV1.1", "SSLV2", "SSLV3"}
                if insecure:
                    legacy_hosts.append((address, port, insecure))
                    if not legacy_evidence:
                        legacy_evidence = f"$ {' '.join(command)}\n\n{completed.stdout}\n{raw}"

            issues = certificate_issues(context, address, port)
            if issues:
                certificate_hosts.add((address, port))
                for issue, evidence in issues.items():
                    certificate_evidence.setdefault(issue, evidence)

        finding_count = 0

        if weak_hosts and weak_values and weak_evidence:
            out = ssl_family_root / "Weak TLS-SSL Cipher"
            out.mkdir(parents=True, exist_ok=True)
            (out / "affected_hosts.txt").write_text(
                "".join(f"{host}, {port}\n" for host, port in sorted(weak_hosts)),
                encoding="utf-8",
            )
            lines = []
            for category in sorted(weak_values):
                lines.append(f"{category}:")
                lines.extend(f"  - {value}" for value in sorted(weak_values[category]))
            (out / "weak_ciphers.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            (out / "raw_output.txt").write_text(weak_evidence + "\n", encoding="utf-8")
            finding_count += len(weak_hosts)

        if legacy_hosts and legacy_evidence:
            out = ssl_family_root / "Insecure TLS Versions"
            out.mkdir(parents=True, exist_ok=True)
            def label(values: set[str]) -> str:
                order = ["SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1"]
                pretty = {
                    "SSLV2": "SSLv2", "SSLV3": "SSLv3",
                    "TLSV1.0": "TLSv1.0", "TLSV1.1": "TLSv1.1",
                }
                return " and ".join(pretty[x] for x in order if x in values)
            (out / "affected_hosts.txt").write_text(
                "".join(f"{host}, {port} [{label(protocols)}]\n"
                        for host, port, protocols in legacy_hosts),
                encoding="utf-8",
            )
            (out / "raw_output.txt").write_text(legacy_evidence + "\n", encoding="utf-8")
            finding_count += len(legacy_hosts)

        if certificate_hosts and certificate_evidence:
            out = ssl_family_root / "Insecure SSL Certificate"
            out.mkdir(parents=True, exist_ok=True)
            (out / "affected_hosts.txt").write_text(
                "".join(f"{host}, {port}\n" for host, port in sorted(certificate_hosts)),
                encoding="utf-8",
            )
            names = {
                "untrusted_ca": "evidence_untrusted_ca.txt",
                "expired": "evidence_expired.txt",
                "hostname_not_target": "evidence_hostname_not_target.txt",
                "no_valid_target_hostname": "evidence_no_valid_target_hostname.txt",
                "deprecated_hash": "evidence_deprecated_hash.txt",
            }
            for issue, evidence in certificate_evidence.items():
                (out / names[issue]).write_text(evidence + "\n", encoding="utf-8")
            finding_count += len(certificate_hosts)

        # Save httpx artifacts only when TLS endpoints were positively identified.
        if finding_count:
            ssl_family_root.mkdir(parents=True, exist_ok=True)
            shutil.copy2(httpx_input, ssl_family_root / "httpx_input.txt")
            shutil.copy2(httpx_result, ssl_family_root / "httpx_result.txt")
            if install_log.exists() and install_log.stat().st_size:
                shutil.copy2(install_log, ssl_family_root / "httpx_install.log")
        elif ssl_family_root.exists():
            shutil.rmtree(ssl_family_root)

        return finding_count
