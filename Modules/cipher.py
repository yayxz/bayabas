"""Bayabas TLS/SSL audit module (classifier revision 0.10.3).

Workflow:
1. Read open TCP services from the current IPv4/IPv6 inventory.
2. Run ProjectDiscovery httpx for web/TLS enrichment only.
3. Group every open TCP port by host.
4. Run one Nmap ssl-enum-ciphers + ssl-dh-params scan per host across all open TCP ports.
5. Perform native certificate validation with Python ssl + cryptography.
6. Create finding output only when validated findings exist.

Certificate checks:
- Untrusted / self-signed / unverifiable CA chain.
- Expired certificate.
- SAN hostname(s) resolving away from the tested address.
- No certificate hostname covering a hostname associated with the tested address.
- Deprecated certificate signature hash (MD5/SHA-1).

Use only against systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import importlib
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


HTTPX_INSTALL = "github.com/projectdiscovery/httpx/cmd/httpx@latest"

LEGACY_PROTOCOLS = (
    "SSLV2",
    "SSLV3",
    "TLSV1.0",
    "TLSV1.1",
)

CERT_LABEL_UNTRUSTED_CA = "Untrusted CA"
CERT_LABEL_EXPIRED = "Expired"
CERT_LABEL_SAN_MISMATCH = "SAN Hostname Mismatch"
CERT_LABEL_MISSING_COVERAGE = "Missing Hostname Coverage"
CERT_LABEL_DEPRECATED_SIG = "Deprecated Signature Algorithm"
CERT_LABEL_WILDCARD = "Wildcard SSL Certificate"

CERT_EVIDENCE_FILES = {
    CERT_LABEL_UNTRUSTED_CA: "evidence_untrusted_ca.txt",
    CERT_LABEL_EXPIRED: "evidence_expired.txt",
    CERT_LABEL_SAN_MISMATCH: "evidence_hostname_not_target.txt",
    CERT_LABEL_MISSING_COVERAGE: "evidence_no_valid_target_hostname.txt",
    CERT_LABEL_DEPRECATED_SIG: "evidence_deprecated_hash.txt",
}


def yes_no(message: str, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        return default

    marker = "Y/n" if default else "y/N"
    answer = input(f"{message} [{marker}]: ").strip().lower()

    if not answer:
        return default

    return answer in {"y", "yes"}


def remove_stale(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def bracket(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def open_tcp_targets(context) -> list[tuple[str, int]]:
    with context.connect() as db:
        rows = db.execute(
            """
            SELECT h.address, p.port
            FROM hosts h
            JOIN ports p ON p.host_id = h.id
            WHERE h.scan_id = ?
              AND p.state = 'open'
              AND p.protocol = 'tcp'
            ORDER BY h.address, p.port
            """,
            (context.scan_id,),
        ).fetchall()

    return [
        (row["address"], int(row["port"]))
        for row in rows
    ]


def associated_names(context, address: str) -> list[str]:
    """Return best-known hostnames for an IP, preferring explicit forward targets."""
    with context.connect() as db:
        rows = db.execute(
            """
            SELECT hostname, source
            FROM resolutions
            WHERE scan_id = ?
              AND address = ?
            ORDER BY
              CASE source
                WHEN 'forward-target' THEN 0
                WHEN 'nmap-xml' THEN 1
                WHEN 'reverse-ptr' THEN 2
                WHEN 'forward-ptr' THEN 3
                ELSE 4
              END,
              hostname
            """,
            (context.scan_id, address),
        ).fetchall()

    return list(
        dict.fromkeys(
            row["hostname"].rstrip(".").lower()
            for row in rows
            if row["hostname"]
        )
    )


# --------------------------------------------------------------------------
# Dependency checks
# --------------------------------------------------------------------------

def find_httpx() -> str | None:
    """Prefer ~/go/bin/httpx directly; PATH is only a fallback."""
    preferred = Path.home() / "go" / "bin" / "httpx"

    candidates: list[str] = []

    if preferred.is_file():
        candidates.append(str(preferred))

    path_candidate = shutil.which("httpx")

    if path_candidate and path_candidate not in candidates:
        candidates.append(path_candidate)

    for candidate in candidates:
        try:
            result = subprocess.run(
                [candidate, "-version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=10,
                check=False,
            )

            output = (result.stdout or "").lower()

            if result.returncode == 0 and (
                "projectdiscovery" in output
                or "httpx" in output
            ):
                return candidate

        except Exception:
            continue

    return None

def install_httpx(log_path: Path) -> str | None:
    if not yes_no(
        "ProjectDiscovery httpx is missing. Install latest httpx using Go?",
        False,
    ):
        return None

    go = shutil.which("go")

    with log_path.open("w", encoding="utf-8") as log:
        if not go:
            log.write(
                "Go is not installed. Install Go from the official Go "
                "distribution, then rerun the module.\n"
            )
            print(
                "[!] Go is not installed. Install Go, then rerun the SSL module."
            )
            return None

        completed = subprocess.run(
            [go, "install", "-v", HTTPX_INSTALL],
            text=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )

        if completed.returncode != 0:
            return None

    return find_httpx()


def load_cryptography():
    try:
        return importlib.import_module("cryptography.x509")
    except ImportError:
        pass

    if not yes_no(
        "Python dependency 'cryptography' is missing. Install it now?",
        False,
    ):
        return None

    completed = subprocess.run(
        [sys.executable, "-m", "pip", "install", "cryptography"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    if completed.returncode != 0:
        print("[!] cryptography installation failed.")
        print(completed.stdout)
        return None

    try:
        return importlib.import_module("cryptography.x509")
    except ImportError:
        return None


# --------------------------------------------------------------------------
# httpx
# --------------------------------------------------------------------------

def run_httpx(
    binary: str,
    input_path: Path,
    result_path: Path,
) -> tuple[list[dict[str, Any]], int]:
    command = [
        binary,
        "-l",
        str(input_path),
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

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    result_path.write_text(
        "$ "
        + " ".join(command)
        + "\n\nSTDOUT\n"
        + stdout
        + "\nSTDERR\n"
        + stderr
        + f"\nEXIT_CODE\n{completed.returncode}\n",
        encoding="utf-8",
    )

    records: list[dict[str, Any]] = []

    for line in stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(value, dict):
            records.append(value)

    return records, completed.returncode

def build_httpx_targets(
    context,
    candidates: list[tuple[str, int]],
) -> list[str]:
    """
    Build httpx targets from the normalized Database inventory.

    Nmap scanning keeps using the concrete address. For httpx, prefer a
    resolved hostname for normal Host/SNI behavior and fall back to the IP.
    """
    targets: list[str] = []
    seen: set[str] = set()

    for address, port in candidates:
        names = associated_names(
            context,
            address,
        )

        host = names[0] if names else address
        target = f"{bracket(host)}:{port}"

        if target not in seen:
            seen.add(target)
            targets.append(target)

    return targets


def https_endpoints(
    records: list[dict[str, Any]],
    family: int,
) -> list[tuple[str, int, str]]:
    """
    Return confirmed HTTPS address/port/url tuples.

    Prefer the IP supplied by httpx where possible. Hostnames are accepted only
    when they resolve into the active address family.
    """
    endpoints: set[tuple[str, int, str]] = set()

    for record in records:
        url = str(record.get("url") or "")

        if not url.lower().startswith("https://"):
            continue

        parsed = urlsplit(url)

        host = (
            str(record.get("host") or "").strip()
            or parsed.hostname
            or ""
        )

        port = (
            record.get("port")
            or parsed.port
            or 443
        )

        try:
            port = int(port)
        except (TypeError, ValueError):
            continue

        candidate_ips: set[str] = set()

        for key in ("a", "aaaa", "host_ip", "ip"):
            value = record.get(key)

            if isinstance(value, str):
                candidate_ips.add(value)

            elif isinstance(value, list):
                candidate_ips.update(
                    str(item)
                    for item in value
                    if item
                )

        try:
            ip = ipaddress.ip_address(host)
            candidate_ips.add(str(ip))
        except ValueError:
            pass

        valid_ips = []

        for candidate in candidate_ips:
            try:
                parsed_ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue

            if parsed_ip.version == family:
                valid_ips.append(str(parsed_ip))

        if not valid_ips and host:
            af = socket.AF_INET if family == 4 else socket.AF_INET6

            try:
                valid_ips = sorted({
                    item[4][0]
                    for item in socket.getaddrinfo(
                        host,
                        port,
                        family=af,
                        type=socket.SOCK_STREAM,
                    )
                })
            except socket.gaierror:
                valid_ips = []

        for address in valid_ips:
            endpoints.add((address, port, url))

    return sorted(endpoints)


# --------------------------------------------------------------------------
# Nmap TLS parsing / weak-cipher classification
# --------------------------------------------------------------------------

PROTOCOL_ORDER = (
    "SSLv2",
    "SSLv3",
    "TLSv1.0",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3",
)

INSECURE_PROTOCOL_NAMES = {
    "SSLv2",
    "SSLv3",
    "TLSv1.0",
    "TLSv1.1",
}

WEAK_NMAP_GRADES = {"C", "D", "F"}

SHA1_CIPHER_RE = re.compile(
    r"(?<![0-9A-Za-z])SHA1?(?![0-9A-Za-z])",
    re.IGNORECASE,
)

WEAK_DH_KEX_RE = re.compile(
    r"^dh\s+(\d+)$",
    re.IGNORECASE,
)

EXPLICIT_KEYSIZE_RE = re.compile(
    r"(?:_|-)(\d{2,3})(?:_|-|$)"
)


def parse_ssl_enum_output(
    output: str,
) -> dict[str, dict[str, list]]:
    """
    Parse nmap ssl-enum-ciphers text.

    Supports both IANA-style names:
        TLS_RSA_WITH_3DES_EDE_CBC_SHA

    and OpenSSL-style aliases where they appear in scanner output:
        DES-CBC3-SHA

    Returns:
        {
          "TLSv1.2": {
             "ciphers": [(name, kex_info, grade, raw_line), ...],
             "warnings": [...]
          }
        }
    """
    protocols: dict[str, dict[str, list]] = {}
    current: str | None = None
    section: str | None = None

    cipher_with_grade = re.compile(
        r"^(\S+)\s+\((.*?)\)\s*-\s*([A-F])$",
        re.IGNORECASE,
    )

    cipher_no_grade = re.compile(
        r"^([A-Z0-9][A-Z0-9_.-]*(?:WITH[A-Z0-9_.-]+|SHA|MD5|GCM|CBC|POLY1305)[A-Z0-9_.-]*)$",
        re.IGNORECASE,
    )

    for raw_line in output.splitlines():
        line = (
            raw_line.strip()
            .lstrip("|")
            .lstrip("_")
            .strip()
        )

        if not line:
            continue

        protocol_match = re.match(
            r"^(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3):$",
            line,
            re.IGNORECASE,
        )

        if protocol_match:
            # Preserve canonical protocol spelling.
            observed = protocol_match.group(1)
            current = next(
                (
                    known
                    for known in PROTOCOL_ORDER
                    if known.lower() == observed.lower()
                ),
                observed,
            )
            protocols.setdefault(
                current,
                {"ciphers": [], "warnings": []},
            )
            section = None
            continue

        if current is None:
            continue

        lowered = line.lower()

        if lowered == "ciphers:":
            section = "ciphers"
            continue

        if lowered == "warnings:":
            section = "warnings"
            continue

        if (
            lowered.startswith("compressors:")
            or lowered.startswith("cipher preference:")
            or lowered.startswith("least strength:")
        ):
            section = None
            continue

        if section == "warnings":
            protocols[current]["warnings"].append(line)
            continue

        if section != "ciphers":
            continue

        match = cipher_with_grade.match(line)

        if match:
            protocols[current]["ciphers"].append(
                (
                    match.group(1),
                    match.group(2).strip(),
                    match.group(3).upper(),
                    raw_line.strip(),
                )
            )
            continue

        # Fallback for scanner/Nmap variants that omit the "(kex) - grade"
        # suffix but still print a cipher-suite token.
        match = cipher_no_grade.match(line)

        if match:
            protocols[current]["ciphers"].append(
                (
                    match.group(1),
                    "",
                    "",
                    raw_line.strip(),
                )
            )

    return protocols


def classify_weak_cipher(
    protocol: str,
    name: str,
    kex_info: str,
    grade: str,
) -> dict[str, str]:
    """Return every weakness category applicable to one offered cipher."""
    upper = name.upper()
    hits: dict[str, str] = {}

    # RC4
    if "RC4" in upper or "ARCFOUR" in upper:
        hits["RC4"] = "RC4"

    # 3DES aliases, including the OpenSSL name reported by Nessus.
    is_3des = any(
        token in upper
        for token in (
            "3DES",
            "DES_EDE",
            "DES-EDE",
            "DES-CBC3",
            "DES_CBC3",
            "CBC3",
        )
    )

    if is_3des:
        hits["3DES"] = "3DES"

    # Single DES, excluding already-classified triple DES.
    elif re.search(
        r"(^|[_-])DES([_-]|$)",
        upper,
    ):
        hits["DES"] = "DES"

    # SHA-1 MAC / suite naming. Covers ..._SHA and ...-SHA, but not SHA256+.
    if (
        SHA1_CIPHER_RE.search(name)
        or (
            re.search(r"(?:_|-)SHA$", upper)
            and not re.search(r"SHA(?:256|384|512)$", upper)
        )
    ):
        hits["SHA1"] = "SHA1"

    # Export suites.
    if (
        "EXPORT" in upper
        or "_EXP_" in upper
        or "-EXP-" in upper
        or upper.startswith("EXP-")
    ):
        if (
            "DHE" in upper
            or "DH_" in upper
            or "DH-" in upper
            or kex_info.lower().startswith("dh ")
        ):
            hits["EXPORT_LOGJAM"] = "export-grade DH"
        else:
            hits["EXPORT_FREAK"] = "export-grade RSA/other"

    # CBC (including OpenSSL's DES-CBC3-SHA).
    if (
        "_CBC_" in upper
        or "-CBC-" in upper
        or "-CBC3-" in upper
        or "_CBC3_" in upper
    ):
        hits["CBC"] = "CBC mode"

    # NULL / anonymous / MD5 legacy markers.
    if "NULL" in upper:
        hits["NULL"] = "NULL encryption"

    if (
        "ANON" in upper
        or "ADH" in upper
        or "AECDH" in upper
    ):
        hits["ANONYMOUS"] = "anonymous key exchange"

    if "MD5" in upper:
        hits["MD5"] = "MD5"

    # Explicit <128-bit key-size markers not already represented by a more
    # specific DES/3DES/RC4/export category.
    if not any(
        key in hits
        for key in (
            "RC4",
            "DES",
            "3DES",
            "EXPORT_FREAK",
            "EXPORT_LOGJAM",
        )
    ):
        sizes = [
            int(value)
            for value in EXPLICIT_KEYSIZE_RE.findall(upper)
        ]

        if any(size < 128 for size in sizes):
            hits["LESS_THAN_128_BITS"] = (
                f"{min(sizes)}-bit cipher"
            )

        if any(
            token in upper
            for token in ("RC2", "IDEA", "_40_", "-40-", "_56_", "-56-")
        ):
            hits["LESS_THAN_128_BITS"] = "short-key cipher"

    # Weak finite-field DH as reported by nmap in kex information.
    match = WEAK_DH_KEX_RE.match(kex_info.strip())

    if match and int(match.group(1)) <= 1024:
        hits["WEAK_DH"] = (
            f"{match.group(1)}-bit finite-field DH"
        )

    # Non-ephemeral/static key exchange. Do not apply this to TLS 1.3.
    if protocol != "TLSv1.3":
        kex_lower = kex_info.lower().strip()

        ephemeral = (
            "ecdhe" in upper
            or "dhe" in upper
            or kex_lower.startswith("ecdh ")
            and "ephemeral" in kex_lower
        )

        static_by_name = bool(
            re.search(
                r"_(RSA|DH|ECDH)_WITH_",
                upper,
            )
        )

        static_by_kex = bool(
            re.match(
                r"^(rsa|dh|ecdh)(?:\s+\d+)?$",
                kex_lower,
            )
        )

        if not ephemeral and (
            static_by_name
            or static_by_kex
        ):
            hits["NON_EPHEMERAL_KEY_EXCHANGE"] = (
                "no forward secrecy"
            )

    # Nmap's own cipher-strength grade is a fallback detector.
    if grade.upper() in WEAK_NMAP_GRADES:
        hits["NMAP_WEAK_GRADE"] = (
            f"Nmap grade {grade.upper()}"
        )

    # Any suite offered under an obsolete protocol is retained in the weak
    # inventory even if its primitive would otherwise be acceptable.
    if protocol in INSECURE_PROTOCOL_NAMES:
        hits["DEPRECATED_PROTOCOL"] = protocol

    return hits



def parse_nmap_tls(
    xml_path: Path,
) -> tuple[str, set[str], dict[str, set[str]]]:
    root = ET.parse(xml_path).getroot()

    outputs: list[str] = []

    for script in root.findall(".//script"):
        if script.get("id") in {
            "ssl-enum-ciphers",
            "ssl-dh-params",
        }:
            outputs.append(
                script.get("output", "")
            )

    output = "\n\n".join(outputs)

    protocols = parse_ssl_enum_output(
        output
    )

    insecure_protocols = {
        protocol.upper()
        for protocol in protocols
        if protocol in INSECURE_PROTOCOL_NAMES
    }

    weak: dict[str, set[str]] = {}

    def add(
        category: str,
        value: str,
    ) -> None:
        weak.setdefault(
            category,
            set(),
        ).add(value)

    for protocol, data in protocols.items():
        for (
            cipher_name,
            kex_info,
            grade,
            _raw_line,
        ) in data["ciphers"]:
            hits = classify_weak_cipher(
                protocol,
                cipher_name,
                kex_info,
                grade,
            )

            for category in hits:
                add(
                    category,
                    cipher_name,
                )

    # Keep ssl-dh-params as a second independent weak-DH source.
    for line in output.splitlines():
        if not re.search(
            r"(?i)(diffie-hellman|dh parameters?|modulus|group strength)",
            line,
        ):
            continue

        match = re.search(
            r"(?<!\d)(512|768|1024)\s*(?:bits?|bit)",
            line,
            re.I,
        )

        if match:
            add(
                "WEAK_DH",
                line.strip(),
            )

    return output, insecure_protocols, weak


# --------------------------------------------------------------------------
# Native certificate validation
# --------------------------------------------------------------------------

def fetch_cert_der(
    address: str,
    port: int,
    timeout: int,
    sni: str | None,
) -> bytes | None:
    context = ssl._create_unverified_context()

    try:
        with socket.create_connection(
            (address, port),
            timeout=timeout,
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=sni,
            ) as tls_socket:
                return tls_socket.getpeercert(
                    binary_form=True
                )

    except (OSError, ssl.SSLError, TimeoutError):
        return None


def check_trust(
    address: str,
    port: int,
    timeout: int,
    sni: str | None,
) -> tuple[bool | None, str | None]:
    context = ssl.create_default_context()

    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection(
            (address, port),
            timeout=timeout,
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=sni,
            ):
                return True, None

    except ssl.SSLCertVerificationError as error:
        return False, str(error)

    except (OSError, ssl.SSLError, TimeoutError) as error:
        return None, str(error)


def hostname_matches(
    pattern: str,
    hostname: str,
) -> bool:
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")

    if pattern.startswith("*."):
        suffix = pattern[2:]

        host_labels = hostname.split(".")
        suffix_labels = suffix.split(".")

        return (
            len(host_labels) == len(suffix_labels) + 1
            and host_labels[1:] == suffix_labels
        )

    return pattern == hostname


def resolve_all(
    hostname: str,
    family: int,
) -> set[str]:
    af = socket.AF_INET if family == 4 else socket.AF_INET6

    try:
        return {
            item[4][0]
            for item in socket.getaddrinfo(
                hostname.rstrip("."),
                None,
                family=af,
                type=socket.SOCK_STREAM,
            )
        }
    except socket.gaierror:
        return set()


def wildcard_certificate_names(cert, x509_module) -> list[str]:
    names: set[str] = set()
    try:
        extension = cert.extensions.get_extension_for_class(
            x509_module.SubjectAlternativeName
        )
        for value in extension.value.get_values_for_type(x509_module.DNSName):
            clean = value.strip().rstrip(".").lower()
            if clean.startswith("*."):
                names.add(clean)
    except x509_module.ExtensionNotFound:
        pass

    for attribute in cert.subject:
        if getattr(attribute.oid, "_name", "") == "commonName":
            clean = str(attribute.value).strip().rstrip(".").lower()
            if clean.startswith("*."):
                names.add(clean)

    return sorted(names)


def certificate_summary(
    cert,
    sans: list[str],
    sni: str | None,
) -> str:
    sig_algo = (
        cert.signature_algorithm_oid._name
        if cert.signature_algorithm_oid
        else "unknown"
    )

    not_before = (
        cert.not_valid_before_utc
        if hasattr(cert, "not_valid_before_utc")
        else cert.not_valid_before
    )

    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after
    )

    return (
        f"Subject: {cert.subject.rfc4514_string()}\n"
        f"Issuer: {cert.issuer.rfc4514_string()}\n"
        f"Not valid before: {not_before}\n"
        f"Not valid after: {not_after}\n"
        f"Signature algorithm: {sig_algo}\n"
        f"SANs: {', '.join(sans) if sans else '(none)'}\n"
        f"SNI/hostname used: {sni or '(none)'}\n"
    )


def check_certificate(
    context,
    address: str,
    port: int,
    timeout: int,
    x509_module,
) -> tuple[list[tuple[str, str]], str]:
    """
    Return validated certificate findings and representative evidence.

    Connection/parsing failures are returned as no-finding results because an
    unavailable certificate is not proof of a certificate vulnerability.
    """
    names = associated_names(context, address)
    sni = names[0] if names else None

    der = fetch_cert_der(
        address,
        port,
        timeout,
        sni,
    )

    if der is None:
        return [], ""

    try:
        cert = x509_module.load_der_x509_certificate(der)
    except Exception:
        return [], ""

    findings: list[tuple[str, str]] = []

    now = datetime.now(timezone.utc)

    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after
    )

    if not_after.tzinfo is None:
        not_after = not_after.replace(
            tzinfo=timezone.utc
        )

    if now > not_after:
        findings.append(
            (
                CERT_LABEL_EXPIRED,
                "Certificate expired at the time of testing "
                f"(expired {not_after:%Y-%m-%d %H:%M:%S %Z}).",
            )
        )

    signature_name = (
        cert.signature_algorithm_oid._name
        if cert.signature_algorithm_oid
        else ""
    )

    signature_hash_name = ""

    try:
        signature_hash_name = cert.signature_hash_algorithm.name
    except Exception:
        pass

    combined_signature = (
        f"{signature_name} {signature_hash_name}"
    ).lower()

    if re.search(
        r"(^|[^a-z0-9])(md5|sha1)([^a-z0-9]|$)",
        combined_signature,
    ):
        findings.append(
            (
                CERT_LABEL_DEPRECATED_SIG,
                "Certificate is signed using a deprecated hashing "
                f"algorithm ({signature_name or signature_hash_name}).",
            )
        )

    trusted, trust_error = check_trust(
        address,
        port,
        timeout,
        sni,
    )

    if trusted is False and trust_error:
        low = trust_error.lower()

        # Expiry is already its own finding. Avoid double-reporting it as CA trust.
        if "expired" not in low and "not yet valid" not in low:
            if (
                "self signed" in low
                or "self-signed" in low
                or "unable to get local issuer" in low
                or "unable to get issuer" in low
                or "unable to verify" in low
                or "unknown ca" in low
                or "certificate verify failed" in low
            ):
                findings.append(
                    (
                        CERT_LABEL_UNTRUSTED_CA,
                        "Certificate chain could not be validated against "
                        f"the local trusted CA store ({trust_error}).",
                    )
                )

    sans: list[str] = []

    try:
        extension = cert.extensions.get_extension_for_class(
            x509_module.SubjectAlternativeName
        )

        sans = [
            value.rstrip(".").lower()
            for value in extension.value.get_values_for_type(
                x509_module.DNSName
            )
        ]

    except x509_module.ExtensionNotFound:
        sans = []

    if sans:
        resolvable_sans: dict[str, set[str]] = {}

        for san in sans:
            # Wildcard names cannot be directly resolved.
            if "*" in san:
                continue

            addresses = resolve_all(
                san,
                context.family,
            )

            if addresses:
                resolvable_sans[san] = addresses

        # Finding 1:
        # Certificate contains concrete SAN names that resolve, but none resolve
        # to the tested address.
        if (
            resolvable_sans
            and not any(
                address in addresses
                for addresses in resolvable_sans.values()
            )
        ):
            details = "; ".join(
                f"{name} -> {', '.join(sorted(addresses))}"
                for name, addresses in sorted(
                    resolvable_sans.items()
                )
            )

            findings.append(
                (
                    CERT_LABEL_SAN_MISMATCH,
                    "Certificate SAN hostname(s) resolve to addresses other "
                    f"than the tested target {address}: {details}.",
                )
            )

        # Finding 2:
        # Bayabas knows one or more valid names for the tested IP but none are
        # covered by certificate SANs.
        if names and not any(
            hostname_matches(
                san,
                known_name,
            )
            for known_name in names
            for san in sans
        ):
            findings.append(
                (
                    CERT_LABEL_MISSING_COVERAGE,
                    "Certificate SANs do not cover any hostname known to "
                    f"resolve to {address} ({', '.join(names)}).",
                )
            )

    elif names:
        # Modern certificate hostname validation requires SAN coverage.
        findings.append(
            (
                CERT_LABEL_MISSING_COVERAGE,
                "Certificate contains no DNS Subject Alternative Name "
                f"covering a hostname known to resolve to {address} "
                f"({', '.join(names)}).",
            )
        )

    wildcard_names = wildcard_certificate_names(cert, x509_module)
    if wildcard_names:
        findings.append(
            (
                CERT_LABEL_WILDCARD,
                "Wildcard certificate name(s): " + ", ".join(wildcard_names),
            )
        )

    if not findings:
        return [], ""

    evidence = (
        f"Endpoint: {address}, {port}\n"
        f"Address family: IPv{context.family}\n"
        f"Associated hostnames: {', '.join(names) if names else '(none)'}\n"
        f"SNI used: {sni or '(none)'}\n\n"
        + certificate_summary(
            cert,
            sans,
            sni,
        )
        + "\nFindings:\n"
        + "\n".join(
            f"- {label}: {detail}"
            for label, detail in findings
        )
    )

    return findings, evidence


# --------------------------------------------------------------------------
# Grouped TLS scanning
# --------------------------------------------------------------------------

def group_open_tcp_targets(
    candidates: list[tuple[str, int]],
) -> dict[str, list[int]]:
    grouped: dict[str, set[int]] = defaultdict(set)

    for address, port in candidates:
        grouped[address].add(int(port))

    return {
        address: sorted(ports)
        for address, ports in grouped.items()
    }


def safe_host_token(address: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", address)


def parse_grouped_nmap_tls(
    xml_path: Path,
) -> dict[int, tuple[str, set[str], dict[str, set[str]]]]:
    """Parse one host-level Nmap XML scan into per-port TLS results."""
    root = ET.parse(xml_path).getroot()
    results: dict[int, tuple[str, set[str], dict[str, set[str]]]] = {}

    for port_node in root.findall(".//port"):
        try:
            port = int(port_node.get("portid", "0"))
        except ValueError:
            continue

        outputs: list[str] = []

        for script in port_node.findall("script"):
            if script.get("id") in {
                "ssl-enum-ciphers",
                "ssl-dh-params",
            }:
                outputs.append(script.get("output", ""))

        if not outputs:
            continue

        output = "\n\n".join(outputs)
        protocols = parse_ssl_enum_output(output)

        insecure_protocols = {
            protocol.upper()
            for protocol in protocols
            if protocol in INSECURE_PROTOCOL_NAMES
        }

        weak: dict[str, set[str]] = {}

        def add(category: str, value: str) -> None:
            weak.setdefault(category, set()).add(value)

        for protocol, data in protocols.items():
            for cipher_name, kex_info, grade, _raw_line in data["ciphers"]:
                hits = classify_weak_cipher(
                    protocol,
                    cipher_name,
                    kex_info,
                    grade,
                )

                for category in hits:
                    add(category, cipher_name)

        for line in output.splitlines():
            if not re.search(
                r"(?i)(diffie-hellman|dh parameters?|modulus|group strength)",
                line,
            ):
                continue

            match = re.search(
                r"(?<!\d)(512|768|1024)\s*(?:bits?|bit)",
                line,
                re.I,
            )

            if match:
                add("WEAK_DH", line.strip())

        results[port] = (
            output,
            insecure_protocols,
            weak,
        )

    return results


def run_grouped_tls_scan(
    context,
    address: str,
    ports: list[int],
    temp: Path,
) -> tuple[str, list[str], dict[int, tuple[str, set[str], dict[str, set[str]]]]]:
    """Run one Nmap process for all open TCP ports on a host."""
    xml = temp / f"tls_{safe_host_token(address)}.xml"
    names = associated_names(context, address)
    sni = names[0] if names else None

    command = [
        context.nmap_path,
        *(["-6"] if context.family == 6 else []),
        "-Pn",
        "-sV",
        "--open",
        "-p",
        ",".join(map(str, ports)),
        "--script",
        "ssl-enum-ciphers,ssl-dh-params",
    ]

    if sni:
        command += [
            "--script-args",
            f"tls.servername={sni}",
        ]

    command += [
        "-oX",
        str(xml),
        address,
    ]

    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    parsed: dict[int, tuple[str, set[str], dict[str, set[str]]]] = {}

    if xml.exists():
        try:
            parsed = parse_grouped_nmap_tls(xml)
        except (ET.ParseError, OSError):
            parsed = {}

    return completed.stdout, command, parsed


# --------------------------------------------------------------------------
# Module execution
# --------------------------------------------------------------------------


def persist_httpx_inventory(
    context,
    input_path: Path,
    result_path: Path,
    records: list[dict[str, Any]],
) -> Path | None:
    """Persist reusable httpx artifacts and a deduplicated URL list."""
    urls = sorted({
        str(record.get("url") or "").strip()
        for record in records
        if str(record.get("url") or "").strip()
    })

    if not records and not urls:
        return None

    httpx_dir = context.scan_root / "httpx"
    httpx_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(input_path, httpx_dir / "targets.txt")
    shutil.copy2(result_path, httpx_dir / "httpx_result.txt")

    if urls:
        (httpx_dir / "urls.txt").write_text(
            "\n".join(urls) + "\n",
            encoding="utf-8",
        )

    return httpx_dir


def run(context) -> int:
    ssl_family_root = (
        context.findings_dir
        / "SSL"
        / context.family_label
    )

    remove_stale(ssl_family_root)

    candidates = open_tcp_targets(context)

    if not candidates:
        print(f"[*] cipher/{context.family_label}: no open TCP ports in inventory.")
        return 0

    grouped = group_open_tcp_targets(candidates)

    print(
        f"[*] cipher/{context.family_label}: "
        f"{len(candidates)} open TCP endpoint(s) across {len(grouped)} host(s)."
    )

    x509_module = load_cryptography()
    certificate_checks_enabled = x509_module is not None

    with tempfile.TemporaryDirectory(
        prefix=f"bayabas_tls_{context.family}_"
    ) as temporary:
        temp = Path(temporary)

        # --------------------------------------------------------------
        # httpx is retained as enrichment/evidence only. It is NOT a gate
        # for TLS scanning because TLS may exist on non-HTTP protocols.
        # --------------------------------------------------------------
        httpx_input = temp / "httpx_input.txt"
        httpx_result = temp / "httpx_result.txt"
        httpx_install_log = temp / "httpx_install.log"

        httpx_targets = build_httpx_targets(
            context,
            candidates,
        )

        httpx_input.write_text(
            "\n".join(httpx_targets)
            + ("\n" if httpx_targets else ""),
            encoding="utf-8",
        )

        print(
            f"[*] cipher/{context.family_label}: "
            f"prepared {len(httpx_targets)} DB-derived TCP endpoint(s) for httpx."
        )

        binary = find_httpx()

        if not binary:
            binary = install_httpx(httpx_install_log)

        if binary:
            print(
                f"[*] cipher/{context.family_label}: using httpx: {binary}"
            )

            try:
                records, httpx_rc = run_httpx(
                    binary,
                    httpx_input,
                    httpx_result,
                )

                web_endpoints = https_endpoints(
                    records,
                    context.family,
                )

                httpx_dir = persist_httpx_inventory(
                    context,
                    httpx_input,
                    httpx_result,
                    records,
                )

                print(
                    f"[*] cipher/{context.family_label}: "
                    f"httpx exit={httpx_rc}, JSON records={len(records)}, "
                    f"HTTPS endpoint(s)={len(web_endpoints)} "
                    f"from {len(httpx_targets)} DB-derived TCP endpoint(s)."
                )

                if httpx_dir is not None:
                    urls_path = httpx_dir / "urls.txt"

                    if urls_path.exists():
                        discovered_urls = [
                            line.strip()
                            for line in urls_path.read_text(
                                encoding="utf-8",
                                errors="replace",
                            ).splitlines()
                            if line.strip()
                        ]

                        print(
                            f"[*] cipher/{context.family_label}: "
                            f"saved {len(discovered_urls)} discovered URL(s) to {urls_path}."
                        )

                        for url in discovered_urls:
                            print(
                                f"[+] httpx/{context.family_label}: {url}"
                            )

                if not records:
                    print(
                        f"[!] cipher/{context.family_label}: httpx returned no JSON records. "
                        f"Review the retained httpx result if findings are produced."
                    )

            except Exception as exc:
                httpx_result.write_text(
                    f"httpx execution failed: {exc}\n",
                    encoding="utf-8",
                )

                print(
                    f"[!] cipher/{context.family_label}: "
                    f"httpx execution failed: {exc}; "
                    "continuing with all-port Nmap TLS detection."
                )
        else:
            print(
                f"[*] cipher/{context.family_label}: httpx unavailable; "
                "continuing with all-port Nmap TLS detection."
            )

        weak_hosts: set[tuple[str, int]] = set()
        weak_values: dict[str, set[str]] = {}
        weak_evidence = ""

        legacy_hosts: list[tuple[str, int, set[str]]] = []
        legacy_evidence = ""

        tls_ports_detected: set[tuple[str, int]] = set()
        parser_warnings: list[str] = []

        # --------------------------------------------------------------
        # One Nmap process per host, scanning all its open TCP ports.
        # Limited host-level concurrency substantially reduces runtime.
        # --------------------------------------------------------------
        workers = min(4, max(1, len(grouped)))
        print(
            f"[*] cipher/{context.family_label}: running {len(grouped)} "
            f"host-level TLS scan(s), concurrency={workers}."
        )

        grouped_results: dict[
            str,
            tuple[str, list[str], dict[int, tuple[str, set[str], dict[str, set[str]]]]],
        ] = {}

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(
                    run_grouped_tls_scan,
                    context,
                    address,
                    ports,
                    temp,
                ): (address, ports)
                for address, ports in grouped.items()
            }

            for future in as_completed(future_map):
                address, ports = future_map[future]

                try:
                    stdout, command, parsed = future.result()
                except Exception as exc:
                    parser_warnings.append(
                        f"{address}: grouped TLS scan failed: {exc}"
                    )
                    continue

                grouped_results[address] = (
                    stdout,
                    command,
                    parsed,
                )

                print(
                    f"    {address}: {len(ports)} port(s) checked, "
                    f"TLS script data on {len(parsed)} port(s)."
                )

        # --------------------------------------------------------------
        # Consume parsed TLS results.
        # --------------------------------------------------------------
        for address, (stdout, command, parsed) in grouped_results.items():
            for port, (raw, protocols, weak) in parsed.items():
                tls_ports_detected.add((address, port))

                if weak:
                    weak_hosts.add((address, port))

                    for category, values in weak.items():
                        weak_values.setdefault(category, set()).update(values)

                    if not weak_evidence:
                        weak_evidence = (
                            "$ "
                            + " ".join(command)
                            + "\n\n"
                            + stdout
                            + "\n"
                            + raw
                        )

                insecure = protocols & set(LEGACY_PROTOCOLS)

                if insecure:
                    legacy_hosts.append((address, port, insecure))

                    if not legacy_evidence:
                        legacy_evidence = (
                            "$ "
                            + " ".join(command)
                            + "\n\n"
                            + stdout
                            + "\n"
                            + raw
                        )

        print(
            f"[*] cipher/{context.family_label}: TLS detected on "
            f"{len(tls_ports_detected)} endpoint(s); "
            f"weak cipher/configuration on {len(weak_hosts)} endpoint(s)."
        )

        # --------------------------------------------------------------
        # Certificate checks: only attempt where Nmap saw TLS script data.
        # This remains per IP:port:SNI because certificate presentation can
        # vary by SNI even on the same socket.
        # --------------------------------------------------------------
        certificate_hosts: dict[tuple[str, int], set[str]] = {}
        certificate_evidence: dict[str, str] = {}
        wildcard_hosts: set[tuple[str, int]] = set()
        wildcard_names_found: set[str] = set()
        wildcard_evidence: dict[str, str] = {}

        if certificate_checks_enabled:
            for address, port in sorted(tls_ports_detected):
                try:
                    cert_findings, cert_evidence = check_certificate(
                        context,
                        address,
                        port,
                        timeout=15,
                        x509_module=x509_module,
                    )
                except Exception:
                    cert_findings = []
                    cert_evidence = ""

                if cert_findings:
                    endpoint = (address, port)
                    generic_findings = [
                        (label, detail)
                        for label, detail in cert_findings
                        if label != CERT_LABEL_WILDCARD
                    ]

                    if generic_findings:
                        certificate_hosts.setdefault(endpoint, set()).update(
                            label for label, _detail in generic_findings
                        )
                        for label, _detail in generic_findings:
                            if label not in certificate_evidence and cert_evidence:
                                certificate_evidence[label] = cert_evidence

                    for label, detail in cert_findings:
                        if label != CERT_LABEL_WILDCARD:
                            continue
                        wildcard_hosts.add(endpoint)
                        _p, _s, values = detail.partition(":")
                        for name in [x.strip() for x in values.split(",") if x.strip()]:
                            wildcard_names_found.add(name)
                            if cert_evidence:
                                wildcard_evidence.setdefault(name, cert_evidence)

        finding_count = 0

        # --------------------------------------------------------------
        # Weak TLS/SSL cipher finding
        # --------------------------------------------------------------
        if weak_hosts and weak_values and weak_evidence:
            out = ssl_family_root / "Weak TLS-SSL Cipher"
            out.mkdir(parents=True, exist_ok=True)

            (out / "affected_hosts.txt").write_text(
                "".join(
                    f"{host}, {port}\n"
                    for host, port in sorted(weak_hosts)
                ),
                encoding="utf-8",
            )

            category_order = [
                "RC4",
                "DES",
                "3DES",
                "SHA1",
                "EXPORT_FREAK",
                "EXPORT_LOGJAM",
                "LESS_THAN_128_BITS",
                "CBC",
                "WEAK_DH",
                "NON_EPHEMERAL_KEY_EXCHANGE",
                "NULL",
                "ANONYMOUS",
                "MD5",
                "NMAP_WEAK_GRADE",
                "DEPRECATED_PROTOCOL",
            ]

            lines: list[str] = []
            ordered_categories = [
                category
                for category in category_order
                if category in weak_values
            ]
            ordered_categories.extend(
                sorted(set(weak_values) - set(ordered_categories))
            )

            for category in ordered_categories:
                lines.append(f"{category}:")
                lines.extend(
                    f"  - {value}"
                    for value in sorted(weak_values[category])
                )

            (out / "weak_ciphers.txt").write_text(
                "\n".join(lines) + "\n",
                encoding="utf-8",
            )

            (out / "raw_output.txt").write_text(
                weak_evidence + "\n",
                encoding="utf-8",
            )

            finding_count += len(weak_hosts)

        # --------------------------------------------------------------
        # Insecure TLS versions finding
        # --------------------------------------------------------------
        if legacy_hosts and legacy_evidence:
            out = ssl_family_root / "Insecure TLS Versions"
            out.mkdir(parents=True, exist_ok=True)

            def protocol_label(values: set[str]) -> str:
                order = ["SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1"]
                pretty = {
                    "SSLV2": "SSLv2",
                    "SSLV3": "SSLv3",
                    "TLSV1.0": "TLSv1.0",
                    "TLSV1.1": "TLSv1.1",
                }
                return " and ".join(
                    pretty[value]
                    for value in order
                    if value in values
                )

            (out / "affected_hosts.txt").write_text(
                "".join(
                    f"{host}, {port} [{protocol_label(protocols)}]\n"
                    for host, port, protocols in legacy_hosts
                ),
                encoding="utf-8",
            )

            (out / "raw_output.txt").write_text(
                legacy_evidence + "\n",
                encoding="utf-8",
            )

            finding_count += len(legacy_hosts)

        # --------------------------------------------------------------
        # Insecure SSL certificate finding
        # --------------------------------------------------------------
        if certificate_hosts and certificate_evidence:
            out = ssl_family_root / "Insecure SSL Certificate"
            out.mkdir(parents=True, exist_ok=True)

            affected_lines: list[str] = []

            for (host, port), labels in sorted(certificate_hosts.items()):
                affected_lines.append(
                    f"{host}, {port} [{'; '.join(sorted(labels))}]"
                )

            (out / "affected_hosts.txt").write_text(
                "\n".join(affected_lines) + "\n",
                encoding="utf-8",
            )

            for label, evidence in certificate_evidence.items():
                filename = CERT_EVIDENCE_FILES[label]
                (out / filename).write_text(
                    evidence + "\n",
                    encoding="utf-8",
                )

            finding_count += len(certificate_hosts)

        # --------------------------------------------------------------
        # Wildcard SSL certificate finding
        # --------------------------------------------------------------
        if wildcard_hosts and wildcard_names_found:
            out = ssl_family_root / "Wildcard SSL Certificate"
            out.mkdir(parents=True, exist_ok=True)

            (out / "affected_hosts.txt").write_text(
                "".join(
                    f"{host}, {port}\n"
                    for host, port in sorted(wildcard_hosts)
                ),
                encoding="utf-8",
            )

            (out / "wildcard_certificates.txt").write_text(
                "\n".join(sorted(wildcard_names_found)) + "\n",
                encoding="utf-8",
            )

            blocks = []
            for name in sorted(wildcard_names_found):
                blocks.append(
                    "=" * 72
                    + "\nWildcard: "
                    + name
                    + "\n"
                    + "=" * 72
                    + "\n"
                    + wildcard_evidence.get(name, "").strip()
                )

            (out / "evidence.txt").write_text(
                "\n\n".join(blocks).rstrip() + "\n",
                encoding="utf-8",
            )

            finding_count += len(wildcard_hosts)

        # --------------------------------------------------------------
        # Diagnostics are retained only if findings exist, consistent with
        # Bayabas' no-empty/no-false-positive output convention.
        # --------------------------------------------------------------
        if finding_count:
            ssl_family_root.mkdir(parents=True, exist_ok=True)

            if httpx_input.exists():
                shutil.copy2(
                    httpx_input,
                    ssl_family_root / "httpx_input.txt",
                )

            if httpx_result.exists():
                shutil.copy2(
                    httpx_result,
                    ssl_family_root / "httpx_result.txt",
                )

            if httpx_install_log.exists() and httpx_install_log.stat().st_size:
                shutil.copy2(
                    httpx_install_log,
                    ssl_family_root / "httpx_install.log",
                )

            if parser_warnings:
                (ssl_family_root / "scan_warnings.txt").write_text(
                    "\n".join(parser_warnings) + "\n",
                    encoding="utf-8",
                )

        elif ssl_family_root.exists():
            shutil.rmtree(ssl_family_root)

        return finding_count

