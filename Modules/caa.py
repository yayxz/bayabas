"""Bayabas CAA (Certification Authority Authorization) audit module.

Resolves the *effective* DNS CAA record for every verified FQDN already
recorded in the current family's inventory (Database/<family>/resolutions.txt)
by walking up the DNS hierarchy per RFC 8659, following CNAMEs where
present, rather than flagging every subdomain that lacks its own CAA
record as a finding.

CAA is a DNS-level property, evaluated per name -- it does not depend on
open ports, so targets come from the resolutions table rather than the
ports table used by cipher.py/ssh.py.

Use only against systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


# Non-exhaustive list of common multi-label public suffixes. Not a full
# Public Suffix List (avoiding a hard dependency), but enough to stop the
# walk-up from wasting a query on a shared registrar-controlled suffix
# such as "co.uk", which is never part of the client's own zone.
KNOWN_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn",
    "com.mx", "com.sg", "com.hk", "com.tw",
    "co.in", "net.in", "org.in", "gov.in",
}


def yes_no(message: str, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        return default
    marker = "Y/n" if default else "y/N"
    answer = input(f"{message} [{marker}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def load_dnspython():
    """Lazily import dnspython, offering to pip-install it if missing.
    Mirrors cipher.py's load_cryptography() so a missing optional
    dependency degrades this module gracefully instead of breaking
    module discovery for the whole framework."""
    try:
        return importlib.import_module("dns.resolver")
    except ImportError:
        pass

    if not yes_no("Python dependency 'dnspython' is missing. Install it now?", False):
        return None

    completed = subprocess.run(
        [sys.executable, "-m", "pip", "install", "dnspython", "--break-system-packages"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if completed.returncode != 0:
        print("[!] dnspython installation failed.")
        print(completed.stdout)
        return None

    try:
        return importlib.import_module("dns.resolver")
    except ImportError:
        return None


def remove_stale(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def target_fqdns(context) -> list[str]:
    """Distinct verified FQDNs from the resolutions table for this scan.
    Bare computer names and IPs are excluded -- CAA walk-up needs an
    actual DNS name."""
    with context.connect() as db:
        rows = db.execute(
            """
            SELECT DISTINCT hostname
            FROM resolutions
            WHERE scan_id = ?
              AND hostname IS NOT NULL
              AND hostname != ''
            ORDER BY hostname
            """,
            (context.scan_id,),
        ).fetchall()

    names: list[str] = []
    seen: set[str] = set()
    for row in rows:
        name = (row["hostname"] or "").strip().rstrip(".").lower()
        if not name or "." not in name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def is_public_suffix(candidate: str) -> bool:
    return candidate in KNOWN_MULTI_LABEL_SUFFIXES


def candidate_chain(hostname: str) -> list[str]:
    """Ordered names to query, walking from the full name up toward (but
    excluding) the registry-controlled suffix. A single-label hostname is
    still queried once rather than silently skipped."""
    labels = hostname.split(".")
    if len(labels) == 1:
        return [hostname]

    chain = []
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if is_public_suffix(candidate):
            break
        chain.append(candidate)
    return chain


def query_with_retry(resolver, name: str, rdtype: str, retries: int):
    import dns.resolver
    import dns.exception

    last_error = None
    for _ in range(retries + 1):
        try:
            return resolver.resolve(name, rdtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            raise
        except dns.exception.DNSException as exc:
            last_error = exc
            continue
    raise RuntimeError(f"{type(last_error).__name__}: {last_error}")


def resolve_cname(resolver, hostname: str, retries: int, max_hops: int = 8) -> str:
    import dns.resolver

    current = hostname
    seen: set[str] = set()
    for _ in range(max_hops):
        if current in seen:
            break
        seen.add(current)
        try:
            answer = query_with_retry(resolver, current, "CNAME", retries)
            current = str(answer[0].target).rstrip(".").lower()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            break
    return current


def walk_caa(resolver, hostname: str, retries: int) -> tuple[str | None, list[str] | None, str | None]:
    """Returns (level, records, None) on a definitive result (including a
    definitive "none found"), or (None, None, errorMessage) if the chain
    could not be fully evaluated. The error case must never be reported
    as a finding."""
    import dns.resolver

    errors = []
    for candidate in candidate_chain(hostname):
        try:
            answer = query_with_retry(resolver, candidate, "CAA", retries)
            records = [r.to_text() for r in answer]
            return candidate, records, None
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except RuntimeError as exc:
            errors.append(f"{candidate}: {exc}")
            continue

    if errors:
        return None, None, "; ".join(errors)
    return None, None, None


def run(context) -> int:
    caa_family_root = context.findings_dir / "CAA" / context.family_label
    remove_stale(caa_family_root)

    hosts = target_fqdns(context)
    if not hosts:
        print(f"[*] caa/{context.family_label}: no verified FQDNs in inventory.")
        return 0

    dns_resolver_module = load_dnspython()
    if dns_resolver_module is None:
        print(f"[*] caa/{context.family_label}: dnspython unavailable; skipping CAA module.")
        return 0

    resolver = dns_resolver_module.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0
    retries = 2

    print(f"[*] caa/{context.family_label}: checking {len(hosts)} FQDN(s) for CAA coverage.")

    no_caa: list[str] = []
    evidence_lines: dict[str, str] = {}
    lookup_errors: list[str] = []

    for host in hosts:
        try:
            effective_target = resolve_cname(resolver, host, retries)
        except Exception as exc:
            lookup_errors.append(f"{host}: DNS error resolving CNAME chain -> {exc}")
            continue

        cname_note = f" (CNAME -> {effective_target})" if effective_target != host else ""
        level, records, error = walk_caa(resolver, effective_target, retries)

        if error:
            lookup_errors.append(f"{host}{cname_note}: {error}")
        elif records:
            continue  # CAA present -- not a finding.
        else:
            no_caa.append(host)
            evidence_lines[host] = f"{host}{cname_note} : no CAA record found in walked chain."

    finding_count = 0

    if no_caa:
        out = caa_family_root / "Missing CAA Record"
        out.mkdir(parents=True, exist_ok=True)
        (out / "affected_hosts.txt").write_text(
            "\n".join(sorted(no_caa)) + "\n", encoding="utf-8"
        )
        (out / "evidence.txt").write_text(
            "\n".join(evidence_lines[h] for h in sorted(no_caa)) + "\n", encoding="utf-8"
        )
        finding_count += len(no_caa)
        print(f"[-] caa/{context.family_label}: {len(no_caa)} host(s) with no effective CAA record.")

    if lookup_errors:
        caa_family_root.mkdir(parents=True, exist_ok=True)
        (caa_family_root / "dns_check_errors.txt").write_text(
            "\n".join(lookup_errors) + "\n", encoding="utf-8"
        )
        print(
            f"[!] caa/{context.family_label}: {len(lookup_errors)} host(s) could not be "
            "verified (see dns_check_errors.txt) -- not treated as findings."
        )

    return finding_count
