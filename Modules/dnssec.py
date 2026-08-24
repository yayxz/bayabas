"""Bayabas DNSSEC audit module.

Checks whether the FQDNs in the current family's inventory are covered by
a working DNSSEC chain of trust.

DNSSEC is a *zone-level* property, not a per-hostname one. Querying DNSKEY
directly on a literal name like "www.example.com" will almost always come
back empty -- not because DNSSEC is unsupported, but because that name is
not a zone apex, just a record inside example.com's zone. This module
first reduces each FQDN to its registrable zone apex (public-suffix
aware) and evaluates DNSSEC there, matching how a finding is actually
described in a report ("example.com does not implement DNSSEC"), not per
subdomain.

For each apex, three independent signals are combined so a real "not
supported" finding is never confused with an inconclusive check:
    1. DS record at the apex (delegation signer published by the parent/
       registrar) -- absence means the chain of trust was never anchored.
    2. DNSKEY record at the apex (keys published by the zone itself) --
       absence means the zone itself isn't signing its records.
    3. The AD (Authenticated Data) flag on a DNSSEC-OK query against a
       known DNSSEC-validating public resolver -- confirms the chain
       actually validates end-to-end, not just that records are present.
    A SERVFAIL response on any of these queries is itself a strong signal
    of a broken chain (the resolver refusing to return bogus data) and is
    reported as a misconfiguration, not an inconclusive result.

DS/DNSKEY presence checks use the system resolver; the AD-flag
confirmation deliberately uses a separate, known-validating public
resolver (1.1.1.1 by default) so a non-validating resolver on the
engagement network can't make every domain look falsely "unsupported".

Use only against systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


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

DEFAULT_VALIDATING_RESOLVER = "1.1.1.1"


def yes_no(message: str, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        return default
    marker = "Y/n" if default else "y/N"
    answer = input(f"{message} [{marker}]: ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def load_dnspython():
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


def is_just_public_suffix(hostname: str) -> bool:
    return hostname in KNOWN_MULTI_LABEL_SUFFIXES


def zone_apex(hostname: str) -> str:
    """Reduce a hostname to its registrable zone apex, public-suffix
    aware. The registrable apex is one label deeper than the effective
    TLD: for an ordinary single-label TLD like "com", that's the last two
    labels ("cloudflare.com"); for a known multi-label public suffix like
    "co.uk", that's the last three labels ("example.co.uk")."""
    labels = hostname.split(".")
    if len(labels) <= 1:
        return hostname
    apex_label_count = 3 if ".".join(labels[-2:]) in KNOWN_MULTI_LABEL_SUFFIXES else 2
    apex_label_count = min(apex_label_count, len(labels))
    return ".".join(labels[-apex_label_count:])


def is_servfail_error(exc) -> bool:
    errors = getattr(exc, "kwargs", {}).get("errors", [])
    for entry in errors:
        if len(entry) >= 4 and str(entry[3]).upper() == "SERVFAIL":
            return True
    return False


class DnssecValidationFailure(Exception):
    """A nameserver explicitly returned SERVFAIL for a DNSSEC-relevant
    query -- a genuine "misconfigured" finding, not an inconclusive one."""


def query_with_retry(resolver, name: str, rdtype: str, retries: int):
    import dns.resolver
    import dns.exception

    last_error = None
    for _ in range(retries + 1):
        try:
            return resolver.resolve(name, rdtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            raise
        except dns.resolver.NoNameservers as exc:
            last_error = exc
            continue
        except dns.exception.DNSException as exc:
            last_error = exc
            continue

    import dns.resolver as _dr
    if isinstance(last_error, _dr.NoNameservers) and is_servfail_error(last_error):
        raise DnssecValidationFailure(
            f"SERVFAIL resolving {rdtype} for {name} -- resolver refused to return data"
        )
    raise RuntimeError(f"{type(last_error).__name__}: {last_error}")


def check_presence(resolver, apex: str, rdtype: str, retries: int) -> bool:
    import dns.resolver

    try:
        answer = query_with_retry(resolver, apex, rdtype, retries)
    except dns.resolver.NXDOMAIN as exc:
        raise RuntimeError(f"NXDOMAIN resolving apex {apex}: {exc}")
    return answer.rrset is not None


def check_ad_flag(validating_resolver, apex: str, retries: int) -> bool:
    import dns.exception

    last_error = None
    for _ in range(retries + 1):
        try:
            answer = validating_resolver.resolve(apex, "SOA", raise_on_no_answer=False)
            import dns.flags
            return bool(answer.response.flags & dns.flags.AD)
        except dns.exception.DNSException as exc:
            last_error = exc
            continue

    import dns.resolver as _dr
    if isinstance(last_error, _dr.NoNameservers) and is_servfail_error(last_error):
        raise DnssecValidationFailure(
            f"SERVFAIL resolving SOA for {apex} via validating resolver -- broken chain"
        )
    raise RuntimeError(f"{type(last_error).__name__}: {last_error}")


def run(context) -> int:
    dnssec_family_root = context.findings_dir / "DNSSEC" / context.family_label
    remove_stale(dnssec_family_root)

    hosts = target_fqdns(context)
    if not hosts:
        print(f"[*] dnssec/{context.family_label}: no verified FQDNs in inventory.")
        return 0

    dns_resolver_module = load_dnspython()
    if dns_resolver_module is None:
        print(f"[*] dnssec/{context.family_label}: dnspython unavailable; skipping DNSSEC module.")
        return 0

    import dns.flags

    resolver = dns_resolver_module.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    validating_resolver = dns_resolver_module.Resolver()
    validating_resolver.nameservers = [DEFAULT_VALIDATING_RESOLVER]
    validating_resolver.timeout = 5.0
    validating_resolver.lifetime = 5.0
    validating_resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=1232)

    retries = 2

    domain_hosts = [h for h in hosts if not is_just_public_suffix(h)]
    apex_to_hosts: dict[str, list[str]] = {}
    for host in domain_hosts:
        apex_to_hosts.setdefault(zone_apex(host), []).append(host)

    print(
        f"[*] dnssec/{context.family_label}: evaluating {len(apex_to_hosts)} unique "
        f"zone(s) from {len(hosts)} FQDN(s)."
    )

    not_supported: list[str] = []
    misconfigured: list[str] = []
    lookup_errors: list[str] = []
    evidence: dict[str, str] = {}

    for apex, original_hosts in sorted(apex_to_hosts.items()):
        covers_note = "" if original_hosts == [apex] else f" (covers {', '.join(original_hosts)})"

        try:
            has_ds = check_presence(resolver, apex, "DS", retries)
            has_dnskey = check_presence(resolver, apex, "DNSKEY", retries)
        except DnssecValidationFailure as exc:
            misconfigured.append(apex)
            evidence[apex] = f"{apex}{covers_note} : MISCONFIGURED -- {exc}"
            continue
        except Exception as exc:
            lookup_errors.append(f"{apex}{covers_note}: DNS error checking DS/DNSKEY -> {exc}")
            continue

        if not has_ds and not has_dnskey:
            not_supported.append(apex)
            evidence[apex] = f"{apex}{covers_note} : NOT SUPPORTED -- no DS, no DNSKEY."
            continue

        if has_ds != has_dnskey:
            missing = "DNSKEY" if has_ds else "DS"
            misconfigured.append(apex)
            evidence[apex] = f"{apex}{covers_note} : MISCONFIGURED -- missing {missing}, broken chain of trust."
            continue

        try:
            ad_confirmed = check_ad_flag(validating_resolver, apex, retries)
        except DnssecValidationFailure as exc:
            misconfigured.append(apex)
            evidence[apex] = f"{apex}{covers_note} : MISCONFIGURED -- {exc}"
            continue
        except Exception as exc:
            lookup_errors.append(f"{apex}{covers_note}: DS+DNSKEY present but could not confirm validation -> {exc}")
            continue

        if not ad_confirmed:
            misconfigured.append(apex)
            evidence[apex] = (
                f"{apex}{covers_note} : MISCONFIGURED -- DS+DNSKEY present but chain "
                "does not validate (check for expired/invalid RRSIG)."
            )
        # else: DNSSEC supported and validated -- not a finding.

    finding_count = 0

    if not_supported:
        out = dnssec_family_root / "DNSSEC Not Supported"
        out.mkdir(parents=True, exist_ok=True)
        (out / "affected_hosts.txt").write_text(
            "\n".join(sorted(not_supported)) + "\n", encoding="utf-8"
        )
        (out / "evidence.txt").write_text(
            "\n".join(evidence[a] for a in sorted(not_supported)) + "\n", encoding="utf-8"
        )
        finding_count += len(not_supported)
        print(f"[-] dnssec/{context.family_label}: {len(not_supported)} zone(s) with no DNSSEC.")

    if misconfigured:
        out = dnssec_family_root / "DNSSEC Misconfigured"
        out.mkdir(parents=True, exist_ok=True)
        (out / "affected_hosts.txt").write_text(
            "\n".join(sorted(misconfigured)) + "\n", encoding="utf-8"
        )
        (out / "evidence.txt").write_text(
            "\n".join(evidence[a] for a in sorted(misconfigured)) + "\n", encoding="utf-8"
        )
        finding_count += len(misconfigured)
        print(f"[!] dnssec/{context.family_label}: {len(misconfigured)} zone(s) with a broken DNSSEC chain.")

    if lookup_errors:
        dnssec_family_root.mkdir(parents=True, exist_ok=True)
        (dnssec_family_root / "dns_check_errors.txt").write_text(
            "\n".join(lookup_errors) + "\n", encoding="utf-8"
        )
        print(
            f"[!] dnssec/{context.family_label}: {len(lookup_errors)} zone(s) could not be "
            "verified (see dns_check_errors.txt) -- not treated as findings."
        )

    return finding_count
