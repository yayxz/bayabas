#!/usr/bin/env python3
"""
Resolve a mixed list of IPs / hostnames to their counterpart, using DNS + NetBIOS.

IP entries       -> reverse DNS (PTR) + NetBIOS (nmap nbstat) + nxc (SMB)  -> hostname(s)
Hostname entries -> forward DNS (A + AAAA) + NetBIOS (nmblookup)          -> IP(s)

For IP entries, nxc's `nxc smb <ip>` is also queried: it often reveals a
host's computer name (and its real AD domain) straight from the SMB
negotiate banner even when there's no PTR record and NetBIOS is silent.
When nxc reports a domain that isn't just "WORKGROUP", that name is fed in
as an already-qualified FQDN, so it also seeds domain-inference for other
rows in the same run. Disable with --no-nxc.

IP entries also get checked with every nmap NSE script that leaks a
target's computer name / AD domain via unauthenticated protocol
negotiation - not just RDP. The following are tried (each only produces
output if that port is open; silently contributes nothing otherwise):
  rdp-ntlm-info      TCP/3389   RDP
  ms-sql-ntlm-info   TCP/1433   MSSQL
  smtp-ntlm-info     TCP/25     SMTP
  imap-ntlm-info     TCP/143    IMAP
  pop3-ntlm-info     TCP/110    POP3
  http-ntlm-info     TCP/80     HTTP (NTLM-auth-enabled sites only)
  smb-os-discovery   TCP/445    SMB (different output format: Computer
                                 name / Domain name / FQDN, parsed
                                 separately from the ntlm-info family above)
Disable the ntlm-info family with --no-ntlm-info, and smb-os-discovery
with --no-smb-os.

An nmap `ssl-cert` check (TCP/443 by default; more ports via --ssl-ports)
pulls candidate hostnames from a certificate's Subject CN and Subject
Alternative Names. Unlike every other source above, certificate names are
NOT inherently trustworthy on their own - a cert can be shared across many
IPs (load balancers, CDNs, SNI-based shared hosting, stale/reused certs),
so a name on a cert doesn't necessarily belong to the specific IP being
scanned. Each candidate name is therefore forward-resolved and only kept
if it actually resolves back to the IP whose cert it came from; unverified
candidates are silently dropped rather than reported. Disable with
--no-ssl-cert.

IPv4 and IPv6 are both handled: an IPv6 address in the input file is treated
as an IP entry (reverse PTR lookup), and forward lookups on a hostname
return both its A and AAAA records. NetBIOS is IPv4-only by design (it has
no IPv6 concept), so it's skipped for IPv6 addresses and never returns
IPv6 results.

DNS lookups (forward and reverse) are done by shelling out to the `host`
command rather than Python's socket module. This matters for two reasons:
  1. Python's socket.gethostbyaddr() delegates to the OS's glibc/NSS
     resolver, which is only reliable for a SINGLE PTR record per IP -
     hosts with multiple PTR records (common behind load balancers / API
     gateways) get silently truncated to just one name with no error.
     `host` queries DNS directly and returns every record in the response.
  2. `host` accepts an explicit server argument, so lookups can be pointed
     at a specific DNS server (e.g. an internal AD DNS server) via
     --dns-server, rather than always using the system's configured
     resolver.

Per-row results are deduplicated case-insensitively (by first label). A
label with MULTIPLE distinct FQDNs (e.g. a host with several PTR records
across different domains) keeps all of them - they are not collapsed to
just the last one seen. A bare NetBIOS name (no domain) gets qualified in
this order:
  1. a domain seen in that same row's own PTR/FQDN result (trusted, no check
     needed - it came straight from that IP's own DNS record)
  2. a domain seen elsewhere in this run, on other rows (most-common first) -
     tried by forward-resolving "name.candidate-domain" and only accepted if
     it actually resolves back to this row's own IP
  3. the fallback domain (auto-detected, or given via --domain) - same
     forward-resolve verification first; if that doesn't confirm it either,
     it's appended unverified as a last resort so --domain always has effect
If nothing above applies, the bare name is left unqualified.

Rows that resolve to more than one final value get a leading '*'. Rows that
resolve to nothing print '???'.

A DNS server to use for all `host` lookups can be given via --dns-server.
If not given on the command line, the script prompts interactively for one
(just hit Enter to use the system's default resolver).

In addition to the IP/Hostname table, the script writes an /etc/hosts-style
snippet (IP followed by every hostname resolved for it) to a file, and
prints a ready-to-run one-liner for appending that snippet into /etc/hosts.

Requires: nmap (with the nbstat, rdp-ntlm-info, ms-sql-ntlm-info,
smtp-ntlm-info, imap-ntlm-info, pop3-ntlm-info, http-ntlm-info,
smb-os-discovery, and ssl-cert NSE scripts - all bundled with a standard
nmap install) for every IP-side discovery method except nxc, nmblookup
(samba-common-bin / samba-client) for name -> IP NetBIOS resolution, the
`host` command (bind9-dnsutils / bind-utils) for all forward/reverse DNS
lookups, and nxc / NetExec (https://github.com/Pennyw0rth/NetExec) for
SMB-based hostname/domain discovery. The script checks whether nxc and
host are on PATH at startup and prints install instructions if either is
missing, rather than failing.
"""

import argparse
import ipaddress
import re
import shutil
import socket
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

NBSTAT_RE = re.compile(r"NetBIOS name:\s*([^,]+),")
NMBLOOKUP_IP_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s")
NXC_NAME_RE = re.compile(r"\(name:([^)]+)\)", re.IGNORECASE)
NXC_DOMAIN_RE = re.compile(r"\(domain:([^)]+)\)", re.IGNORECASE)
HOST_PTR_RE = re.compile(r"domain name pointer\s+(\S+)")
HOST_A_RE = re.compile(r"has address\s+(\S+)")
HOST_AAAA_RE = re.compile(r"has IPv6 address\s+(\S+)")

# Shared field format across nmap's *-ntlm-info scripts (rdp-ntlm-info,
# ms-sql-ntlm-info, smtp-ntlm-info, imap-ntlm-info, pop3-ntlm-info,
# http-ntlm-info) - they all use the same underlying NTLM-challenge parsing
# code and print identical field names regardless of protocol.
NTLM_NETBIOS_NAME_RE = re.compile(r"NetBIOS_Computer_Name:\s*(\S+)")
NTLM_DNS_NAME_RE = re.compile(r"DNS_Computer_Name:\s*(\S+)")
NTLM_DNS_DOMAIN_RE = re.compile(r"DNS_Domain_Name:\s*(\S+)")

# (script name, default port) for every *-ntlm-info script tried per IP.
NTLM_INFO_SCRIPTS = [
    ("rdp-ntlm-info", 3389),
    ("ms-sql-ntlm-info", 1433),
    ("smtp-ntlm-info", 25),
    ("imap-ntlm-info", 143),
    ("pop3-ntlm-info", 110),
    ("http-ntlm-info", 80),
]

# smb-os-discovery uses a different output format from the ntlm-info family.
SMB_OS_COMPUTER_NAME_RE = re.compile(r"Computer name:\s*(\S+)")
SMB_OS_NETBIOS_NAME_RE = re.compile(r"NetBIOS computer name:\s*(\S+)")
SMB_OS_DOMAIN_NAME_RE = re.compile(r"Domain name:\s*(\S+)")
SMB_OS_FQDN_RE = re.compile(r"FQDN:\s*(\S+)")

# ssl-cert output: Subject commonName and Subject Alternative Name DNS entries.
SSL_CERT_CN_RE = re.compile(r"commonName=([^/,\s]+)")
SSL_CERT_SAN_RE = re.compile(r"DNS:([^,\s]+)")

NXC_INSTALL_HINT = (
    "nxc (NetExec) not found on PATH - install it with:\n"
    "    sudo apt install -y pipx git && pipx ensurepath && pipx install git+https://github.com/Pennyw0rth/NetExec\n"
    "    (Kali/ParrotSec: apt install netexec   |   BlackArch: pacman -S netexec)\n"
    "  Continuing without nxc-based SMB hostname resolution (use --no-nxc to silence this check)."
)

HOST_CMD_INSTALL_HINT = (
    "`host` command not found on PATH - install it with:\n"
    "    sudo apt install -y bind9-dnsutils   (Debian/Kali/Ubuntu)\n"
    "    sudo yum install -y bind-utils       (RHEL/CentOS)\n"
    "  DNS lookups will not work without it."
)


def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def is_ip(s):
    """True for either an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def host_cmd_available():
    return shutil.which("host") is not None


def reverse_dns(ip, dns_server=None):
    """PTR lookup via `host` -> list of ALL hostnames for this IP (no
    trailing dot). Deliberately does not use socket.gethostbyaddr(), which
    only reliably returns a single PTR record via the glibc/NSS resolver -
    hosts with multiple PTR records get silently truncated to one name."""
    cmd = ["host", "-t", "PTR", ip] + ([dns_server] if dns_server else [])
    out = run(cmd)
    return [m.rstrip(".").lower() for m in HOST_PTR_RE.findall(out)]


def netbios_name_for_ip(ip):
    out = run(["nmap", "-sU", "-p137", "--script", "nbstat", "-Pn", ip])
    return [m.strip() for m in NBSTAT_RE.findall(out)]


def forward_dns(name, dns_server=None):
    """A + AAAA lookup via `host` -> list of IPv4 and IPv6 addresses.
    Uses `host` rather than socket.getaddrinfo() so a specific DNS server
    can be targeted via --dns-server."""
    cmd = ["host", name] + ([dns_server] if dns_server else [])
    out = run(cmd)
    ips = set(HOST_A_RE.findall(out)) | set(HOST_AAAA_RE.findall(out))
    return [ip.split("%", 1)[0] for ip in ips]


def netbios_ip_for_name(name):
    out = run(["nmblookup", name])
    ips = []
    for line in out.splitlines():
        m = NMBLOOKUP_IP_RE.match(line.strip())
        if m:
            ips.append(m.group(1))
    return ips


def nxc_available():
    return shutil.which("nxc") is not None


def nxc_smb_info(ip):
    """Query nxc's SMB module for this host's computer name and AD domain,
    parsed from the unauthenticated SMB banner nxc prints, e.g.:
      SMB  10.86.24.4  445  LTGUKSTDMPUB1  [*] Windows ... (name:LTGUKSTDMPUB1) (domain:sd.com) (signing:True) (SMBv1:None)
    Returns (names, domain): names is every "(name:...)" seen (there's
    normally just one), domain is the domain field if present and not just
    "WORKGROUP" (which means no real AD domain, just a local workgroup)."""
    out = run(["nxc", "smb", ip], timeout=25)
    names = [m.strip() for m in NXC_NAME_RE.findall(out) if m.strip()]
    domain = None
    dm = NXC_DOMAIN_RE.search(out)
    if dm:
        d = dm.group(1).strip()
        if d and d.upper() != "WORKGROUP":
            domain = d.lower()
    return names, domain


def ntlm_info_names_for_ip(ip, script, port):
    """Query one *-ntlm-info nmap script (see NTLM_INFO_SCRIPTS) against a
    single port for this host's NetBIOS computer name and, when
    domain-joined, its DNS domain and fully qualified DNS computer name -
    all unauthenticated. Returns a list of names: the FQDN if
    DNS_Computer_Name was printed directly, plus the bare NetBIOS name on
    its own (or constructed into an FQDN if DNS_Domain_Name was given but
    DNS_Computer_Name wasn't). Returns an empty list if the port isn't
    open/responsive or the service doesn't support NTLM negotiation - this

    is expected for most host/script combinations and not an error."""
    out = run(["nmap", "-p", str(port), "--script", script, "-Pn", ip], timeout=30)
    netbios_m = NTLM_NETBIOS_NAME_RE.search(out)
    dns_m = NTLM_DNS_NAME_RE.search(out)
    domain_m = NTLM_DNS_DOMAIN_RE.search(out)

    names = []
    if dns_m:
        names.append(dns_m.group(1).strip())
    if netbios_m:
        netbios_name = netbios_m.group(1).strip()
        names.append(netbios_name)
        if domain_m and not dns_m:
            names.append(f"{netbios_name}.{domain_m.group(1).strip()}")
    return names


def collect_ntlm_info_names(ip):
    """Run every script in NTLM_INFO_SCRIPTS against this IP and pool the
    results. Each script only fires anything if its port is open, so most
    calls on most hosts contribute nothing - that's expected."""
    names = []
    for script, port in NTLM_INFO_SCRIPTS:
        names += ntlm_info_names_for_ip(ip, script, port)
    return names


def smb_os_discovery_names_for_ip(ip):
    """Query nmap's smb-os-discovery script (TCP/445) for this host's
    computer name, NetBIOS computer name, domain name, and FQDN - a
    different output format from the ntlm-info family, parsed separately.
    Returns an empty list if SMB isn't open or doesn't respond to this
    script, which is expected on many hosts."""
    out = run(["nmap", "-p", "445", "--script", "smb-os-discovery", "-Pn", ip], timeout=30)
    names = []
    fqdn_m = SMB_OS_FQDN_RE.search(out)
    if fqdn_m:
        names.append(fqdn_m.group(1).strip())
    for m in (SMB_OS_COMPUTER_NAME_RE, SMB_OS_NETBIOS_NAME_RE):
        found = m.search(out)
        if found:
            names.append(found.group(1).strip())
    return names


def ssl_cert_candidates_for_ip(ip, ports):
    """Query nmap's ssl-cert script against each port in `ports` and pull
    candidate hostnames from the certificate's Subject commonName and
    Subject Alternative Name (DNS) entries. These are CANDIDATES ONLY -
    unlike every other discovery method here, a certificate can legitimately
    be shared across many IPs (load balancers, CDNs, SNI-based shared
    hosting, stale/reused certs), so a name appearing on a cert does not by
    itself mean that name belongs to this specific IP. Callers must
    forward-resolve each candidate and only keep it if it actually resolves
    back to this IP (see verify_cert_candidates_task). Wildcard entries
    (e.g. "*.example.com") are dropped outright, since they aren't a
    resolvable literal hostname."""
    candidates = set()
    for port in ports:
        out = run(["nmap", "-p", str(port), "--script", "ssl-cert", "-Pn", ip], timeout=30)
        cn_m = SSL_CERT_CN_RE.search(out)
        if cn_m:
            candidates.add(cn_m.group(1).strip().rstrip(".").lower())
        for san in SSL_CERT_SAN_RE.findall(out):
            candidates.add(san.strip().rstrip(".").lower())
    return [c for c in candidates if c and not c.startswith("*")]


def detect_local_domain():
    """Best-effort auto-discovery of a DNS domain to use as a fallback for
    qualifying bare NetBIOS names when nothing better is found for that row.
    Tries, in order: `dnsdomainname`, the `domain`/`search` line in
    /etc/resolv.conf, and this machine's own FQDN. Returns None if none of
    those yield anything (e.g. offline, or resolv.conf has no domain set)."""
    out = run(["dnsdomainname"]).strip()
    if out and out != "(none)":
        return out.lower()

    try:
        with open("/etc/resolv.conf") as f:
            lines = f.readlines()
        for line in lines:
            parts = line.split()
            if parts and parts[0] == "domain" and len(parts) > 1:
                return parts[1].lower()
        for line in lines:
            parts = line.split()
            if parts and parts[0] == "search" and len(parts) > 1:
                return parts[1].lower()
    except OSError:
        pass

    fqdn = socket.getfqdn()
    if "." in fqdn:
        return fqdn.split(".", 1)[1].lower()

    return None


def parse_hostnames(names):
    """Split raw hostname/NetBIOS-name results into: best (label -> set of
    chosen FQDN values for that label, since a label can legitimately have
    MULTIPLE distinct FQDNs - e.g. a host with several PTR records across
    different domains - these are all kept, not collapsed to the last one
    seen), is_fqdn (label -> bool), and the domain of this row's own FQDN
    (the first one seen, if any).
    """
    best, is_fqdn, domain = {}, {}, None
    for raw in names:
        n = raw.strip().rstrip(".").lower()
        if not n:
            continue
        label = n.split(".", 1)[0]
        if "." in n:
            best.setdefault(label, set()).add(n)
            is_fqdn[label] = True
            if domain is None:
                domain = n.split(".", 1)[1]
        elif label not in best:
            best[label] = {n}
            is_fqdn[label] = False
    return best, is_fqdn, domain


def dedupe_ips(ips):
    def key(ip):
        try:
            addr = ipaddress.ip_address(ip)
            return (addr.version, int(addr))
        except ValueError:
            return (99, 0)
    return sorted(set(ip for ip in ips if ip), key=key)


def ip_equal(a, b):
    """Compare two address strings by value, not text, so e.g. '::1' and
    '0:0:0:0:0:0:0:1' (or any other equivalent IPv6 form) still match."""
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b


def parallel_map(fn, items, workers):
    """Run fn(item) for every item concurrently; return results in the same
    order as items (order of completion doesn't matter to the caller)."""
    results = [None] * len(items)
    if not items:
        return results
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(fn, item): i for i, item in enumerate(items)}
        for fut in as_completed(futures):
            results[futures[fut]] = fut.result()
    return results


def raw_lookup(entry, use_nxc=False, dns_server=None, use_ntlm=False, use_smb_os=False, use_ssl_cert=False, ssl_ports=None):
    entry = entry.strip()
    if is_ip(entry):
        names = reverse_dns(entry, dns_server)
        if is_ipv4(entry):  # NetBIOS has no IPv6 equivalent
            names += netbios_name_for_ip(entry)
        if use_nxc:
            nxc_names, nxc_domain = nxc_smb_info(entry)
            names += nxc_names
            if nxc_domain:
                # feed in an already-qualified form too, so parse_hostnames
                # treats this row as having a trusted domain of its own
                names += [f"{n}.{nxc_domain}" for n in nxc_names]
        if use_ntlm:
            names += collect_ntlm_info_names(entry)
        if use_smb_os:
            names += smb_os_discovery_names_for_ip(entry)
        cert_candidates = ssl_cert_candidates_for_ip(entry, ssl_ports) if use_ssl_cert else []
        return {"entry": entry, "type": "ip", "raw": names, "cert_candidates": cert_candidates}
    return {"entry": entry, "type": "host", "raw": forward_dns(entry, dns_server) + netbios_ip_for_name(entry)}


def gather_candidate_domains(raws, parsed_ip_rows):
    """Domains actually observed elsewhere in this run: from other IP rows'
    own PTR/FQDN results, and from any hostname-type entry that was itself
    given as an FQDN. Sorted most-common first, since a domain seen on more
    hosts in this list is a better guess for an unqualified one."""
    counter = Counter()
    for r in raws:
        if r["type"] == "host" and "." in r["entry"]:
            counter[r["entry"].split(".", 1)[1].lower()] += 1
    for _best, _is_fqdn, domain in parsed_ip_rows.values():
        if domain:
            counter[domain] += 1
    return [d for d, _ in counter.most_common()]


def verify_task(task):
    """Try candidate domains in order against one bare (label, ip); return
    the first "label.domain" that forward-resolves back to that ip."""
    idx, label, short, entry_ip, candidates, dns_server = task
    for candidate in candidates:
        resolved = forward_dns(f"{short}.{candidate}", dns_server)
        if any(ip_equal(entry_ip, ip) for ip in resolved):
            return idx, label, f"{short}.{candidate}"
    return idx, label, None


def verify_cert_candidates_task(task):
    """Forward-resolve each SSL-cert-derived candidate name and keep only
    the ones that actually resolve back to the IP the cert came from -
    since a cert can be shared across IPs it isn't inherently trustworthy
    the way a PTR/NetBIOS/NTLM/SMB result is. Returns (idx, verified_names)."""
    idx, entry_ip, candidates, dns_server = task
    verified = []
    for name in candidates:
        resolved = forward_dns(name, dns_server)
        if any(ip_equal(entry_ip, ip) for ip in resolved):
            verified.append(name)
    return idx, verified


def finalize_ip_row(entry, best, is_fqdn, domain, verified_for_row, fallback_domain):
    result = []
    for label, vals in best.items():
        for val in vals:
            if not is_fqdn[label]:
                if label in verified_for_row:
                    val = verified_for_row[label]
                elif domain:
                    val = f"{val}.{domain}"
                elif fallback_domain:
                    val = f"{val}.{fallback_domain}"
            result.append(val)
    resolved = sorted(set(result))
    col = "???" if not resolved else ",".join(resolved)
    flag = "*" if len(resolved) > 1 else ""
    return f"{flag}{entry}", col


def finalize_host_row(entry, raw_ips):
    resolved = dedupe_ips(raw_ips)
    col = "???" if not resolved else ",".join(resolved)
    flag = "*" if len(resolved) > 1 else ""
    return f"{flag}{col}", entry


def resolve_all(entries, workers, fallback_domain, use_nxc=False, dns_server=None,
                 use_ntlm=False, use_smb_os=False, use_ssl_cert=False, ssl_ports=None):
    # Phase 1: run every DNS/NetBIOS/nxc/NTLM-info/SMB-OS/ssl-cert lookup
    # concurrently. ssl-cert results land in "cert_candidates", not "raw",
    # since they need forward-resolve verification before they're trusted.
    raws = parallel_map(
        lambda e: raw_lookup(e, use_nxc, dns_server, use_ntlm, use_smb_os, use_ssl_cert, ssl_ports),
        entries, workers,
    )

    # Phase 1b: verify ssl-cert candidates by forward-resolving each one and
    # keeping only those that resolve back to the IP the cert came from.
    # Verified names are folded into "raw" alongside the trusted sources.
    cert_tasks = [
        (idx, r["entry"], r.get("cert_candidates", []), dns_server)
        for idx, r in enumerate(raws)
        if r["type"] == "ip" and r.get("cert_candidates")
    ]
    for idx, verified_names in parallel_map(verify_cert_candidates_task, cert_tasks, workers):
        raws[idx]["raw"] += verified_names

    parsed_ip_rows = {}
    for idx, r in enumerate(raws):
        if r["type"] == "ip":
            parsed_ip_rows[idx] = parse_hostnames(r["raw"])

    # Phase 2: learn candidate domains from rows that already have one, then
    # verify bare names on the rows that don't against those candidates
    # (plus the fallback domain, tried last).
    candidates = gather_candidate_domains(raws, parsed_ip_rows)
    if fallback_domain and fallback_domain not in candidates:
        candidates = candidates + [fallback_domain]

    verify_tasks = []
    for idx, (best, is_fqdn, domain) in parsed_ip_rows.items():
        if domain or not candidates:
            continue
        entry_ip = raws[idx]["entry"]
        for label, vals in best.items():
            if not is_fqdn[label]:
                short = next(iter(vals))
                verify_tasks.append((idx, label, short, entry_ip, candidates, dns_server))

    verified = {}
    for idx, label, fqdn in parallel_map(verify_task, verify_tasks, workers):
        if fqdn:
            verified.setdefault(idx, {})[label] = fqdn

    # Phase 3: assemble final rows.
    rows = [None] * len(entries)
    for idx, r in enumerate(raws):
        if r["type"] == "ip":
            best, is_fqdn, domain = parsed_ip_rows[idx]
            rows[idx] = finalize_ip_row(r["entry"], best, is_fqdn, domain, verified.get(idx, {}), fallback_domain)
        else:
            rows[idx] = finalize_host_row(r["entry"], r["raw"])
    return rows


def build_target_list(rows):
    """From the final (ip, hostnames) rows, build a new target list: the
    resolved hostname(s) when there are any (splitting out each one if a row
    resolved to multiple), otherwise the IP as given (again splitting out
    each one if a hostname entry resolved to multiple IPs). Order-preserving
    de-dupe, since the same host can legitimately show up via more than one
    row (e.g. an IP row and a hostname row both pointing at it).

    Same cleanup as the /etc/hosts snippet: within each row, a bare
    (unqualified) NetBIOS name is dropped if a fully-qualified name sharing
    its short label is also present in that row - see
    _dedupe_bare_when_fqdn_exists(). Otherwise a target list commonly ends
    up with both "sql01" and "sql01.scottdunn.com" as separate targets for
    the same host."""
    targets = []
    seen = set()
    for ip_col, host_col in rows:
        ip_col = ip_col.lstrip("*")
        host_col = host_col.lstrip("*")
        if host_col != "???":
            values = [v.strip() for v in host_col.split(",") if v.strip()]
            keep = _dedupe_bare_when_fqdn_exists(set(values))
            values = [v for v in values if v in keep]
        else:
            values = [v.strip() for v in ip_col.split(",") if v.strip()]
        for v in values:
            if v and v not in seen:
                seen.add(v)
                targets.append(v)
    return targets


def _dedupe_bare_when_fqdn_exists(hosts):
    """Given a set of hostnames resolved for one IP, drop any bare
    (unqualified, no dot) name when a fully-qualified name sharing the same
    short label is also present - e.g. {"sdukstdsql1",
    "sdukstdsql1.scottdunn.com"} becomes just {"sdukstdsql1.scottdunn.com"}.
    This happens when a bare NetBIOS name couldn't be verified against any
    candidate/fallback domain (so it was left unqualified) while a separate
    discovery method (PTR, RDP, nxc) independently found the real FQDN for
    the same host. The bare form is redundant noise at that point - keep it
    only for labels that have no qualified form at all."""
    by_label = {}
    for h in hosts:
        label = h.split(".", 1)[0]
        by_label.setdefault(label, []).append(h)
    result = set()
    for label, names in by_label.items():
        fqdns = [n for n in names if "." in n]
        result.update(fqdns if fqdns else names)
    return result


def build_hosts_entries(rows):
    """From the final (ip_col, host_col) rows, build an /etc/hosts-style
    mapping of IP -> set of hostnames. Rows are always (ip-ish, host-ish)
    regardless of whether the original entry was an IP or a hostname (see
    finalize_ip_row / finalize_host_row), so this works uniformly across
    both row types. Rows that didn't resolve ("???" in either column) are
    skipped, since there's nothing usable to put in /etc/hosts. Bare
    (unqualified) names are dropped per-IP whenever a fully-qualified name
    with the same short label is also present for that IP - see
    _dedupe_bare_when_fqdn_exists()."""
    ip_to_hosts = {}
    for ip_col, host_col in rows:
        ip_col = ip_col.lstrip("*")
        host_col = host_col.lstrip("*")
        if ip_col == "???" or host_col == "???":
            continue
        ips = [v.strip() for v in ip_col.split(",") if v.strip()]
        hosts = [v.strip() for v in host_col.split(",") if v.strip()]
        for ip in ips:
            if not is_ip(ip):
                continue
            for h in hosts:
                ip_to_hosts.setdefault(ip, set()).add(h)

    return {ip: _dedupe_bare_when_fqdn_exists(hosts) for ip, hosts in ip_to_hosts.items()}


def write_hosts_snippet(ip_to_hosts, path):
    """Write one /etc/hosts-format line per (IP, hostname) PAIR - i.e. a
    host with multiple resolved hostnames gets one line per hostname, all
    sharing the same IP, e.g.:
        1.1.1.1  ab.com
        1.1.1.1  b.com
    rather than one line per IP with every hostname crammed onto it. Lines
    are sorted by IP, then by hostname within each IP. Returns the list of
    lines written."""

    def ip_key(ip):
        try:
            addr = ipaddress.ip_address(ip)
            return (addr.version, int(addr))
        except ValueError:
            return (99, 0)

    lines = []
    for ip in sorted(ip_to_hosts, key=ip_key):
        for host in sorted(ip_to_hosts[ip]):
            lines.append(f"{ip}\t{host}")

    with open(path, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))

    return lines


def prompt_append_to_hosts(path, lines):
    """Interactively ask whether to append the resolved entries straight
    into /etc/hosts (one IP-hostname pair per line, via `sudo tee -a`).
    Declining just leaves the snippet sitting at `path` for manual review/
    use. Skipped automatically for empty results or non-interactive stdin."""
    if not lines:
        return
    try:
        answer = input(
            f"[?] Append these {len(lines)} entries to /etc/hosts now? "
            f"(will prompt for sudo password) [y/N]: "
        ).strip().lower()
    except EOFError:
        return
    if answer not in ("y", "yes"):
        print(f"[i] skipped; snippet still saved at {path}", file=sys.stderr)
        return
    try:
        result = subprocess.run(
            ["sudo", "tee", "-a", "/etc/hosts"],
            input="\n".join(lines) + "\n",
            text=True,
            stdout=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[!] failed to append to /etc/hosts: {e}", file=sys.stderr)
        return
    if result.returncode == 0:
        print(f"[i] appended {len(lines)} entries to /etc/hosts", file=sys.stderr)
    else:
        print("[!] `sudo tee` returned a non-zero exit code; /etc/hosts may not have been updated", file=sys.stderr)


def pretty_print(rows, headers=("IP", "Hostnames")):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    # don't pad the last column, so lines don't end in trailing whitespace
    parts = [f"{{:<{w}}}" for w in widths[:-1]] + ["{}"]
    fmt = "  ".join(parts)
    print(fmt.format(*headers))
    for row in rows:
        print(fmt.format(*row))


def prompt_for_dns_server():
    """Interactively ask the user for a DNS server to use for all lookups.
    Only called when --dns-server wasn't given on the command line and
    --no-dns-prompt wasn't passed. Blank input means: use the system's
    default resolver (no server override)."""
    try:
        answer = input(
            "[?] DNS server to use for lookups (e.g. an internal AD DNS "
            "server), or press Enter to use the system default: "
        ).strip()
    except EOFError:
        # non-interactive stdin (e.g. piped input) - just skip the prompt
        return None
    return answer or None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("infile", nargs="?", default="ips.txt", help="file with one IP/hostname per line (default: ips.txt)")
    ap.add_argument("-w", "--workers", type=int, default=16, help="parallel lookups (default: 16)")
    ap.add_argument("-d", "--domain", help="fallback domain to try for bare NetBIOS names with no domain evidence elsewhere (default: auto-detect via dnsdomainname/resolv.conf/local FQDN)")
    ap.add_argument("--no-auto-domain", action="store_true", help="disable domain auto-detection; only use --domain if it's given")
    ap.add_argument("--no-nxc", action="store_true", help="skip nxc (NetExec) SMB-based hostname/domain resolution")
    ap.add_argument("--no-ntlm-info", action="store_true", help="skip the *-ntlm-info NSE script family (rdp/mssql/smtp/imap/pop3/http) for hostname/domain resolution")
    ap.add_argument("--no-smb-os", action="store_true", help="skip nmap smb-os-discovery (TCP/445) for hostname/domain resolution")
    ap.add_argument("--no-ssl-cert", action="store_true", help="skip nmap ssl-cert based hostname discovery (candidate names verified against reverse resolution before being trusted)")
    ap.add_argument("--ssl-ports", default="443", help="comma-separated ports to check for TLS certificates (default: 443)")
    ap.add_argument("-s", "--dns-server", help="DNS server to use for all forward/reverse lookups (default: prompt interactively, or the system's configured resolver if left blank)")
    ap.add_argument("--no-dns-prompt", action="store_true", help="don't interactively prompt for a DNS server if --dns-server wasn't given; just use the system default")
    ap.add_argument("-t", "--targets-out", default="targets.txt", help="where to write the derived target list: hostname(s) if resolved, else the IP (default: targets.txt; use '-' for stdout only, or 'none' to skip)")
    ap.add_argument("-o", "--hosts-out", default="hosts_snippet.txt", help="where to write the /etc/hosts-style snippet, one line per IP-hostname pair (default: hosts_snippet.txt; use 'none' to skip)")
    ap.add_argument("--no-hosts-prompt", action="store_true", help="don't interactively ask to append the snippet to /etc/hosts; just write the file")
    args = ap.parse_args()

    if not host_cmd_available():
        print(f"[!] {HOST_CMD_INSTALL_HINT}", file=sys.stderr)
        sys.exit(1)

    use_nxc = not args.no_nxc
    if use_nxc and not nxc_available():
        print(f"[i] {NXC_INSTALL_HINT}", file=sys.stderr)
        use_nxc = False
    elif use_nxc:
        print("[i] using nxc for SMB-based hostname/domain resolution", file=sys.stderr)

    use_ntlm = not args.no_ntlm_info
    if use_ntlm:
        script_list = ", ".join(s for s, _ in NTLM_INFO_SCRIPTS)
        print(f"[i] using ntlm-info scripts for hostname/domain resolution: {script_list}", file=sys.stderr)

    use_smb_os = not args.no_smb_os
    if use_smb_os:
        print("[i] using nmap smb-os-discovery (TCP/445) for hostname/domain resolution", file=sys.stderr)

    use_ssl_cert = not args.no_ssl_cert
    ssl_ports = [p.strip() for p in args.ssl_ports.split(",") if p.strip()]
    if use_ssl_cert:
        print(f"[i] using ssl-cert candidate hostnames (verified against reverse resolution) on port(s): {', '.join(ssl_ports)}", file=sys.stderr)

    dns_server = args.dns_server
    if not dns_server and not args.no_dns_prompt:
        dns_server = prompt_for_dns_server()
    if dns_server:
        print(f"[i] using DNS server: {dns_server}", file=sys.stderr)
    else:
        print("[i] using system default DNS resolver", file=sys.stderr)

    if args.domain:
        fallback_domain = args.domain.strip().lower()
    elif args.no_auto_domain:
        fallback_domain = None
    else:
        fallback_domain = detect_local_domain()

    if fallback_domain:
        print(f"[i] fallback domain: {fallback_domain}", file=sys.stderr)
    else:
        print("[i] no fallback domain available; bare NetBIOS names with no domain evidence stay unqualified", file=sys.stderr)

    try:
        with open(args.infile) as f:
            entries = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"[!] can't read input file '{args.infile}': {e.strerror}", file=sys.stderr)
        print("    pass the path to your target list, e.g.: python3 resolve.py /path/to/targets.txt", file=sys.stderr)
        sys.exit(1)

    if not entries:
        print(f"[!] '{args.infile}' has no entries to resolve", file=sys.stderr)
        sys.exit(1)

    rows = resolve_all(entries, args.workers, fallback_domain, use_nxc, dns_server,
                        use_ntlm, use_smb_os, use_ssl_cert, ssl_ports)
    pretty_print(rows)

    targets = build_target_list(rows)
    if args.targets_out.lower() != "none":
        if args.targets_out == "-":
            print(file=sys.stderr)
            print("\n".join(targets))
        else:
            with open(args.targets_out, "w") as f:
                f.write("\n".join(targets) + ("\n" if targets else ""))
            print(f"[i] wrote {len(targets)} target(s) to {args.targets_out}", file=sys.stderr)

    if args.hosts_out.lower() != "none":
        ip_to_hosts = build_hosts_entries(rows)
        hosts_lines = write_hosts_snippet(ip_to_hosts, args.hosts_out)
        print(f"[i] wrote {len(hosts_lines)} /etc/hosts line(s) to {args.hosts_out}", file=sys.stderr)
        print(file=sys.stderr)
        print("===== /etc/hosts snippet =====", file=sys.stderr)
        for line in hosts_lines:
            print(line, file=sys.stderr)
        print(file=sys.stderr)
        print("To append this snippet to /etc/hosts manually, run:", file=sys.stderr)
        print(f"    sudo tee -a /etc/hosts < {args.hosts_out} > /dev/null", file=sys.stderr)
        print(file=sys.stderr)
        if not args.no_hosts_prompt:
            prompt_append_to_hosts(args.hosts_out, hosts_lines)


if __name__ == "__main__":
    main()

def dependency_status():
    return {
        "host": shutil.which("host"),
        "nmap": shutil.which("nmap"),
        "nmblookup": shutil.which("nmblookup"),
        "nxc": shutil.which("nxc"),
    }


def resolve_for_bayabas(entries, dns_server=None, workers=16):
    status = dependency_status()
    if not status["host"]:
        raise RuntimeError(HOST_CMD_INSTALL_HINT)
    if not status["nmap"]:
        raise RuntimeError("nmap is required for Bayabas resolution.")

    rows = resolve_all(
        entries,
        workers=max(1, workers),
        fallback_domain=detect_local_domain(),
        use_nxc=bool(status["nxc"]),
        dns_server=dns_server,
        use_ntlm=True,
        use_smb_os=True,
        use_ssl_cert=False,
        ssl_ports=["443"],
    )

    mappings = set()
    for ip_col, host_col in rows:
        ips = [v.strip() for v in ip_col.lstrip("*").split(",")
               if v.strip() and v.strip() != "???"]
        hosts = [v.strip().rstrip(".").lower()
                 for v in host_col.lstrip("*").split(",")
                 if v.strip() and v.strip() != "???"]
        for address in ips:
            if not is_ip(address):
                continue
            for hostname in hosts:
                if hostname and not is_ip(hostname):
                    mappings.add((hostname, address, "core-resolve"))
    return rows, mappings
