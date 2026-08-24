# Bayabas v0.10.12

The selected output directory is the single engagement root:

```text
SD/
├── assessment.json
├── Database/
│   ├── IPv4/
│   │   ├── hosts_ports.sqlite3
│   │   ├── host_port.txt
│   │   ├── hosts.txt
│   │   ├── ports-per-host.txt
│   │   ├── live-hosts.txt
│   │   ├── service-frequency.txt
│   │   ├── tcp-ports.txt
│   │   ├── udp-ports.txt
│   │   ├── hostname_ip_mapping.txt
│   │   └── resolutions.txt
│   └── IPv6/
├── Scans/
│   ├── IPv4/
│   └── IPv6/
└── Findings/
    ├── SSL/
    └── SSH/
```

`Core/resolve.py` runs before scans/modules and prompts once for DNS through
the main launcher. Required dependencies are `nmap` and `host`; `nmblookup`
and `nxc` are optional enrichment.

Python dependencies (`cryptography` for `cipher.py`, `dnspython` for
`caa.py`/`dnssec.py`) can be installed up front with:

```text
pip install -r requirements.txt --break-system-packages
```

or left alone -- each module offers to install its own dependency the
first time it's run if it's missing.

Imported Nmap inventories create a deduplicated address-only `hosts.txt`.

Wildcard certificates are reported separately:

```text
Findings/SSL/IPv4/Wildcard SSL Certificate/
├── affected_hosts.txt
├── wildcard_certificates.txt
└── evidence.txt
```


## v0.10.5 httpx fix

`Modules/cipher.py` now uses `~/go/bin/httpx` directly when present, without
requiring `~/go/bin` to be exported into PATH.

httpx targets are derived from the normalized Database inventory:
- every open TCP endpoint
- preferred resolved hostname for each address when available
- IP fallback when no hostname is known

The module reports the httpx binary path, input endpoint count, exit code,
JSON-record count, and HTTPS endpoint count. Nmap TLS checks still run against
all open TCP ports regardless of httpx results.


## v0.10.6

`live-hosts.txt` now prefers verified FQDNs. If only a bare computer name is
known, Core/resolve.py tries parent domains observed elsewhere in the
engagement and only accepts the FQDN when it resolves back to the same IP.
If no FQDN is verified, the bare name is kept; if no name exists, the IP is
used.

`hosts.txt` remains IP-only.

The httpx stage now persists reusable web inventory:

```text
Scans/IPv4/httpx/
├── targets.txt
├── httpx_result.txt
└── urls.txt
```

`urls.txt` is deduplicated and can be passed directly to tools such as nuclei.


## v0.10.8 /etc/hosts-ready file

After resolution and database normalization, Bayabas creates
`Database/<family>/etc-hosts.txt` only when verified FQDN/IP mappings exist.
Bare computer names and unresolved IPs are excluded.

The resolver already learns parent domains from other resolved hosts and tries
those domains against bare names. Such an inferred FQDN is retained only when
it resolves back to the same IP.

Bayabas prints an optional append command but does not modify `/etc/hosts`.


## v0.10.9 CAA and DNSSEC modules

Two new configuration-audit modules, discovered the same way as `cipher`
and `ssh`:

```text
Findings/CAA/IPv4/
└── Missing CAA Record/
    ├── affected_hosts.txt
    └── evidence.txt

Findings/DNSSEC/IPv4/
├── DNSSEC Not Supported/
│   ├── affected_hosts.txt
│   └── evidence.txt
└── DNSSEC Misconfigured/
    ├── affected_hosts.txt
    └── evidence.txt
```

Both modules pull their targets from the verified FQDNs already recorded
in `Database/<family>/resolutions.txt` rather than the open-port
inventory, since CAA and DNSSEC are DNS-level properties, not tied to a
specific open service.

`Modules/caa.py` resolves the effective CAA record per RFC 8659 walk-up
(CNAME-aware, public-suffix aware), the same logic as the standalone
`checkCaaRecords.py` script.

`Modules/dnssec.py` evaluates DNSSEC at each hostname's registrable zone
apex (not per subdomain), combining DS/DNSKEY presence with an AD-flag
confirmation against a known-validating public resolver (1.1.1.1 by
default) so a non-validating resolver on the engagement network can't
produce false "not supported" findings. A SERVFAIL response is treated as
a "Misconfigured" finding (broken chain), distinct from "Not Supported"
(no DNSSEC configured at all) and from an inconclusive DNS error, which
is never reported as a finding.

Both modules require `dnspython` and will offer to `pip install` it on
first run if missing, matching the `cryptography`/`httpx` prompts already
used by `cipher.py`. If declined or unavailable in a non-interactive run,
the module prints a notice and skips cleanly rather than failing the
batch.


## v0.10.10 Target resolution fixes

Two bugs fixed in target handling during `main()`:

1. **`dns` variable read-before-assignment.** The interactive DNS-server
   prompt block read the `dns` variable before it was ever assigned in
   that scope, which raises `UnboundLocalError` in Python regardless of
   whether a custom server was supplied. Fixed by assigning
   `dns = args.dns_server` before the prompt check instead of after.

2. **`resolve_hostname()` ignored the configured DNS server and had no
   timeout.** `split_targets()` -- which runs immediately after "Run
   IPv6 scans (-6) as well?" -- resolved every hostname target via
   `socket.getaddrinfo()`, which always uses the system's default
   resolver and silently ignores whatever DNS server was set at the
   earlier prompt (that value was only ever passed to the separate
   `Core/resolve.py` preflight pass). It also had no timeout, so a
   hostname that only resolves through the configured server, or that
   simply doesn't resolve promptly, could hang the whole run
   indefinitely with no error and no indication anything was wrong.

   `resolve_hostname()` now takes an optional `dns_server` and a
   `timeout` (default 5s). With a server configured, it queries that
   server explicitly via the same `host` command `Core/resolve.py`
   already uses, bounded by `subprocess.run(..., timeout=...)`. Without
   one, it still uses the system resolver for ordinary
   internet-accessible hostnames, but bounded via a worker thread since
   `socket.getaddrinfo()` doesn't honor `socket.setdefaulttimeout()`.
   Either way, a failed or slow lookup is logged and treated as
   unresolved instead of blocking the tool. `split_targets()`,
   `collect_family_mappings()`, and `parse_existing_nmap()` all now
   thread the configured `dns_server` through consistently.


## v0.10.11 requirements.txt

Added `requirements.txt` covering the project's pip dependencies
(`cryptography`, `dnspython`) so they can all be installed in one shot
with `pip install -r requirements.txt --break-system-packages` instead of
being prompted per module on first use. Non-pip dependencies (`nmap`,
`host`, `screen`, `nmblookup`, `nxc`, and the Go-based `httpx` binary used
by `cipher.py`, not the PyPI package of the same name) are documented in
the file as comments but are intentionally not part of the pip install,
since pip can't provide them.


## v0.10.12 Malformed target resilience

`load_targets()` previously called `classify_target()` purely to validate
each line, letting the resulting `ValueError` propagate uncaught -- a
single malformed entry anywhere in the targets file (invalid syntax, a
stray unexpanded shell variable like `$web.s3.amazonaws.com`, etc.)
crashed the entire run before it even started, regardless of how many
valid targets were also in the file. Now each entry is validated
individually; invalid ones are skipped and reported together in one
`[!] Skipped N invalid target(s): ...` line, and the run proceeds with
everything that's actually valid. It only still dies if literally nothing
in the file was valid.
