# Bayabas

Authorized Nmap orchestration and configuration-audit framework.

## Runtime structure

```text
Host_DB/
├── IPv4/
│   ├── hosts_ports.sqlite3
│   ├── host_port.txt
│   ├── hostname_ip_mapping.txt
│   └── resolutions.txt
└── IPv6/
    ├── hosts_ports.sqlite3
    ├── host_port.txt
    ├── hostname_ip_mapping.txt
    └── resolutions.txt
```

```text
Scans/<assessment_id>/
├── assessment.json
├── IPv4/
│   ├── Discovery/
│   ├── Initial/
│   │   ├── tcp_ports.txt
│   │   ├── udp_ports.txt
│   │   └── ini_scan_live_hosts.txt
│   └── Final/
└── IPv6/
    ├── Discovery/
    ├── Initial/
    │   ├── tcp_ports.txt
    │   ├── udp_ports.txt
    │   └── ini_scan_live_hosts.txt
    └── Final/
```

IPv4 and IPv6 final scans are started simultaneously in independent GNU Screen
sessions. Bayabas monitors completion and emits a terminal alert for each job.

## Findings

Modules write under:

```text
Findings/<Module>/IPv4/
Findings/<Module>/IPv6/
```

A finding directory or output file is created only after validated evidence
exists. Empty scans, negative checks, module failures, and unconfirmed
conditions do not create finding output.

SSL findings are separated into:

```text
Findings/SSL/<IPv4-or-IPv6>/
├── Weak TLS-SSL Cipher/
├── Insecure TLS Versions/
└── Insecure SSL Certificate/
```

## Interactive run

```bash
sudo python3 bayabas.py targets.txt
```

## Non-interactive example

```bash
sudo python3 bayabas.py targets.txt \
  --ipv6 \
  --host-discovery \
  --quick \
  --dns-server 192.0.2.53 \
  --max-retries 2 \
  --max-scan-delay 1s \
  --min-parallelism 10 \
  --mtu 24 \
  --min-rate 100 \
  --max-hostgroup 64 \
  --ipv4-final-output ipv4_final \
  --ipv6-final-output ipv6_final \
  --run-modules \
  --non-interactive
```

Only scan systems for which you have explicit authorization.


## Source-only repository

The Git repository and release ZIP contain only source files:

```text
bayabas/
├── bayabas.py
├── Modules/
│   ├── __init__.py
│   ├── cipher.py
│   └── ssh.py
├── readme.md
└── .gitignore
```

`Scans/`, `Host_DB/`, and `Findings/` are not packaged or committed.

After an assessment begins, Bayabas creates:

```text
Scans/<assessment_id>/
├── assessment.json
├── Host_DB/
│   ├── IPv4/
│   └── IPv6/
├── Findings/
├── IPv4/
└── IPv6/
```

Module-specific finding folders are created only when validated findings exist.
