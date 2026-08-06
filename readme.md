# bayabas

Authorized Nmap scan orchestration and configuration-audit framework.

## Structure

```text
bayabas/
├── bayabas.py
├── readme.md
├── Host_DB/
│   ├── host_port.txt
│   └── hosts_ports.sqlite3
├── Modules/
│   ├── ssh.py
│   └── cipher.py
├── Findings/
│   ├── SSH/
│   │   └── template.txt
│   └── SSL/
│       ├── TLSv10-11/
│       └── Insecure_SSL/
└── Scans/
```

## Requirements

- Python 3.10+
- Nmap with its standard NSE script library
- GNU Screen
- Root privileges are recommended for SYN, UDP, MTU/fragmentation, and complete
  host-discovery behavior.

## Interactive use

```bash
cd bayabas
sudo ./bayabas.py 192.168.56.0/24
sudo ./bayabas.py '10.0.0.10,host.lab,10.0.1.0/24'
sudo ./bayabas.py targets.txt
```

The program asks whether to:

1. Run host discovery first.
2. Use quick scanning (`-F`).
3. Use explicit ports instead.
4. Set Nmap timing and packet parameters.
5. Execute the installed configuration-audit modules.

When host discovery is selected, the program runs Nmap `-sn --reason` first and
extracts only XML hosts with state `up`. The port scan then uses that generated
target list with `-Pn`, avoiding a redundant second discovery phase.

## Port input

```text
T:22,80,443
U:53,123,161
T:22,80,U:53,161
-
top100
top1000
```

`-` means all TCP ports. Quick scan uses Nmap `-F`, which scans approximately the
100 most common ports for each requested protocol.

## Non-interactive example

```bash
sudo ./bayabas.py 192.168.56.0/24 \
  --host-discovery \
  --quick \
  --dns-server 192.168.56.1 \
  --max-retries 2 \
  --max-scan-delay 1s \
  --min-parallelism 10 \
  --mtu 24 \
  --min-rate 100 \
  --max-hostgroup 64 \
  --run-modules \
  --non-interactive
```

## Outputs

`Host_DB/host_port.txt` uses the requested flat format:

```text
host-or-ip, port
```

The SQLite database retains scan IDs, hostnames, protocols, states, services,
products, versions, and TLS tunnel metadata. Modules use the latest scan ID so
older scan data does not contaminate current findings.

Raw Nmap scan output is retained in `Scans/<timestamp>/`.

## SSH module

The SSH module selects ports identified as SSH, plus TCP/22 as a fallback, and
runs only Nmap safe/discovery scripts:

```text
ssh2-enum-algos
sshv1
```

It checks key exchange, host key, encryption, and MAC algorithms for known weak
or legacy choices. It also records a conservative "possible Terrapin
configuration" indicator where ChaCha20-Poly1305 or CBC plus Encrypt-then-MAC is
advertised. This is not treated as proof of exploitability; patch level and
strict key exchange support must still be verified.

Outputs:

```text
Findings/SSH/affected_host.txt
Findings/SSH/weak_configuration.txt
Findings/SSH/raw_output.txt
Findings/SSH/finding.txt
```

## TLS module

The TLS module selects likely TLS services and runs:

```text
ssl-enum-ciphers
ssl-dh-params
```

It separates TLS 1.0/1.1 findings from weak cipher/configuration findings and
deduplicates cipher names.

Outputs:

```text
Findings/SSL/TLSv10-11/affected_hosts.txt
Findings/SSL/TLSv10-11/raw_output.txt
Findings/SSL/Insecure_SSL/affected_hosts.txt
Findings/SSL/Insecure_SSL/weak_ciphers.txt
Findings/SSL/Insecure_SSL/raw_output.txt
```

## Safety and interpretation

The modules enumerate server-advertised cryptographic configuration; they do
not authenticate, brute-force credentials, exploit vulnerabilities, or modify
targets. Findings should be manually validated before reporting because service
detection, middleboxes, protocol negotiation, and Nmap/NSE versions can affect
results.

## httpx web-service normalization before TLS checks

The cipher module now treats the parent scan database as the source of truth and
performs a web-service normalization phase before running TLS NSE scripts:

1. Every open TCP `host, port` record from the current scan is converted to
   ProjectDiscovery httpx input as `host:port` (IPv6 literals use `[address]:port`).
2. The module verifies that the executable is ProjectDiscovery `httpx`.
3. If it is missing, an interactive user is prompted before any installation.
   When approved, the module installs the latest stable Go toolchain under
   `~/.local/go` if Go is absent, verifies the official archive SHA-256, and then
   installs `github.com/projectdiscovery/httpx/cmd/httpx@latest` under
   `~/go/bin/httpx`.
4. httpx probes both HTTP and HTTPS and writes stdout, stderr, command, and exit
   status to `Findings/SSL/httpx_result.txt`.
5. Only endpoints positively returned as `https://` are passed to
   `ssl-enum-ciphers` and `ssl-dh-params`.

Supporting files:

```text
Findings/SSL/httpx_input.txt
Findings/SSL/httpx_result.txt
Findings/SSL/httpx_install.log   # created when installation is offered
```

Legacy protocol reporting now includes SSLv2, SSLv3, TLSv1.0, and TLSv1.1.

## Three-stage scan pipeline

The framework now uses up to three network scan stages:

1. **Optional host discovery**: `nmap -sn --reason` identifies responsive targets.
2. **Initial port scan**: scans the user-selected TCP/UDP scope without `-sV` and records only open ports.
3. **Final service scan**: scans only hosts that had an open port and only the unique ports found in the initial scan, with service/version detection enabled.

The initial scan writes these files beneath `Scans/<timestamp>/`:

```text
tcp_ports.txt
udp_ports.txt
ini_scan_live_hosts.txt
```

The port files contain comma-separated, numerically sorted unique ports. The live-host file contains only IP addresses for hosts with at least one open TCP or UDP port.

The final command is built in this form:

```bash
nmap --open -v --resolve-all -n -Pn \
  -iL Scans/<timestamp>/ini_scan_live_hosts.txt \
  -sV -sS -sU \
  -p T:22,80,443,U:53,161 \
  <timing flags> \
  -oA /required/output/path/name
```

The TCP scan mode is `-sS` when privileged and `-sT` otherwise. `-sU` is included only when the initial scan found open UDP ports.

The final output base is mandatory. In interactive mode the framework asks for a directory and base name. In non-interactive mode use:

```bash
--final-output /engagement/results/client_final
```

The parent directory must already exist. The framework refuses to start the final scan if the base path or any corresponding `.nmap`, `.xml`, or `.gnmap` file already exists.
