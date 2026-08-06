"""SSH configuration audit using Nmap safe/discovery NSE scripts."""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

NAME = "SSH"

WEAK = {
    "key_exchange": {
        "diffie-hellman-group1-sha1": "Diffie-Hellman group 1 (1024-bit / Logjam exposure)",
        "diffie-hellman-group14-sha1": "SHA-1 based Diffie-Hellman group 14",
        "diffie-hellman-group-exchange-sha1": "SHA-1 based group exchange",
    },
    "server_host_key": {
        "ssh-dss": "1024-bit DSS host key",
        "ssh-rsa": "SHA-1 based SSH-RSA host signature",
    },
    "encryption": {
        "3des-cbc": "3DES",
        "des-cbc": "DES",
        "arcfour": "RC4",
        "arcfour128": "RC4",
        "arcfour256": "RC4",
        "blowfish-cbc": "Blowfish CBC",
        "cast128-cbc": "CAST CBC",
    },
    "mac": {
        "hmac-md5": "HMAC-MD5",
        "hmac-md5-96": "HMAC-MD5-96",
        "hmac-sha1": "HMAC-SHA1",
        "hmac-sha1-96": "HMAC-SHA1-96",
    },
}
PQ_KEX_MARKERS = (
    "mlkem", "sntrup", "ntru", "kyber"
)


def latest_ssh_targets(context) -> list[tuple[str, int]]:
    with context.connect() as db:
        rows = db.execute(
            """
            SELECT h.address, p.port
            FROM hosts h JOIN ports p ON p.host_id=h.id
            WHERE h.scan_id=? AND p.state='open' AND p.protocol='tcp'
              AND (lower(p.service)='ssh' OR p.port=22)
            ORDER BY h.address,p.port
            """,
            (context.scan_id,),
        ).fetchall()
    return [(row["address"], int(row["port"])) for row in rows]


def parse_script_output(xml_path: Path) -> tuple[str, dict[str, list[str]], bool]:
    root = ET.parse(xml_path).getroot()
    raw_parts: list[str] = []
    categories: dict[str, list[str]] = {
        "key_exchange": [], "server_host_key": [], "encryption": [], "mac": []
    }
    sshv1 = False

    for script in root.findall(".//script"):
        sid = script.get("id", "")
        output = script.get("output", "")
        raw_parts.append(f"{sid}:\n{output}")
        if sid == "sshv1" and re.search(r"(?i)(supported|server supports sshv1)", output):
            sshv1 = True
        if sid != "ssh2-enum-algos":
            continue

        # Structured XML tables are preferred.
        mapping = {
            "kex_algorithms": "key_exchange",
            "server_host_key_algorithms": "server_host_key",
            "encryption_algorithms": "encryption",
            "mac_algorithms": "mac",
            "encryption_algorithms_client_to_server": "encryption",
            "encryption_algorithms_server_to_client": "encryption",
            "mac_algorithms_client_to_server": "mac",
            "mac_algorithms_server_to_client": "mac",
        }
        for table in script.iter("table"):
            key = table.get("key", "")
            target = mapping.get(key)
            if not target:
                continue
            for elem in table.findall("elem"):
                if elem.text:
                    categories[target].append(elem.text.strip())

        # Fallback for Nmap versions that expose only text output.
        section = None
        for line in output.splitlines():
            clean = line.strip(" |_")
            for marker, target in mapping.items():
                if clean.startswith(marker):
                    section = target
                    break
            else:
                token = clean.strip()
                if section and token and not token.startswith("("):
                    token = re.sub(r"\s+\(\d+\)$", "", token)
                    if re.fullmatch(r"[A-Za-z0-9@._+\-/]+", token):
                        categories[section].append(token)

    for key in categories:
        categories[key] = sorted(set(categories[key]))
    return "\n\n".join(raw_parts), categories, sshv1


def assess(categories: dict[str, list[str]], sshv1: bool) -> dict[str, Any]:
    issues: dict[str, Any] = {}
    for group, algorithms in categories.items():
        weak = []
        for algorithm in algorithms:
            lower = algorithm.lower()
            if lower in WEAK[group]:
                weak.append(f"{algorithm}: {WEAK[group][lower]}")
            if group == "encryption" and "-cbc" in lower:
                weak.append(f"{algorithm}: CBC-mode encryption")
            if group == "mac" and lower.endswith("-etm@openssh.com") and "sha1" in lower:
                weak.append(f"{algorithm}: SHA-1 Encrypt-then-MAC")
        if weak:
            issues[group] = sorted(set(weak))

    kex = [x.lower() for x in categories["key_exchange"]]
    issues["no_post_quantum_kex"] = not any(
        marker in alg for alg in kex for marker in PQ_KEX_MARKERS
    )
    issues["ssh_v1"] = sshv1

    encryption = [x.lower() for x in categories["encryption"]]
    macs = [x.lower() for x in categories["mac"]]
    # Conservative configuration-only indicator, not a vulnerability proof:
    # Terrapin is potentially relevant when ChaCha20-Poly1305 or CBC with
    # Encrypt-then-MAC is negotiated.
    chacha = any("chacha20-poly1305" in x for x in encryption)
    cbc = any("-cbc" in x for x in encryption)
    etm = any("-etm@" in x for x in macs)
    issues["possible_terrapin_configuration"] = chacha or (cbc and etm)
    return issues


def render_finding(host_results: list[dict[str, Any]], template: str) -> str:
    affected_groups = sorted({
        group
        for item in host_results
        for group in ("key_exchange", "server_host_key", "encryption", "mac")
        if item["issues"].get(group)
    })
    names = {
        "key_exchange": "key exchange",
        "server_host_key": "server host key",
        "encryption": "encryption",
        "mac": "message authentication code (MAC)",
    }
    scope = ", ".join(names[x] for x in affected_groups) or "one or more SSH algorithm groups"
    summary = template.replace(
        "[all of the above |{REMOVE THOSE THAT ARE NOT RELEVANT the key exchange, server host key, encryption, and message authentication code (MAC) algorithms}.]",
        scope,
    )
    details = ["", "Detected configuration:", ""]
    for item in host_results:
        details.append(f"{item['host']}, {item['port']}")
        for group in ("key_exchange", "server_host_key", "encryption", "mac"):
            for issue in item["issues"].get(group, []):
                details.append(f"  - {group}: {issue}")
        if item["issues"].get("ssh_v1"):
            details.append("  - SSH protocol version 1 appears enabled")
        if item["issues"].get("no_post_quantum_kex"):
            details.append("  - No post-quantum key exchange algorithm observed")
        if item["issues"].get("possible_terrapin_configuration"):
            details.append(
                "  - Potential Terrapin-relevant algorithm combination observed; "
                "confirm server/client strict key exchange support and patch status"
            )
        details.append("")
    return summary.strip() + "\n" + "\n".join(details)


def run(context) -> int:
    targets = latest_ssh_targets(context)
    if not targets:
        return 0

    out_dir = context.finding_dir("SSH")
    template_path = out_dir / "template.txt"
    template = template_path.read_text(encoding="utf-8") if template_path.exists() else ""
    results: list[dict[str, Any]] = []
    raw_samples: list[str] = []

    for host, port in targets:
        xml = out_dir / f".{host.replace(':', '_')}_{port}.xml"
        command = [
            context.nmap_path, "-Pn", "-sV", "-p", str(port),
            "--script", "ssh2-enum-algos,sshv1", "-oX", str(xml), host
        ]
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if not xml.exists():
            continue
        raw, categories, sshv1 = parse_script_output(xml)
        issues = assess(categories, sshv1)
        meaningful = any(issues.get(x) for x in (
            "key_exchange", "server_host_key", "encryption", "mac",
            "ssh_v1", "possible_terrapin_configuration"
        ))
        # Lack of PQ KEX is reported only when another weak condition exists,
        # preventing every conventional SSH endpoint from becoming a finding.
        if meaningful:
            results.append({"host": host, "port": port, "issues": issues})
            if not raw_samples:
                raw_samples.append(
                    f"$ {' '.join(command[:-3])} -oX <file> {host}\n"
                    f"{completed.stdout}\n{raw}"
                )
        try:
            xml.unlink()
        except OSError:
            pass

    if not results:
        return 0

    (out_dir / "affected_host.txt").write_text(
        "".join(f"{x['host']}, {x['port']}\n" for x in results), encoding="utf-8"
    )
    weak_lines = []
    for result in results:
        weak_lines.append(f"{result['host']}, {result['port']}")
        for group in ("key_exchange", "server_host_key", "encryption", "mac"):
            values = result["issues"].get(group, [])
            if values:
                weak_lines.append(f"  {group}:")
                weak_lines.extend(f"    - {x}" for x in values)
        if result["issues"].get("possible_terrapin_configuration"):
            weak_lines.append("  possible_terrapin_configuration: yes")
    (out_dir / "weak_configuration.txt").write_text(
        "\n".join(weak_lines) + "\n", encoding="utf-8"
    )
    (out_dir / "raw_output.txt").write_text(
        "\n\n".join(raw_samples) + "\n", encoding="utf-8"
    )
    (out_dir / "finding.txt").write_text(
        render_finding(results, template), encoding="utf-8"
    )
    return len(results)
