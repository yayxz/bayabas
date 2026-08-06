"""SSH configuration audit using Nmap safe/discovery NSE scripts."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

WEAK = {
    "key_exchange": {
        "diffie-hellman-group1-sha1": "Diffie-Hellman group 1",
        "diffie-hellman-group14-sha1": "SHA-1 based Diffie-Hellman group 14",
        "diffie-hellman-group-exchange-sha1": "SHA-1 based group exchange",
    },
    "server_host_key": {
        "ssh-dss": "DSS host key",
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


def targets(context) -> list[tuple[str, int]]:
    with context.connect() as db:
        rows = db.execute(
            """
            SELECT h.address,p.port
            FROM hosts h JOIN ports p ON p.host_id=h.id
            WHERE h.scan_id=? AND p.state='open' AND p.protocol='tcp'
              AND (lower(p.service)='ssh' OR p.port=22)
            ORDER BY h.address,p.port
            """,
            (context.scan_id,),
        ).fetchall()
    return [(row["address"], int(row["port"])) for row in rows]


def parse(xml_path: Path) -> tuple[str, dict[str, list[str]], bool]:
    root = ET.parse(xml_path).getroot()
    categories = {"key_exchange": [], "server_host_key": [], "encryption": [], "mac": []}
    raw = []
    sshv1 = False
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
    for script in root.findall(".//script"):
        sid = script.get("id", "")
        output = script.get("output", "")
        if output:
            raw.append(f"{sid}:\n{output}")
        if sid == "sshv1" and re.search(r"(?i)\bsupported\b", output):
            sshv1 = True
        if sid != "ssh2-enum-algos":
            continue
        for table in script.iter("table"):
            group = mapping.get(table.get("key", ""))
            if group:
                categories[group].extend(
                    elem.text.strip() for elem in table.findall("elem") if elem.text
                )
    for group in categories:
        categories[group] = sorted(set(categories[group]))
    return "\n\n".join(raw), categories, sshv1


def assess(categories: dict[str, list[str]], sshv1: bool) -> dict[str, Any]:
    issues: dict[str, Any] = {}
    for group, algorithms in categories.items():
        values = []
        for algorithm in algorithms:
            lower = algorithm.lower()
            if lower in WEAK[group]:
                values.append(f"{algorithm}: {WEAK[group][lower]}")
            if group == "encryption" and "-cbc" in lower:
                values.append(f"{algorithm}: CBC-mode encryption")
        if values:
            issues[group] = sorted(set(values))
    issues["ssh_v1"] = sshv1

    encryption = [x.lower() for x in categories["encryption"]]
    macs = [x.lower() for x in categories["mac"]]
    # Indicator only when both sides of the known vulnerable configuration pattern exist.
    issues["possible_terrapin_configuration"] = (
        any("chacha20-poly1305" in x for x in encryption)
        or (
            any("-cbc" in x for x in encryption)
            and any("-etm@" in x for x in macs)
        )
    )
    return issues


def remove_stale(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def run(context) -> int:
    candidates = targets(context)
    family_root = context.findings_dir / "SSH" / context.family_label
    remove_stale(family_root)
    if not candidates:
        return 0

    results = []
    evidence = ""
    with tempfile.TemporaryDirectory(prefix="bayabas_ssh_") as temporary:
        temp = Path(temporary)
        for host, port in candidates:
            xml = temp / f"{host.replace(':', '_')}_{port}.xml"
            command = [
                context.nmap_path,
                *(["-6"] if context.family == 6 else []),
                "-Pn", "-sV", "-p", str(port),
                "--script", "ssh2-enum-algos,sshv1",
                "-oX", str(xml), host,
            ]
            completed = subprocess.run(
                command, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False
            )
            if not xml.exists():
                continue
            raw, categories, sshv1 = parse(xml)
            issues = assess(categories, sshv1)
            meaningful = any(issues.get(key) for key in (
                "key_exchange", "server_host_key", "encryption", "mac",
                "ssh_v1", "possible_terrapin_configuration",
            ))
            if not meaningful:
                continue
            results.append((host, port, issues))
            if not evidence:
                evidence = f"$ {' '.join(command)}\n\n{completed.stdout}\n{raw}"

    if not results:
        return 0

    family_root.mkdir(parents=True)
    (family_root / "affected_hosts.txt").write_text(
        "".join(f"{host}, {port}\n" for host, port, _ in results),
        encoding="utf-8",
    )
    lines = []
    for host, port, issues in results:
        lines.append(f"{host}, {port}")
        for group in ("key_exchange", "server_host_key", "encryption", "mac"):
            if issues.get(group):
                lines.append(f"  {group}:")
                lines.extend(f"    - {value}" for value in issues[group])
        if issues.get("ssh_v1"):
            lines.append("  ssh_v1: enabled")
        if issues.get("possible_terrapin_configuration"):
            lines.append("  possible_terrapin_configuration: review patch and strict-kex support")
    (family_root / "weak_configuration.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (family_root / "raw_output.txt").write_text(evidence + "\n", encoding="utf-8")
    return len(results)
