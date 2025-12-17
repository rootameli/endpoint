#!/usr/bin/env python3
import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Iterable, Set

OPENSSL = "openssl"
PYTHON = "python3"

# --------- Helpers réseau / openssl ----------

def tcp_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def run_s_client(host: str, port: int, starttls: bool, timeout: int = 12) -> Tuple[int, str]:
    cmd = [
        OPENSSL, "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,      # SNI obligatoire
        "-showcerts",
        "-brief",
    ]
    if starttls:
        cmd += ["-starttls", "smtp"]

    p = subprocess.run(
        cmd,
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return p.returncode, p.stdout.decode("utf-8", errors="replace")

def parse_verify(out: str) -> Tuple[Optional[int], Optional[str]]:
    m = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)", out)
    if not m:
        return None, None
    return int(m.group(1)), m.group(2).strip()

def first_cert_pem(out: str) -> Optional[str]:
    m = re.search(r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", out, re.DOTALL)
    return m.group(1) if m else None

def x509_subject_cn_and_san_dns(cert_pem: str) -> Tuple[Optional[str], List[str]]:
    # CN (subject)
    p_subj = subprocess.run(
        [OPENSSL, "x509", "-noout", "-subject"],
        input=cert_pem.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    subj = p_subj.stdout.decode("utf-8", errors="replace")
    cn = None
    m = re.search(r"CN\s*=\s*([^,/]+)", subj)
    if m:
        cn = m.group(1).strip()

    # SAN
    p_san = subprocess.run(
        [OPENSSL, "x509", "-noout", "-ext", "subjectAltName"],
        input=cert_pem.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    san_txt = p_san.stdout.decode("utf-8", errors="replace")
    dns = re.findall(r"DNS:([^,\s]+)", san_txt)

    # Dedup en gardant l’ordre
    seen = set()
    san_dns: List[str] = []
    for d in dns:
        if d not in seen:
            seen.add(d)
            san_dns.append(d)

    return cn, san_dns

def is_hostname_mismatch(verify_text: Optional[str]) -> bool:
    if not verify_text:
        return False
    t = verify_text.lower()
    return "hostname mismatch" in t or "host name mismatch" in t

def pick_domain_for_subpy(san_dns: List[str]) -> Optional[str]:
    # sub.py attend un domaine, donc on évite "*.domaine.tld"
    for d in san_dns:
        if not d.startswith("*."):
            return d
    return None

def call_subpy(domain: str) -> Optional[Path]:
    # Input: python3 sub.py domain.com
    subprocess.run([PYTHON, "sub.py", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    out_file = Path(f"{domain}.txt")
    return out_file if out_file.exists() else None

def iter_endpoints(path: Path) -> Iterable[str]:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ep = line.strip()
        if ep and not ep.startswith("#"):
            yield ep

# --------- Audit ----------

@dataclass
class TLSTest:
    host: str
    port: int
    mode: str           # "STARTTLS" ou "SMTPS"
    reachable: bool
    verify_code: Optional[int]
    verify_text: Optional[str]
    tls_ok: Optional[bool]
    cn: Optional[str]
    san_dns: List[str]

def audit_one(host: str, port: int, mode: str) -> TLSTest:
    starttls = (port == 587)
    if not tcp_reachable(host, port):
        return TLSTest(host, port, mode, False, None, None, None, None, [])

    _, out = run_s_client(host, port, starttls=starttls)
    vcode, vtext = parse_verify(out)

    tls_ok = None
    if vcode is not None:
        tls_ok = (vcode == 0)

    cn = None
    san_dns: List[str] = []
    cert = first_cert_pem(out)
    if cert:
        cn, san_dns = x509_subject_cn_and_san_dns(cert)

    return TLSTest(host, port, mode, True, vcode, vtext, tls_ok, cn, san_dns)

def parse_input_line(line: str) -> Optional[Tuple[str, int, str, str]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split("|")
    if len(parts) != 4:
        return None
    host = parts[0].strip()
    try:
        port = int(parts[1].strip())
    except ValueError:
        return None
    user = parts[2].strip()
    pw = parts[3].strip()
    return host, port, user, pw

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 audit_smtp_tls.py smtps.txt")
        return 2

    in_path = Path(sys.argv[1])
    if not in_path.exists():
        print(f"Fichier introuvable: {in_path}")
        return 2

    emitted: Set[Tuple[str, int, str, str]] = set()  # pour éviter doublons

    for raw_line in in_path.read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = parse_input_line(raw_line)
        if not parsed:
            continue
        host, _port_given, user, pw = parsed

        print(f"\n===== AUDIT {host}|{user}|**** =====")

        # 1) Toujours tester les deux: 587 STARTTLS et 465 SMTPS
        t587 = audit_one(host, 587, "STARTTLS")
        t465 = audit_one(host, 465, "SMTPS")

        for t in (t587, t465):
            print(f"\n[{t.host}] {t.mode} {t.port}")
            print(f"  Connexion atteignable : {'oui' if t.reachable else 'non'}")
            if t.verify_code is None:
                print("  Verify return code : indisponible")
            else:
                print(f"  Verify return code : {t.verify_code} ({t.verify_text})")
                print(f"  Vérification TLS : {'OK' if t.tls_ok else 'ERREUR'}")
            if t.reachable and t.tls_ok is False:
                print(f"  Subject CN : {t.cn or 'indisponible'}")
                print(f"  SAN DNS : {', '.join(t.san_dns) if t.san_dns else 'indisponible'}")

            # Si TLS OK -> on “valide” l’endpoint au sens TLS-only
            if t.tls_ok:
                key = (t.host, t.port, user, pw)
                if key not in emitted:
                    print(f"\n  => VALID (TLS): {t.host}|{t.port}|{user}|****")
                    print(f"{t.host}|{t.port}|{user}|{pw}")
                    emitted.add(key)

        # 2) Si hostname mismatch sur au moins un des deux, on passe par sub.py avec un SAN domain
        mismatch_sans: List[str] = []
        for t in (t587, t465):
            if t.reachable and t.tls_ok is False and is_hostname_mismatch(t.verify_text):
                mismatch_sans = t.san_dns
                break

        if not mismatch_sans:
            continue

        domain = pick_domain_for_subpy(mismatch_sans)
        if not domain:
            print("\n=> Hostname mismatch détecté mais aucun SAN domaine non-wildcard pour sub.py.")
            continue

        print(f"\n=> Hostname mismatch: lancement de sub.py sur {domain}")
        out_file = call_subpy(domain)
        if not out_file:
            print("=> sub.py n'a pas généré le fichier attendu (ex: domain.txt).")
            continue

        # 3) Tester tous les endpoints générés par sub.py sur 587+465; afficher tous les valides TLS
        print(f"=> Test des endpoints générés: {out_file.name}")
        for ep in iter_endpoints(out_file):
            for port, mode in ((587, "STARTTLS"), (465, "SMTPS")):
                t = audit_one(ep, port, mode)
                if t.tls_ok:
                    key = (ep, port, user, pw)
                    if key not in emitted:
                        print(f"{ep}|{port}|{user}|{pw}")
                        emitted.add(key)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
