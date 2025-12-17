#!/usr/bin/env python3
"""
Analyse TLS de serveurs SMTP via openssl, test d'envoi en TLS avec fallback sur SAN/CN
et énumération de sous-domaines via sub.py en cas de problème de certificat.
"""
from __future__ import annotations

import re
import smtplib
import ssl
import subprocess
import sys
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
INPUT_FILE = SCRIPT_DIR / "smtps.txt"
OUTPUT_FILE = SCRIPT_DIR / "validated_endpoints.txt"
DEFAULT_TIMEOUT = 15


@dataclass
class Endpoint:
    host: str
    port: int
    username: str
    password: str

    def as_line(self) -> str:
        return f"{self.host}|{self.port}|{self.username}|{self.password}"


@dataclass
class TLSCheck:
    port: int
    starttls: bool
    reachable: bool
    verify_code: Optional[int]
    verify_text: Optional[str]
    cn: Optional[str]
    san: List[str]
    raw_output: str


def parse_verify(output: str) -> Tuple[Optional[int], Optional[str]]:
    match = re.search(r"Verify return code: (\d+) \(([^)]*)\)", output)
    if not match:
        return None, None
    return int(match.group(1)), match.group(2)


def parse_certificate_names(output: str) -> Tuple[Optional[str], List[str]]:
    cn_match = re.search(r"subject=.*?CN\s*=\s*([^/\n]+)", output)
    cn = cn_match.group(1).strip() if cn_match else None

    san_matches = re.findall(r"DNS:([^,\s]+)", output)
    san = [entry.strip() for entry in san_matches if entry.strip()]

    return cn, san


def run_s_client(host: str, port: int, starttls: bool, timeout: int = DEFAULT_TIMEOUT) -> TLSCheck:
    cmd = [
        "openssl",
        "s_client",
        "-servername",
        host,
        "-verify_hostname",
        host,
        "-connect",
        f"{host}:{port}",
    ]
    if starttls:
        cmd.extend(["-starttls", "smtp"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return TLSCheck(
            port=port,
            starttls=starttls,
            reachable=False,
            verify_code=None,
            verify_text=str(exc),
            cn=None,
            san=[],
            raw_output=str(exc),
        )

    combined_output = (result.stdout or "") + "\n" + (result.stderr or "")
    reachable = "CONNECTED" in combined_output or result.returncode == 0
    verify_code, verify_text = parse_verify(combined_output)
    cn, san = parse_certificate_names(combined_output)

    return TLSCheck(
        port=port,
        starttls=starttls,
        reachable=reachable,
        verify_code=verify_code,
        verify_text=verify_text,
        cn=cn,
        san=san,
        raw_output=combined_output,
    )


def print_tls_result(endpoint: Endpoint, check: TLSCheck) -> None:
    mode = "STARTTLS" if check.starttls else "SMTPS"
    print(f"\n[{endpoint.host}] Test {mode} sur {check.port}")
    print(f"  Connexion atteignable : {'oui' if check.reachable else 'non'}")
    if check.verify_code is not None:
        print(f"  Verify return code : {check.verify_code} ({check.verify_text})")
        if check.verify_code == 0:
            print("  Vérification TLS : OK")
        else:
            print("  Vérification TLS : ERREUR")
    else:
        print("  Verify return code : indisponible")

    if check.verify_code not in (None, 0):
        if check.cn:
            print(f"  Subject CN : {check.cn}")
        if check.san:
            print(f"  SAN : {', '.join(check.san)}")


def send_test_email(host: str, port: int, username: str, password: str, recipient: str) -> bool:
    context = ssl.create_default_context()
    sender = username or f"tester@{host}"
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = "SMTP TLS test"
    msg.set_content("Test automatique de connexion SMTP sécurisée.")

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=DEFAULT_TIMEOUT, context=context) as smtp:
                smtp.ehlo()
                if username:
                    smtp.login(username, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=DEFAULT_TIMEOUT) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                if username:
                    smtp.login(username, password)
                smtp.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"  Échec d'envoi via {host}:{port} ({exc})")
        return False


def save_validated(endpoint: Endpoint) -> None:
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("a", encoding="utf-8") as fh:
        fh.write(endpoint.as_line() + "\n")


def derive_root_domain(name: str) -> str:
    clean = name[2:] if name.startswith("*.") else name
    parts = clean.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return clean


def run_sub_enum(domain: str, timeout: int = DEFAULT_TIMEOUT * 8) -> List[str]:
    cmd = [sys.executable, "sub.py", domain]
    try:
        result = subprocess.run(
            cmd,
            cwd=SCRIPT_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"  Impossible d'exécuter sub.py ({exc})")
        return []

    if result.stdout:
        print("  sub.py output:")
        print(result.stdout.strip())
    if result.stderr:
        print("  sub.py stderr:")
        print(result.stderr.strip())

    output_file = SCRIPT_DIR / f"{domain}.txt"
    if not output_file.exists():
        return []
    return [line.strip() for line in output_file.read_text(encoding="utf-8").splitlines() if line.strip()]


def collect_candidates(checks: Sequence[TLSCheck]) -> List[str]:
    candidates: List[str] = []
    seen: set[str] = set()

    for check in checks:
        if check.verify_code in (None, 0):
            continue
        for name in ([check.cn] if check.cn else []):
            if name not in seen:
                candidates.append(name)
                seen.add(name)
        for name in check.san:
            if name not in seen:
                candidates.append(name)
                seen.add(name)
    return candidates


def try_candidates(candidates: Sequence[str], base_endpoint: Endpoint, recipient: str) -> Optional[str]:
    for name in candidates:
        candidate_ep = Endpoint(name, base_endpoint.port, base_endpoint.username, base_endpoint.password)
        print(f"  Tentative d'envoi via {candidate_ep.as_line()} ...")
        if send_test_email(candidate_ep.host, candidate_ep.port, candidate_ep.username, candidate_ep.password, recipient):
            print("  ✅ Envoi réussi avec ce nom")
            save_validated(candidate_ep)
            return candidate_ep.host
    return None


def process_entry(endpoint: Endpoint, recipient: str) -> None:
    print(f"\n===== Traitement de {endpoint.as_line()} =====")

    tls_checks = [
        run_s_client(endpoint.host, 587, starttls=True),
        run_s_client(endpoint.host, 465, starttls=False),
    ]
    for check in tls_checks:
        print_tls_result(endpoint, check)

    print(f"\nTest d'envoi initial via {endpoint.host}:{endpoint.port} ...")
    if send_test_email(endpoint.host, endpoint.port, endpoint.username, endpoint.password, recipient):
        print("  ✅ Envoi réussi : endpoint valide")
        save_validated(endpoint)
        return

    candidates = collect_candidates(tls_checks)
    if candidates:
        print("  Utilisation des CN/SAN pour retester en TLS...")
        success_host = try_candidates(candidates, endpoint, recipient)
        if success_host:
            return

        root_domain = derive_root_domain(candidates[0])
        print(f"  Aucun CN/SAN direct valide. Lancement de sub.py pour {root_domain} ...")
        subdomains = run_sub_enum(root_domain)
        if subdomains:
            print(f"  Test des sous-domaines ({len(subdomains)}) ...")
            success_host = try_candidates(subdomains, endpoint, recipient)
            if success_host:
                return

    print("  Aucun endpoint sécurisé trouvé pour cette entrée.")


def read_input(path: Path) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            raise ValueError(f"Ligne invalide (attendu smtpserver|port|user|password) : {line}")
        host, port_str, username, password = parts[:4]
        endpoints.append(Endpoint(host, int(port_str), username, password))
    return endpoints


def main() -> int:
    if not INPUT_FILE.exists():
        print(f"Fichier d'entrée introuvable : {INPUT_FILE}")
        return 1

    recipient = input("Adresse email de test (destinataire) : ").strip()
    if not recipient:
        print("Une adresse email de test est requise.")
        return 1

    try:
        endpoints = read_input(INPUT_FILE)
    except Exception as exc:  # noqa: BLE001
        print(f"Erreur de lecture de {INPUT_FILE} : {exc}")
        return 1

    for endpoint in endpoints:
        process_entry(endpoint, recipient)

    print("\nTerminé. Consultez validated_endpoints.txt pour les endpoints sécurisés trouvés.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
