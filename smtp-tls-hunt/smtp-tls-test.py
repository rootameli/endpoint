#!/usr/bin/env python3
"""
Script unique pour tester des endpoints SMTP en TLS et tenter des sous-domaines
quand un problème de certificat est détecté.
"""
from __future__ import annotations

import json
import smtplib
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
INPUT_FILE = SCRIPT_DIR / "smtps.txt"
OUTPUT_FILE = SCRIPT_DIR / "validated_endpoints.txt"
LOG_FILE = SCRIPT_DIR / "smtp.log"
DEFAULT_TIMEOUT = 10.0


@dataclass
class Endpoint:
    host: str
    port: int
    username: str
    password: str

    def label(self) -> str:
        return f"{self.host}:{self.port}"


class JsonLogger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def log(self, event: str, **kwargs: object) -> None:
        payload = {"event": event, **kwargs, "timestamp": time.time()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


class SMTPTLSHunter:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        self.logger = JsonLogger(LOG_FILE)

    def _send_test_email(self, smtp: smtplib.SMTP, sender: str, recipient: str, username: str, password: str) -> None:
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = "SMTP TLS test"
        msg.set_content("Test message for secure SMTP endpoint discovery.")

        if username:
            smtp.login(username, password)
        smtp.send_message(msg)

    def _smtp_tls_connection(self, endpoint: Endpoint, recipient: str) -> Tuple[bool, Optional[BaseException]]:
        sender = endpoint.username
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            if endpoint.port == 465:
                with smtplib.SMTP_SSL(endpoint.host, endpoint.port, timeout=self.timeout, context=context) as smtp:
                    smtp.ehlo()
                    self._send_test_email(smtp, sender, recipient, endpoint.username, endpoint.password)
            else:
                with smtplib.SMTP(endpoint.host, endpoint.port, timeout=self.timeout) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=context)
                    smtp.ehlo()
                    self._send_test_email(smtp, sender, recipient, endpoint.username, endpoint.password)
            return True, None
        except BaseException as exc:  # noqa: BLE001
            return False, exc

    def _extract_certificate_names(self, host: str, port: int) -> Tuple[Optional[str], List[str]]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        names: List[str] = []
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
        except BaseException as exc:  # noqa: BLE001
            self.logger.log("extract_cert_names", host=host, port=port, status="failure", error=str(exc))
            return None, names

        san = cert.get("subjectAltName", []) if cert else []
        for entry in san:
            if entry[0].lower() == "dns":
                names.append(entry[1])

        cn = None
        for subject_entry in cert.get("subject", []) if cert else []:
            for key, value in subject_entry:
                if key.lower() == "commonname":
                    cn = value
                    break
            if cn:
                break
        if cn and cn not in names:
            names.append(cn)

        best = names[0] if names else None
        self.logger.log("extract_cert_names", host=host, port=port, status="success", names=names)
        return best, names

    def _read_subdomains(self, domain: str) -> List[str]:
        output_file = SCRIPT_DIR / f"{domain}.txt"
        if not output_file.exists():
            return []
        return [line.strip() for line in output_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _run_sub_enum(self, domain: str) -> List[str]:
        self.logger.log("run_sub_enum", domain=domain, status="start")
        cmd = [sys.executable, "sub.py", domain]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * 12,
                cwd=SCRIPT_DIR,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self.logger.log("run_sub_enum", domain=domain, status="timeout", error=str(exc))
            return []
        except FileNotFoundError as exc:
            self.logger.log("run_sub_enum", domain=domain, status="failure", error=str(exc))
            return []

        self.logger.log(
            "run_sub_enum",
            domain=domain,
            status="end",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        return self._read_subdomains(domain)

    def _derive_domain_for_enum(self, name: str) -> str:
        clean = name[2:] if name.startswith("*.") else name
        parts = clean.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return clean

    def _test_candidates(self, candidates: Sequence[str], endpoint: Endpoint, recipient: str) -> Optional[str]:
        tested = []
        for candidate in candidates:
            candidate_ep = Endpoint(candidate, endpoint.port, endpoint.username, endpoint.password)
            success, error = self._smtp_tls_connection(candidate_ep, recipient)
            tested.append({"host": candidate, "port": endpoint.port, "success": success, "error": str(error) if error else None})
            if success:
                self.logger.log("tls_hunt_endpoints", cert_valid_for=candidates, tested=tested)
                return candidate
        self.logger.log("tls_hunt_endpoints", cert_valid_for=candidates, tested=tested)
        return None

    def _record_validated(self, host: str, endpoint: Endpoint) -> None:
        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        line = f"{host}|{endpoint.port}|{endpoint.username}|{endpoint.password}\n"
        with OUTPUT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def process_endpoint(self, endpoint: Endpoint, recipient: str) -> None:
        success, error = self._smtp_tls_connection(endpoint, recipient)
        self.logger.log(
            "initial_tls_test",
            endpoint=endpoint.label(),
            status="success" if success else "failure",
            error=str(error) if error else None,
            username=endpoint.username,
            recipient=recipient,
        )
        if success:
            self._record_validated(endpoint.host, endpoint)
            return

        if isinstance(error, (ssl.SSLCertVerificationError, ssl.CertificateError)):
            best, names = self._extract_certificate_names(endpoint.host, endpoint.port)
            candidates: List[str] = []
            seen: set[str] = set()
            for name in names:
                if name not in seen:
                    candidates.append(name)
                    seen.add(name)
            if best and best.startswith("*.") and best[2:] not in seen:
                candidates.append(best[2:])
                seen.add(best[2:])

            validated_host = None
            if candidates:
                validated_host = self._test_candidates(candidates, endpoint, recipient)

            if not validated_host and best:
                domain = self._derive_domain_for_enum(best)
                subdomains = self._run_sub_enum(domain)
                if subdomains:
                    validated_host = self._test_candidates(subdomains, endpoint, recipient)

            if validated_host:
                self._record_validated(validated_host, endpoint)

    def run(self, endpoints: Sequence[Endpoint], recipient: str) -> None:
        for endpoint in endpoints:
            self.process_endpoint(endpoint, recipient)


def read_input_file(path: Path) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    content = path.read_text(encoding="utf-8")
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            raise ValueError(f"Ligne invalide (format attendu smtp|port|user|pass): {line}")
        host, port_str, username, password = parts[:4]
        endpoints.append(Endpoint(host, int(port_str), username, password))
    return endpoints


def main() -> int:
    if not INPUT_FILE.exists():
        print(f"Fichier d'entrée introuvable: {INPUT_FILE}")
        return 1

    recipient = input("Adresse email de test (destinataire): ").strip()
    if not recipient:
        print("Une adresse email de test est requise.")
        return 1

    try:
        endpoints = read_input_file(INPUT_FILE)
    except Exception as exc:  # noqa: BLE001
        print(f"Erreur de lecture du fichier d'entrée: {exc}")
        return 1

    hunter = SMTPTLSHunter()
    hunter.run(endpoints, recipient)
    print("Traitement terminé. Consultez validated_endpoints.txt et smtp.log pour les résultats.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
