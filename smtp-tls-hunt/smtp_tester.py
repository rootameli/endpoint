#!/usr/bin/env python3
"""
SMTP TLS hunter.
"""
from __future__ import annotations

import argparse
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
LOG_FILE = SCRIPT_DIR / "smtp.log"
VALIDATED_FILE = SCRIPT_DIR / "validated_endpoints.txt"


@dataclass
class Endpoint:
    host: str
    port: Optional[int] = None

    def with_port(self, port: int) -> "Endpoint":
        return Endpoint(self.host, port)

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host


class JsonLogger:
    def __init__(self, log_file: Path) -> None:
        self.log_file = log_file

    def log(self, event: str, **kwargs: object) -> None:
        payload = {"event": event, **kwargs, "timestamp": time.time()}
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        with self.log_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


@dataclass
class SMTPConfig:
    sender: str
    recipient: str
    username: Optional[str]
    password: Optional[str]
    timeout: float
    ports: Sequence[int]
    enum_timeout: float
    fallback_plain: bool


class SMTPTester:
    def __init__(self, logger: JsonLogger, config: SMTPConfig) -> None:
        self.logger = logger
        self.config = config
        self.validated: set[str] = set()

    def save_validated(self, endpoint: Endpoint) -> None:
        label = endpoint.label
        if label not in self.validated:
            self.validated.add(label)
            with VALIDATED_FILE.open("a", encoding="utf-8") as fh:
                fh.write(label + "\n")

    def send_test_message(
        self, smtp, sender: str, recipient: str, username: Optional[str], password: Optional[str]
    ) -> None:
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = "SMTP TLS hunt test"
        msg.set_content("Test message for SMTP TLS validation.")

        if username and password:
            smtp.login(username, password)
        smtp.send_message(msg)

    def attempt_tls(self, endpoint: Endpoint) -> Tuple[bool, Optional[BaseException]]:
        port = endpoint.port
        if port is None:
            return False, ValueError("Port must be specified for TLS attempt")

        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            if port == 465:
                with smtplib.SMTP_SSL(endpoint.host, port, timeout=self.config.timeout, context=context) as smtp:
                    smtp.ehlo()
                    self.send_test_message(
                        smtp,
                        self.config.sender,
                        self.config.recipient,
                        self.config.username,
                        self.config.password,
                    )
            else:
                with smtplib.SMTP(endpoint.host, port, timeout=self.config.timeout) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=context)
                    smtp.ehlo()
                    self.send_test_message(
                        smtp,
                        self.config.sender,
                        self.config.recipient,
                        self.config.username,
                        self.config.password,
                    )
            return True, None
        except BaseException as exc:  # noqa: BLE001
            return False, exc

    def attempt_plain_no_tls(self, endpoint: Endpoint) -> Tuple[bool, Optional[BaseException]]:
        try:
            with smtplib.SMTP(endpoint.host, endpoint.port or 25, timeout=self.config.timeout) as smtp:
                smtp.ehlo()
                if self.config.username and self.config.password:
                    smtp.login(self.config.username, self.config.password)
                self.send_test_message(smtp, self.config.sender, self.config.recipient, self.config.username, self.config.password)
            return True, None
        except BaseException as exc:  # noqa: BLE001
            return False, exc

    def extract_certificate_domains(self, host: str, port: int) -> Tuple[Optional[str], List[str]]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        names: List[str] = []
        try:
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock:
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
        if not names and cn:
            names.append(cn)
        if cn and cn not in names:
            names.append(cn)

        self.logger.log("extract_cert_names", host=host, port=port, status="success", names=names)
        best = names[0] if names else None
        return best, names

    def derive_root_domain(self, domain: str) -> str:
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def run_sub_enum(self, domain: str) -> List[str]:
        self.logger.log("run_sub_enum", domain=domain, status="start")
        cmd = [sys.executable, "sub.py", domain]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.enum_timeout,
                check=False,
                cwd=SCRIPT_DIR,
            )
            self.logger.log(
                "run_sub_enum",
                domain=domain,
                status="end",
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            self.logger.log("run_sub_enum", domain=domain, status="timeout", error=str(exc))
            return []
        except FileNotFoundError as exc:
            self.logger.log("run_sub_enum", domain=domain, status="failure", error=str(exc))
            return []

        output_file = SCRIPT_DIR / f"{domain}.txt"
        if output_file.exists():
            content = [line.strip() for line in output_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        else:
            content = []
        return content

    def tls_hunt(self, host: str, port: int) -> None:
        best, names = self.extract_certificate_domains(host, port)
        if not best:
            return

        domain_candidates = [best]
        if best.startswith("*."):
            domain_candidates.append(best[2:])
        root = self.derive_root_domain(best)
        if root not in domain_candidates:
            domain_candidates.append(root)
        subdomains = self.run_sub_enum(root)
        domain_candidates.extend(subdomains)

        tested = []
        seen: set[str] = set()
        for candidate in domain_candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            for p in self.config.ports:
                endpoint = Endpoint(candidate, p)
                success, error = self.attempt_tls(endpoint)
                tested.append({"host": candidate, "port": p, "success": success, "error": str(error) if error else None})
                if success:
                    self.save_validated(endpoint)
        self.logger.log("tls_hunt_endpoints", tested=tested, cert_valid_for=best, names=names)

        if self.config.fallback_plain and not any(item.get("success") for item in tested):
            fallback_results = []
            for candidate in domain_candidates:
                endpoint = Endpoint(candidate, 25)
                success, error = self.attempt_plain_no_tls(endpoint)
                fallback_results.append({"host": candidate, "port": 25, "success": success, "error": str(error) if error else None})
                if success:
                    self.save_validated(endpoint)
            self.logger.log("fallback_plain_auth_no_tls", attempts=fallback_results)

    def process_endpoint(self, endpoint: Endpoint) -> None:
        ports = [endpoint.port] if endpoint.port else self.config.ports
        for port in ports:
            ep_with_port = endpoint.with_port(port)
            success, error = self.attempt_tls(ep_with_port)
            self.logger.log(
                "initial_tls_test",
                endpoint=ep_with_port.label,
                status="success" if success else "failure",
                error=str(error) if error else None,
            )
            if success:
                self.save_validated(ep_with_port)
                return
            if isinstance(error, ssl.SSLCertVerificationError) or isinstance(error, ssl.CertificateError):
                before = len(self.validated)
                self.tls_hunt(endpoint.host, port)
                if len(self.validated) > before:
                    return

        if self.config.fallback_plain:
            success, error = self.attempt_plain_no_tls(endpoint)
            self.logger.log(
                "fallback_plain_auth_no_tls",
                endpoint=endpoint.label,
                status="success" if success else "failure",
                error=str(error) if error else None,
            )
            if success:
                self.save_validated(endpoint)


def parse_ports(ports_str: str) -> List[int]:
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ports.append(int(part))
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port: {part}")
    return ports


def read_input_file(path: Path) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        if ":" in clean:
            host, port_str = clean.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"Invalid port in line: {clean}")
            endpoints.append(Endpoint(host, port))
        else:
            endpoints.append(Endpoint(clean))
    return endpoints


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SMTP TLS hunter")
    parser.add_argument("--input", required=True, help="Input file with SMTP endpoints")
    parser.add_argument("--from", dest="sender", required=True, help="Sender email")
    parser.add_argument("--to", dest="recipient", required=True, help="Recipient email")
    parser.add_argument("--username", help="SMTP username")
    parser.add_argument("--password", help="SMTP password")
    parser.add_argument("--ports", default="465,587,25", help="Comma-separated ports to test")
    parser.add_argument("--timeout", type=float, default=10.0, help="Network timeout in seconds")
    parser.add_argument("--enum-timeout", type=float, default=120.0, help="Timeout for subdomain enumeration")
    parser.add_argument("--fallback-plain", default="false", help="Enable AUTH PLAIN without TLS if TLS fails")
    return parser.parse_args(argv)


def str_to_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y"}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ports = parse_ports(args.ports)
    fallback_plain = str_to_bool(args.fallback_plain)

    logger = JsonLogger(LOG_FILE)
    config = SMTPConfig(
        sender=args.sender,
        recipient=args.recipient,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        ports=ports,
        enum_timeout=args.enum_timeout,
        fallback_plain=fallback_plain,
    )

    input_file = Path(args.input)
    endpoints = read_input_file(input_file)

    tester = SMTPTester(logger, config)
    for endpoint in endpoints:
        tester.process_endpoint(endpoint)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
