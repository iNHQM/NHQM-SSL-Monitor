"""Inspect TLS certificates for hostnames using Python's standard library."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import socket
import ssl
from typing import Optional


@dataclass(frozen=True)
class CertificateStatus:
    hostname: str
    port: int
    valid: bool
    expires_at: Optional[datetime]
    days_remaining: Optional[int]
    issuer: str
    subject: str
    warning: bool
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "port": self.port,
            "valid": self.valid,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "days_remaining": self.days_remaining,
            "issuer": self.issuer,
            "subject": self.subject,
            "warning": self.warning,
            "error": self.error,
        }


def _name(parts: tuple) -> str:
    return ", ".join(f"{key}={value}" for rdn in parts for key, value in rdn)


def check_certificate(hostname: str, *, port: int = 443, timeout: float = 5.0,
                      warning_days: int = 30) -> CertificateStatus:
    """Validate a site's TLS certificate and report expiration.

    Uses system trust roots, certificate chain verification, and hostname matching.
    The hostname must not include a URL scheme or path. This performs a live network
    connection; callers should only supply trusted destinations (SSRF consideration).
    """
    if not isinstance(hostname, str) or not hostname or hostname.strip() != hostname or any(c in hostname for c in '/:@?# \\'):
        raise ValueError("hostname must be a plain DNS name or IP address")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 120:
        raise ValueError("timeout must be between 0 and 120 seconds")
    if not isinstance(warning_days, int) or isinstance(warning_days, bool) or warning_days < 0:
        raise ValueError("warning_days must be a nonnegative integer")

    # IP literals can be passed to create_connection, but still verify the cert.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname.encode("idna")
        except UnicodeError as exc:
            raise ValueError("invalid hostname") from exc

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
        expiry_text = cert.get("notAfter")
        if not expiry_text:
            raise ValueError("certificate does not include expiration date")
        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry_text), tz=timezone.utc)
        now = datetime.now(timezone.utc)
        seconds_left = (expiry - now).total_seconds()
        days = max(0, int(seconds_left // 86400)) if seconds_left > 0 else 0
        return CertificateStatus(
            hostname=hostname, port=port, valid=True,
            expires_at=expiry, days_remaining=days,
            issuer=_name(cert.get("issuer", ())), subject=_name(cert.get("subject", ())),
            warning=seconds_left <= warning_days * 86400,
        )
    except (OSError, ssl.SSLError, ValueError) as exc:
        return CertificateStatus(hostname, port, False, None, None, "", "", True,
                                 f"{type(exc).__name__}: {exc}")
