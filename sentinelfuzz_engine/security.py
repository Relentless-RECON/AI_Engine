from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def is_private_or_local_ip(hostname: str) -> bool:
    if not hostname:
        return True
    lowered = hostname.strip().lower()
    if lowered in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True

    for info in infos:
        ip_text = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return True
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            return True
    return False


def validate_target_url(url: str, allow_private_targets: bool) -> tuple[bool, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False, "Only http/https targets are supported."
    if not parsed.netloc:
        return False, "Target URL must include a hostname."
    if not allow_private_targets and is_private_or_local_ip(parsed.hostname or ""):
        return False, "Private, loopback, and local targets are blocked by default."
    return True, ""

