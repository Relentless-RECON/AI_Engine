from __future__ import annotations

import re
from typing import List

from .types import Finding, HTTPResponse, RequestContext


SQL_PATTERNS = [
    re.compile(r"sql syntax", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"warning.*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"sqlite.*error", re.IGNORECASE),
    re.compile(r"postgresql.*error", re.IGNORECASE),
]

TRAVERSAL_PATTERNS = [
    re.compile(r"root:x:0:0:", re.IGNORECASE),
    re.compile(r"\[extensions\]", re.IGNORECASE),
    re.compile(r"for 16-bit app support", re.IGNORECASE),
]

COMMAND_PATTERNS = [
    re.compile(r"uid=\d+", re.IGNORECASE),
    re.compile(r"gid=\d+", re.IGNORECASE),
    re.compile(r"www-data", re.IGNORECASE),
    re.compile(r"nt authority", re.IGNORECASE),
]

SSRF_PATTERNS = [
    re.compile(r"instance-id", re.IGNORECASE),
    re.compile(r"ami-id", re.IGNORECASE),
    re.compile(r"meta-data", re.IGNORECASE),
]


def _mk_finding(
    *,
    vuln_type: str,
    confidence: float,
    ctx: RequestContext,
    evidence: str,
) -> Finding:
    return Finding(
        finding_id=Finding.new_id(),
        vulnerability_type=vuln_type,
        severity="",
        score=0.0,
        confidence=confidence,
        url=ctx.request_url,
        method=ctx.method,
        parameter=ctx.parameter,
        payload=ctx.payload,
        evidence=evidence[:350],
    )


def analyze_response(
    *,
    ctx: RequestContext,
    response: HTTPResponse,
    baseline_ms: int,
) -> List[Finding]:
    findings: List[Finding] = []
    body = response.body or ""
    body_lower = body.lower()
    payload_lower = ctx.payload.lower()

    if any(p.search(body_lower) for p in SQL_PATTERNS):
        findings.append(
            _mk_finding(
                vuln_type="sql_injection",
                confidence=0.9,
                ctx=ctx,
                evidence="Database error signature detected in response body.",
            )
        )

    if (
        any(tok in payload_lower for tok in ("<script", "onerror", "onload", "javascript:"))
        and ctx.payload in body
    ):
        findings.append(
            _mk_finding(
                vuln_type="xss_reflected",
                confidence=0.88,
                ctx=ctx,
                evidence="Injected payload reflected unescaped in response body.",
            )
        )

    if any(p.search(body_lower) for p in TRAVERSAL_PATTERNS):
        findings.append(
            _mk_finding(
                vuln_type="path_traversal",
                confidence=0.9,
                ctx=ctx,
                evidence="File disclosure pattern detected in response body.",
            )
        )

    if any(p.search(body_lower) for p in COMMAND_PATTERNS):
        findings.append(
            _mk_finding(
                vuln_type="command_injection",
                confidence=0.86,
                ctx=ctx,
                evidence="Command execution signature detected in response output.",
            )
        )

    if "sleep(" in payload_lower and response.response_time_ms > (baseline_ms + 4000):
        findings.append(
            _mk_finding(
                vuln_type="time_based_injection",
                confidence=0.75,
                ctx=ctx,
                evidence=f"Response delay anomaly. baseline={baseline_ms}ms test={response.response_time_ms}ms",
            )
        )

    location = response.headers.get("location", "").lower()
    if response.status in {301, 302, 303, 307, 308} and "evil.example" in location:
        findings.append(
            _mk_finding(
                vuln_type="open_redirect",
                confidence=0.8,
                ctx=ctx,
                evidence=f"Redirected to untrusted location header: {location[:200]}",
            )
        )

    if "169.254.169.254" in payload_lower and any(p.search(body_lower) for p in SSRF_PATTERNS):
        findings.append(
            _mk_finding(
                vuln_type="ssrf",
                confidence=0.7,
                ctx=ctx,
                evidence="Cloud metadata signature observed after URL-based payload injection.",
            )
        )

    # De-duplicate within this response pass.
    dedupe = {}
    for finding in findings:
        key = (finding.vulnerability_type, finding.url, finding.parameter, finding.evidence)
        dedupe[key] = finding
    return list(dedupe.values())


def analyze_security_headers(url: str, response: HTTPResponse) -> List[Finding]:
    findings: List[Finding] = []
    required = [
        "content-security-policy",
        "x-frame-options",
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
    ]
    present = set(response.headers.keys())

    for header_name in required:
        if header_name not in present:
            findings.append(
                Finding(
                    finding_id=Finding.new_id(),
                    vulnerability_type="missing_security_header",
                    severity="",
                    score=0.0,
                    confidence=0.95,
                    url=url,
                    method="HEAD",
                    parameter=header_name,
                    payload="",
                    evidence=f"Missing security header: {header_name}",
                )
            )

    cors = response.headers.get("access-control-allow-origin", "")
    if cors.strip() == "*":
        findings.append(
            Finding(
                finding_id=Finding.new_id(),
                vulnerability_type="permissive_cors",
                severity="",
                score=0.0,
                confidence=0.9,
                url=url,
                method="HEAD",
                parameter="access-control-allow-origin",
                payload="",
                evidence="CORS policy allows all origins with wildcard '*'.",
            )
        )

    if response.headers.get("server") or response.headers.get("x-powered-by"):
        findings.append(
            Finding(
                finding_id=Finding.new_id(),
                vulnerability_type="server_disclosure",
                severity="",
                score=0.0,
                confidence=0.8,
                url=url,
                method="HEAD",
                parameter="server",
                payload="",
                evidence="Server technology disclosure header is present.",
            )
        )

    return findings

