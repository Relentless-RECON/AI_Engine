from __future__ import annotations

from difflib import SequenceMatcher
import re
from typing import List, Optional

from .types import Endpoint, Finding, HTTPResponse, RequestContext


SQL_PATTERNS = [
    re.compile(r"sql syntax", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"warning.*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"sqlclient\.sqlexception", re.IGNORECASE),
    re.compile(r"incorrect syntax near", re.IGNORECASE),
    re.compile(r"oledb.*sql server", re.IGNORECASE),
    re.compile(r"odbc.*sql server", re.IGNORECASE),
    re.compile(r"microsoft sql native client error", re.IGNORECASE),
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
    baseline_status: int | None = None,
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

    if any(tok in payload_lower for tok in ("<script", "onerror", "onload", "javascript:")) and (
        ctx.payload in body
        or ("javascript:" in payload_lower and "javascript:" in body_lower)
        or ("sentinelxss" in payload_lower and "sentinelxss" in body_lower)
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

    if any(tok in payload_lower for tok in ("sleep(", "pg_sleep(", "waitfor delay", "benchmark(")) and response.response_time_ms > (baseline_ms + 3500):
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

    # Fallback anomaly heuristic: payload triggers server-side failure.
    if (
        response.status >= 500
        and (baseline_status is None or baseline_status < 500)
        and any(tok in payload_lower for tok in ("'", "\"", "<script", "onerror", "javascript:", ";", "`", "$("))
    ):
        findings.append(
            _mk_finding(
                vuln_type="injection_anomaly",
                confidence=0.58,
                ctx=ctx,
                evidence=f"Injected payload produced server error status={response.status}",
            )
        )

    # De-duplicate within this response pass.
    dedupe = {}
    for finding in findings:
        key = (finding.vulnerability_type, finding.url, finding.parameter, finding.evidence)
        dedupe[key] = finding
    return list(dedupe.values())


def analyze_boolean_sql(
    *,
    ctx: RequestContext,
    baseline: HTTPResponse,
    true_response: HTTPResponse,
    false_response: HTTPResponse,
) -> Optional[Finding]:
    # Compare behavior across true/false boolean SQL payloads.
    baseline_text = (baseline.body or "")[:8000]
    true_text = (true_response.body or "")[:8000]
    false_text = (false_response.body or "")[:8000]

    true_similarity = SequenceMatcher(None, baseline_text, true_text).ratio()
    false_similarity = SequenceMatcher(None, baseline_text, false_text).ratio()
    len_delta = abs(len(true_text) - len(false_text))
    status_delta = true_response.status != false_response.status

    diff = true_similarity - false_similarity
    if diff >= 0.22 or (diff >= 0.05 and (len_delta >= 20 or status_delta)):
        evidence = (
            "Differential SQLi behavior observed with boolean payload pair. "
            f"sim_true={true_similarity:.2f} sim_false={false_similarity:.2f} "
            f"status_true={true_response.status} status_false={false_response.status}"
        )
        return _mk_finding(
            vuln_type="sql_injection",
            confidence=0.84,
            ctx=ctx,
            evidence=evidence,
        )
    return None


def analyze_csrf_for_form(endpoint: Endpoint) -> Optional[Finding]:
    if endpoint.source != "form" or endpoint.method != "POST":
        return None
    token_hints = ("csrf", "token", "__requestverificationtoken", "authenticity_token")
    has_token = any(any(hint in p.lower() for hint in token_hints) for p in endpoint.parameters)
    if has_token:
        return None
    return Finding(
        finding_id=Finding.new_id(),
        vulnerability_type="csrf_missing_token",
        severity="",
        score=0.0,
        confidence=0.75,
        url=endpoint.url,
        method=endpoint.method,
        parameter="form",
        payload="",
        evidence="POST form detected without obvious anti-CSRF token parameter.",
    )


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

    allow_methods = response.headers.get("allow", "")
    dangerous = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT") if m in allow_methods.upper()]
    if dangerous:
        findings.append(
            Finding(
                finding_id=Finding.new_id(),
                vulnerability_type="dangerous_http_methods",
                severity="",
                score=0.0,
                confidence=0.7,
                url=url,
                method="HEAD",
                parameter="allow",
                payload="",
                evidence=f"Potentially dangerous HTTP methods enabled: {', '.join(dangerous)}",
            )
        )

    return findings
