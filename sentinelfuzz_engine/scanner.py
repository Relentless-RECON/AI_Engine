from __future__ import annotations

import time
import uuid
from typing import Dict, List
from urllib.parse import urlparse

from .ai import AIEngine
from .analyzer import (
    analyze_boolean_sql,
    analyze_csrf_for_form,
    analyze_response,
    analyze_security_headers,
)
from .http_client import send_request
from .payloads import build_payloads, sql_boolean_payload_pair
from .recon import crawl_target
from .scoring import calculate_score
from .security import validate_target_url
from .types import (
    Endpoint,
    Finding,
    HTTPResponse,
    RequestContext,
    ScanConfig,
    ScanResult,
    ScanStats,
    utc_now_iso,
)


REFERENCE_MAP = {
    "sql_injection": ["https://owasp.org/Top10/A03_2021-Injection/"],
    "time_based_injection": ["https://owasp.org/Top10/A03_2021-Injection/"],
    "xss_reflected": ["https://owasp.org/Top10/A03_2021-Injection/"],
    "path_traversal": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    "command_injection": ["https://owasp.org/www-community/attacks/Command_Injection"],
    "ssrf": ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
    "open_redirect": ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
    "missing_security_header": ["https://owasp.org/www-project-secure-headers/"],
    "permissive_cors": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
    "server_disclosure": ["https://owasp.org/www-project-secure-headers/"],
    "csrf_missing_token": ["https://owasp.org/www-community/attacks/csrf"],
    "dangerous_http_methods": ["https://owasp.org/www-project-web-security-testing-guide/"],
    "injection_anomaly": ["https://owasp.org/Top10/A03_2021-Injection/"],
}


class ScanEngine:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.ai = AIEngine()
        self.stats = ScanStats()
        self.errors: List[str] = []

    def _request_headers(self) -> Dict[str, str]:
        return {"User-Agent": self.config.user_agent}

    def _build_request_params(self, endpoint: Endpoint, attack_param: str, payload: str) -> Dict[str, str]:
        params = dict(endpoint.default_params)
        for name in endpoint.parameters:
            if name == attack_param:
                params[name] = payload
            elif name not in params:
                params[name] = "1"
        if attack_param not in params:
            params[attack_param] = payload
        return params

    @staticmethod
    def _attackable_param(name: str) -> bool:
        lower = name.lower()
        if lower.startswith("__"):
            return False
        if lower in {"_viewstate", "_eventvalidation", "_eventtarget", "_eventargument"}:
            return False
        return True

    def _baseline_for_endpoint(self, endpoint: Endpoint) -> HTTPResponse:
        params = endpoint.default_params if endpoint.default_params else None
        response = send_request(
            url=endpoint.url,
            method=endpoint.method,
            params=params,
            headers=self._request_headers(),
            timeout_sec=self.config.request_timeout_sec,
        )
        self.stats.requests_sent += 1
        return response

    @staticmethod
    def _guess_parameters(endpoint: Endpoint) -> List[str]:
        path = urlparse(endpoint.url).path.lower()
        guesses: List[str] = []
        if "search" in path:
            guesses.extend(["q", "query"])
        elif any(k in path for k in ("news", "comment", "item", "product", "details")):
            guesses.extend(["id"])
        elif any(k in path for k in ("user", "account", "profile", "login")):
            guesses.extend(["id", "user"])
        elif any(k in path for k in ("api", "rest", "graphql")):
            guesses.extend(["id", "q"])
        if any(k in path for k in ("redirect", "callback", "return", "next")):
            guesses.extend(["url", "next", "redirect"])
        if not guesses:
            guesses.extend(["id"])
        return list(dict.fromkeys(guesses))[:3]

    def _score_and_enrich(self, finding: Finding) -> Finding:
        score, severity = calculate_score(finding.vulnerability_type, finding.confidence)
        finding.score = score
        finding.severity = severity
        finding.references = REFERENCE_MAP.get(finding.vulnerability_type, [])
        finding.recommendation = self.ai.remediation(finding)
        return finding

    def _fuzz_endpoint(self, endpoint: Endpoint, findings: List[Finding]) -> None:
        baseline = self._baseline_for_endpoint(endpoint)
        baseline_ms = baseline.response_time_ms if baseline.status else 300
        attack_params = [p for p in endpoint.parameters if self._attackable_param(p)]
        guessed_params: List[str] = []
        if not attack_params and self.config.guess_common_params and endpoint.method in {"GET", "POST"}:
            guessed_params = self._guess_parameters(endpoint)
            attack_params = guessed_params
        if not attack_params:
            return

        for param in attack_params:
            # Differential boolean SQL test first for high-signal SQLi detection.
            if "id" in param.lower() or "user" in param.lower() or "query" in param.lower():
                true_template, false_template = sql_boolean_payload_pair()
                base_value = str(endpoint.default_params.get(param, "1")).strip() or "1"
                true_payload = f"{base_value} {true_template}".strip()
                false_payload = f"{base_value} {false_template}".strip()
                true_response = send_request(
                    url=endpoint.url,
                    method=endpoint.method,
                    params=self._build_request_params(endpoint, param, true_payload),
                    headers=self._request_headers(),
                    timeout_sec=self.config.request_timeout_sec,
                )
                false_response = send_request(
                    url=endpoint.url,
                    method=endpoint.method,
                    params=self._build_request_params(endpoint, param, false_payload),
                    headers=self._request_headers(),
                    timeout_sec=self.config.request_timeout_sec,
                )
                self.stats.requests_sent += 2
                if not true_response.error and not false_response.error:
                    ctx = RequestContext(
                        endpoint_url=endpoint.url,
                        method=endpoint.method,
                        request_url=true_response.url,
                        parameter=param,
                        payload=f"{true_payload} | {false_payload}",
                    )
                    bool_finding = analyze_boolean_sql(
                        ctx=ctx,
                        baseline=baseline,
                        true_response=true_response,
                        false_response=false_response,
                    )
                    if bool_finding is not None:
                        findings.append(bool_finding)

            payloads = build_payloads(param, self.config.max_payloads_per_param)
            if param in guessed_params:
                payloads = payloads[: min(4, len(payloads))]
            for payload in payloads:
                params = self._build_request_params(endpoint, param, payload)
                response = send_request(
                    url=endpoint.url,
                    method=endpoint.method,
                    params=params,
                    headers=self._request_headers(),
                    timeout_sec=self.config.request_timeout_sec,
                )
                self.stats.requests_sent += 1
                if response.error:
                    self.errors.append(f"{endpoint.url} {endpoint.method}: {response.error}")
                    self.stats.errors_count += 1
                    continue

                ctx = RequestContext(
                    endpoint_url=endpoint.url,
                    method=endpoint.method,
                    request_url=response.url,
                    parameter=param,
                    payload=payload,
                )
                findings.extend(
                    analyze_response(
                        ctx=ctx,
                        response=response,
                        baseline_ms=baseline_ms,
                        baseline_status=baseline.status,
                    )
                )
                if self.config.delay_ms > 0:
                    time.sleep(self.config.delay_ms / 1000.0)

    def _header_scan(self, endpoints: List[Endpoint], findings: List[Finding]) -> None:
        origins = set()
        for endpoint in endpoints:
            parsed = urlparse(endpoint.url)
            origins.add(f"{parsed.scheme}://{parsed.netloc}")
        for url in sorted(origins):
            response = send_request(
                url=url,
                method="HEAD",
                headers=self._request_headers(),
                timeout_sec=self.config.request_timeout_sec,
            )
            self.stats.requests_sent += 1
            if response.error or response.status == 405:
                # Fallback for servers that block HEAD.
                response = send_request(
                    url=url,
                    method="GET",
                    headers=self._request_headers(),
                    timeout_sec=self.config.request_timeout_sec,
                )
                self.stats.requests_sent += 1
            if response.error:
                self.errors.append(f"HEAD {url}: {response.error}")
                self.stats.errors_count += 1
                continue
            findings.extend(analyze_security_headers(url, response))

    @staticmethod
    def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
        dedupe: Dict[str, Finding] = {}
        for finding in findings:
            parsed = urlparse(finding.url)
            normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if finding.vulnerability_type == "injection_anomaly":
                key = (
                    f"{finding.vulnerability_type}|{normalized_url}|"
                    f"{finding.method}|{finding.parameter}"
                )
            elif finding.vulnerability_type in {"missing_security_header", "server_disclosure"}:
                key = f"{finding.vulnerability_type}|{normalized_url}|{finding.parameter}"
            else:
                key = (
                    f"{finding.vulnerability_type}|{normalized_url}|{finding.method}|"
                    f"{finding.parameter}|{finding.evidence[:100]}"
                )
            current = dedupe.get(key)
            if current is None or finding.confidence > current.confidence:
                dedupe[key] = finding
        return list(dedupe.values())

    def run(self) -> ScanResult:
        if not self.config.authorized:
            raise PermissionError(
                "Scan blocked: set authorized=true only when you have explicit permission."
            )
        valid, reason = validate_target_url(
            self.config.target_url, self.config.allow_private_targets
        )
        if not valid:
            raise ValueError(f"Target validation failed: {reason}")

        started = time.perf_counter()
        started_at = utc_now_iso()

        endpoints = crawl_target(self.config)
        self.stats.endpoints_discovered = len(endpoints)

        all_findings: List[Finding] = []
        for endpoint in endpoints:
            csrf_finding = analyze_csrf_for_form(endpoint)
            if csrf_finding is not None:
                all_findings.append(csrf_finding)

        for endpoint in endpoints:
            self._fuzz_endpoint(endpoint, all_findings)

        if self.config.include_header_scan:
            self._header_scan(endpoints, all_findings)

        deduped = self._dedupe_findings(all_findings)
        enriched = [self._score_and_enrich(finding) for finding in deduped]
        self.stats.findings_count = len(enriched)

        completed_at = utc_now_iso()
        duration_ms = int((time.perf_counter() - started) * 1000)
        return ScanResult(
            scan_id=str(uuid.uuid4()),
            target_url=self.config.target_url,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            stats=self.stats,
            findings=enriched,
            errors=self.errors,
        )
