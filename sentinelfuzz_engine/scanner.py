from __future__ import annotations

import time
import uuid
from typing import Dict, List

from .ai import AIEngine
from .analyzer import analyze_response, analyze_security_headers
from .http_client import send_request
from .payloads import build_payloads
from .recon import crawl_target
from .scoring import calculate_score
from .security import validate_target_url
from .types import Endpoint, Finding, RequestContext, ScanConfig, ScanResult, ScanStats, utc_now_iso


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
}


class ScanEngine:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.ai = AIEngine()
        self.stats = ScanStats()
        self.errors: List[str] = []

    def _request_headers(self) -> Dict[str, str]:
        return {"User-Agent": self.config.user_agent}

    def _baseline_for_endpoint(self, endpoint: Endpoint) -> int:
        response = send_request(
            url=endpoint.url,
            method="GET",
            headers=self._request_headers(),
            timeout_sec=self.config.request_timeout_sec,
        )
        self.stats.requests_sent += 1
        return response.response_time_ms if response.status else 300

    def _score_and_enrich(self, finding: Finding) -> Finding:
        score, severity = calculate_score(finding.vulnerability_type, finding.confidence)
        finding.score = score
        finding.severity = severity
        finding.references = REFERENCE_MAP.get(finding.vulnerability_type, [])
        finding.recommendation = self.ai.remediation(finding)
        return finding

    def _fuzz_endpoint(self, endpoint: Endpoint, findings: List[Finding]) -> None:
        if not endpoint.parameters:
            return

        baseline_ms = self._baseline_for_endpoint(endpoint)

        for param in endpoint.parameters:
            payloads = build_payloads(param, self.config.max_payloads_per_param)
            for payload in payloads:
                params = {p: ("sentinel" if p != param else payload) for p in endpoint.parameters}
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
                    analyze_response(ctx=ctx, response=response, baseline_ms=baseline_ms)
                )
                if self.config.delay_ms > 0:
                    time.sleep(self.config.delay_ms / 1000.0)

    def _header_scan(self, endpoints: List[Endpoint], findings: List[Finding]) -> None:
        unique_urls = sorted({e.url for e in endpoints})
        for url in unique_urls:
            response = send_request(
                url=url,
                method="HEAD",
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
            key = (
                f"{finding.vulnerability_type}|{finding.url}|{finding.method}|"
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

