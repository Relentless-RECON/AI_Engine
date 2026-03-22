from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanConfig:
    target_url: str
    authorized: bool = False
    max_depth: int = 2
    max_pages: int = 30
    request_timeout_sec: float = 8.0
    max_payloads_per_param: int = 18
    delay_ms: int = 100
    include_header_scan: bool = True
    allow_private_targets: bool = False
    user_agent: str = "SentinelFuzz/1.0"
    enable_spa_api_discovery: bool = True
    max_js_files: int = 8
    guess_common_params: bool = True

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "ScanConfig":
        return cls(
            target_url=str(payload.get("target_url", "")).strip(),
            authorized=bool(payload.get("authorized", False)),
            max_depth=int(payload.get("max_depth", 2)),
            max_pages=int(payload.get("max_pages", 30)),
            request_timeout_sec=float(payload.get("request_timeout_sec", 8.0)),
            max_payloads_per_param=int(payload.get("max_payloads_per_param", 18)),
            delay_ms=int(payload.get("delay_ms", 100)),
            include_header_scan=bool(payload.get("include_header_scan", True)),
            allow_private_targets=bool(payload.get("allow_private_targets", False)),
            user_agent=str(payload.get("user_agent", "SentinelFuzz/1.0")),
            enable_spa_api_discovery=bool(payload.get("enable_spa_api_discovery", True)),
            max_js_files=int(payload.get("max_js_files", 8)),
            guess_common_params=bool(payload.get("guess_common_params", True)),
        )


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    default_params: Dict[str, str] = field(default_factory=dict)
    source: str = "crawl"


@dataclass
class HTTPResponse:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    response_time_ms: int
    error: Optional[str] = None


@dataclass
class RequestContext:
    endpoint_url: str
    method: str
    request_url: str
    parameter: str
    payload: str


@dataclass
class Finding:
    finding_id: str
    vulnerability_type: str
    severity: str
    score: float
    confidence: float
    url: str
    method: str
    parameter: str
    payload: str
    evidence: str
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    @staticmethod
    def new_id() -> str:
        return str(uuid.uuid4())


@dataclass
class ScanStats:
    endpoints_discovered: int = 0
    requests_sent: int = 0
    findings_count: int = 0
    errors_count: int = 0


@dataclass
class ScanResult:
    scan_id: str
    target_url: str
    started_at: str
    completed_at: str
    duration_ms: int
    stats: ScanStats
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
