from __future__ import annotations

from typing import Tuple


BASE_METRICS = {
    "sql_injection": (9.5, 8.8, 8.0),
    "time_based_injection": (8.8, 7.8, 7.2),
    "xss_reflected": (7.0, 7.2, 6.2),
    "path_traversal": (8.1, 7.3, 7.0),
    "command_injection": (9.8, 8.4, 8.8),
    "ssrf": (8.5, 6.9, 7.9),
    "open_redirect": (5.2, 7.6, 4.2),
    "missing_security_header": (4.8, 7.0, 4.0),
    "permissive_cors": (7.4, 7.2, 6.4),
    "server_disclosure": (2.5, 7.5, 2.1),
}


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


def calculate_score(vulnerability_type: str, confidence: float) -> Tuple[float, str]:
    impact, exploitability, scope = BASE_METRICS.get(
        vulnerability_type, (4.0, 4.0, 4.0)
    )
    confidence = max(0.1, min(confidence, 1.0))
    raw = (impact * 0.5) + (exploitability * 0.3) + (scope * 0.2)
    # Penalize low-confidence heuristic hits so severe labels stay meaningful.
    weighted = raw * (0.65 + 0.35 * confidence)
    score = round(min(10.0, weighted), 1)
    return score, severity_from_score(score)

