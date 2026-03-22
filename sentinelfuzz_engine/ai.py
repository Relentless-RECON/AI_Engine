from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .types import Finding


OFFLINE_REMEDIATION = {
    "sql_injection": (
        "Use parameterized queries/prepared statements, enforce server-side input validation, "
        "and remove database error leakage from HTTP responses."
    ),
    "time_based_injection": (
        "Apply parameterized queries, strict type constraints for user input, and monitor unusual query latency patterns."
    ),
    "xss_reflected": (
        "Apply context-aware output encoding, validate/allowlist inputs, and enforce Content-Security-Policy."
    ),
    "path_traversal": (
        "Normalize and allowlist file paths, avoid direct user-controlled filesystem access, "
        "and run application processes with least privilege."
    ),
    "command_injection": (
        "Remove shell invocation with user input; use safe library calls and strict allowlists."
    ),
    "ssrf": (
        "Implement outbound URL allowlists, block private address ranges, and enforce protocol restrictions."
    ),
    "open_redirect": (
        "Use allowlisted redirect targets and reject external redirect destinations by default."
    ),
    "missing_security_header": (
        "Add baseline secure headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy)."
    ),
    "permissive_cors": (
        "Replace wildcard CORS with explicit trusted origins and least-privilege methods/headers."
    ),
    "server_disclosure": (
        "Remove or sanitize technology disclosure headers (Server, X-Powered-By) in production."
    ),
    "csrf_missing_token": (
        "Add anti-CSRF tokens to all state-changing forms and validate them server-side per session."
    ),
    "dangerous_http_methods": (
        "Disable unnecessary HTTP methods (especially TRACE, PUT, DELETE, CONNECT) at the web server and app gateway."
    ),
    "injection_anomaly": (
        "Investigate server-side exception handling for this input path, add strict validation, and retest with encoded payload variants."
    ),
}


class AIProvider:
    def generate(self, finding: Finding) -> str:
        raise NotImplementedError


class OfflineProvider(AIProvider):
    def generate(self, finding: Finding) -> str:
        return OFFLINE_REMEDIATION.get(
            finding.vulnerability_type,
            "Apply secure coding controls, validate inputs, and verify remediation with repeatable tests.",
        )


class OllamaProvider(AIProvider):
    def __init__(self) -> None:
        self.base_url = os.getenv("SENTINEL_OLLAMA_URL", "http://127.0.0.1:11434")
        self.model = os.getenv("SENTINEL_OLLAMA_MODEL", "llama3.1:8b")

    def generate(self, finding: Finding) -> str:
        prompt = (
            "You are an AppSec remediation assistant. "
            "Provide a concise remediation plan in 4 bullets.\n"
            f"Type: {finding.vulnerability_type}\n"
            f"URL: {finding.url}\n"
            f"Parameter: {finding.parameter}\n"
            f"Evidence: {finding.evidence}\n"
        )
        payload = json.dumps(
            {"model": self.model, "prompt": prompt, "stream": False}
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        text = str(data.get("response", "")).strip()
        if not text:
            raise RuntimeError("Ollama returned empty response.")
        return text


class HuggingFaceProvider(AIProvider):
    def __init__(self) -> None:
        self.token = os.getenv("HF_API_TOKEN", "")
        self.model = os.getenv(
            "SENTINEL_HF_MODEL", "mistralai/Mistral-7B-Instruct-v0.2"
        )

    def generate(self, finding: Finding) -> str:
        if not self.token:
            raise RuntimeError("HF_API_TOKEN is required for huggingface provider.")
        prompt = (
            "Give concise remediation guidance for this vulnerability.\n"
            f"type={finding.vulnerability_type}\n"
            f"url={finding.url}\n"
            f"parameter={finding.parameter}\n"
            f"evidence={finding.evidence}\n"
        )
        payload = json.dumps({"inputs": prompt}).encode("utf-8")
        request = urllib.request.Request(
            f"https://api-inference.huggingface.co/models/{self.model}",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=14) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        if isinstance(data, list) and data and isinstance(data[0], dict):
            text = str(data[0].get("generated_text", "")).strip()
            if text:
                return text
        raise RuntimeError("Unexpected HuggingFace response format.")


class AIEngine:
    def __init__(self) -> None:
        provider_name = os.getenv("SENTINEL_AI_PROVIDER", "offline").lower()
        if provider_name == "ollama":
            self.provider = OllamaProvider()
        elif provider_name == "huggingface":
            self.provider = HuggingFaceProvider()
        else:
            self.provider = OfflineProvider()
        self.offline_fallback = OfflineProvider()

    def remediation(self, finding: Finding) -> str:
        try:
            return self.provider.generate(finding)
        except (RuntimeError, urllib.error.URLError, TimeoutError, ValueError):
            return self.offline_fallback.generate(finding)
