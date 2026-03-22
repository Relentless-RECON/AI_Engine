from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional

from .scanner import ScanEngine
from .security import validate_target_url
from .types import ScanConfig, utc_now_iso


ScanRunner = Callable[[Dict[str, Any]], Dict[str, Any]]


def _default_runner(payload: Dict[str, Any]) -> Dict[str, Any]:
    config = ScanConfig.from_payload(payload)
    engine = ScanEngine(config)
    return engine.run().to_dict()


class ScanJobManager:
    def __init__(self, runner: Optional[ScanRunner] = None) -> None:
        self._runner = runner or _default_runner
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._results: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _validate_payload(payload: Dict[str, Any]) -> None:
        config = ScanConfig.from_payload(payload)
        if not config.authorized:
            raise PermissionError(
                "Scan blocked: set authorized=true only when you have explicit permission."
            )
        valid, reason = validate_target_url(
            config.target_url, config.allow_private_targets
        )
        if not valid:
            raise ValueError(f"Target validation failed: {reason}")

    def start_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._validate_payload(payload)
        job_id = str(uuid.uuid4())
        created_at = utc_now_iso()
        job = {
            "job_id": job_id,
            "status": "queued",
            "target_url": str(payload.get("target_url", "")),
            "created_at": created_at,
            "started_at": None,
            "completed_at": None,
            "error": None,
            "summary": None,
        }
        with self._lock:
            self._jobs[job_id] = job

        worker = threading.Thread(
            target=self._run_job,
            args=(job_id, payload),
            daemon=True,
            name=f"sentinel-scan-{job_id[:8]}",
        )
        worker.start()
        return dict(job)

    def _run_job(self, job_id: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job["status"] = "running"
            job["started_at"] = utc_now_iso()

        started = time.perf_counter()
        try:
            result = self._runner(payload)
            duration_ms = int((time.perf_counter() - started) * 1000)
            summary = {
                "duration_ms": duration_ms,
                "findings_count": int(result.get("stats", {}).get("findings_count", 0)),
                "requests_sent": int(result.get("stats", {}).get("requests_sent", 0)),
            }
            with self._lock:
                self._results[job_id] = result
                job = self._jobs[job_id]
                job["status"] = "completed"
                job["completed_at"] = utc_now_iso()
                job["summary"] = summary
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                job = self._jobs[job_id]
                job["status"] = "failed"
                job["completed_at"] = utc_now_iso()
                job["error"] = str(exc)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return dict(job)

    def get_result(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            result = self._results.get(job_id)
            if not result:
                return None
            return dict(result)

