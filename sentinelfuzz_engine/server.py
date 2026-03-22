from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .job_manager import ScanJobManager
from .scanner import ScanEngine
from .types import ScanConfig

JOB_MANAGER = ScanJobManager()


class SentinelRequestHandler(BaseHTTPRequestHandler):
    server_version = "SentinelFuzzCore/1.0"

    def _write_json(self, status_code: int, payload: dict) -> None:
        encoded = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        if not raw:
            return {}
        return json.loads(raw)

    @staticmethod
    def _path_parts(path: str) -> list[str]:
        clean = urlparse(path).path
        return [part for part in clean.split("/") if part]

    def _run_sync_scan(self, payload: dict) -> None:
        config = ScanConfig.from_payload(payload)
        engine = ScanEngine(config)
        result = engine.run()
        self._write_json(200, result.to_dict())

    def do_GET(self) -> None:  # noqa: N802
        parts = self._path_parts(self.path)
        path = urlparse(self.path).path
        if path == "/health":
            self._write_json(
                200,
                {
                    "status": "ok",
                    "service": "sentinelfuzz-core-engine",
                    "version": "1.1.0",
                },
            )
            return

        if len(parts) >= 3 and parts[0] == "v1" and parts[1] == "scans":
            job_id = parts[2]
            job = JOB_MANAGER.get_job(job_id)
            if not job:
                self._write_json(404, {"error": "Scan job not found"})
                return

            if len(parts) == 3:
                payload = {"job": job}
                if job["status"] in {"queued", "running"}:
                    payload["poll_after_ms"] = 1500
                self._write_json(200, payload)
                return

            if len(parts) == 4 and parts[3] == "result":
                if job["status"] == "completed":
                    result = JOB_MANAGER.get_result(job_id)
                    if result is None:
                        self._write_json(
                            500, {"error": "Job marked completed but result is unavailable"}
                        )
                        return
                    self._write_json(200, result)
                    return
                if job["status"] == "failed":
                    self._write_json(
                        409,
                        {"error": "Scan job failed", "job_id": job_id, "details": job["error"]},
                    )
                    return
                self._write_json(
                    202,
                    {
                        "message": "Scan still in progress",
                        "job_id": job_id,
                        "status": job["status"],
                        "poll_after_ms": 1500,
                    },
                )
                return

        self._write_json(404, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path not in {"/v1/scan", "/v1/scans"}:
            self._write_json(404, {"error": "Not found"})
            return
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._write_json(400, {"error": "Invalid JSON"})
            return

        try:
            if path == "/v1/scan":
                self._run_sync_scan(payload)
                return
            job = JOB_MANAGER.start_scan(payload)
            self._write_json(202, {"job": job, "status_url": f"/v1/scans/{job['job_id']}"})
        except PermissionError as exc:
            self._write_json(403, {"error": str(exc)})
        except ValueError as exc:
            self._write_json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._write_json(500, {"error": f"Scan failed: {exc}"})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        # Keep server quiet by default in hackathon environments.
        return


def run_server() -> None:
    host = os.getenv("SENTINEL_HOST", "127.0.0.1")
    port = int(os.getenv("SENTINEL_PORT", "8787"))
    httpd = ThreadingHTTPServer((host, port), SentinelRequestHandler)
    print(f"SentinelFuzz core engine listening on http://{host}:{port}")
    httpd.serve_forever()
