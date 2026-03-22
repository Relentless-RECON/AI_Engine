from __future__ import annotations

from typing import Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import time
import urllib.request
import urllib.error

from .types import HTTPResponse


def _merge_query_params(url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    current = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        current[key] = [value]
    new_query = urlencode(current, doseq=True)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def send_request(
    *,
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout_sec: float = 8.0,
) -> HTTPResponse:
    method = method.upper()
    headers = dict(headers or {})
    body_bytes = None
    request_url = url

    if params:
        if method == "GET":
            request_url = _merge_query_params(url, params)
        else:
            body_bytes = urlencode(params).encode("utf-8")
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    request = urllib.request.Request(
        request_url,
        data=body_bytes,
        headers=headers,
        method=method,
    )

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            elapsed_ms = int((time.perf_counter() - started) * 1000)
            response_headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            return HTTPResponse(
                url=request_url,
                status=getattr(resp, "status", 200),
                headers=response_headers,
                body=body,
                response_time_ms=elapsed_ms,
                error=None,
            )
    except urllib.error.HTTPError as err:
        err_body = err.read().decode("utf-8", errors="ignore")
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        response_headers = {k.lower(): v for k, v in dict(err.headers).items()}
        return HTTPResponse(
            url=request_url,
            status=err.code,
            headers=response_headers,
            body=err_body,
            response_time_ms=elapsed_ms,
            error=None,
        )
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return HTTPResponse(
            url=request_url,
            status=0,
            headers={},
            body="",
            response_time_ms=elapsed_ms,
            error=str(exc),
        )

