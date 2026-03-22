from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

from .http_client import send_request
from .types import Endpoint, ScanConfig


def _strip_fragment(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, "")
    )


def _same_host(url: str, base_url: str) -> bool:
    return (urlparse(url).hostname or "").lower() == (urlparse(base_url).hostname or "").lower()


def _query_param_names(url: str) -> List[str]:
    return sorted(parse_qs(urlparse(url).query, keep_blank_values=True).keys())


def _query_param_defaults(url: str) -> Dict[str, str]:
    parsed = parse_qs(urlparse(url).query, keep_blank_values=True)
    return {key: (values[0] if values else "") for key, values in parsed.items()}


def _looks_like_static_asset(path: str) -> bool:
    lower = path.lower()
    return lower.endswith(
        (
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".webp",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".map",
        )
    )


def _default_seed_paths() -> List[str]:
    # Generic API-first seeds to improve SPA coverage.
    return [
        "/api",
        "/graphql",
        "/rest/products/search?q=apple",
        "/rest/user/login",
        "/api/search?q=test",
        "/search?q=test",
    ]


def extract_candidate_endpoints_from_js(js_text: str, base_url: str) -> List[str]:
    candidates: List[str] = []
    for match in re.finditer(r'["\']((?:/|https?://)[^"\']{1,180})["\']', js_text):
        raw = match.group(1).strip()
        absolute = _strip_fragment(urljoin(base_url, raw))
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if not _same_host(absolute, base_url):
            continue
        if _looks_like_static_asset(parsed.path):
            continue
        interesting = (
            "api" in parsed.path.lower()
            or "rest" in parsed.path.lower()
            or "graphql" in parsed.path.lower()
            or "search" in parsed.path.lower()
            or "login" in parsed.path.lower()
            or "user" in parsed.path.lower()
            or "product" in parsed.path.lower()
            or "comment" in parsed.path.lower()
            or parsed.query != ""
        )
        if interesting:
            candidates.append(absolute)
    return list(dict.fromkeys(candidates))


@dataclass
class _Form:
    action: str
    method: str = "GET"
    inputs: List[str] = field(default_factory=list)


class _HTMLMapParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.forms: List[_Form] = []
        self._active_form: _Form | None = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        attr_map: Dict[str, str] = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
        elif t == "script":
            src = attr_map.get("src", "").strip()
            if src:
                self.scripts.append(src)
        elif t == "form":
            action = attr_map.get("action", "").strip()
            method = attr_map.get("method", "GET").upper().strip() or "GET"
            self._active_form = _Form(action=action, method=method)
        elif t in {"input", "textarea", "select"} and self._active_form is not None:
            name = attr_map.get("name", "").strip()
            if name and name not in self._active_form.inputs:
                self._active_form.inputs.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._active_form is not None:
            self.forms.append(self._active_form)
            self._active_form = None


def crawl_target(config: ScanConfig) -> List[Endpoint]:
    base_url = _strip_fragment(config.target_url)
    queue = deque([(base_url, 0, "crawl")])
    if config.enable_spa_api_discovery:
        for seed in _default_seed_paths():
            queue.append((urljoin(base_url, seed), 0, "seed"))

    visited: Set[str] = set()
    visited_js: Set[str] = set()
    endpoints: Dict[str, Endpoint] = {}
    headers = {"User-Agent": config.user_agent}

    while queue and len(visited) < config.max_pages:
        current_url, depth, source = queue.popleft()
        normalized = _strip_fragment(current_url)
        if normalized in visited:
            continue
        visited.add(normalized)

        response = send_request(
            url=normalized,
            method="GET",
            headers=headers,
            timeout_sec=config.request_timeout_sec,
        )
        if response.status == 0:
            continue

        params = _query_param_names(normalized)
        key = f"GET::{normalized}::{','.join(params)}"
        endpoints[key] = Endpoint(
            url=normalized,
            method="GET",
            parameters=params,
            default_params=_query_param_defaults(normalized),
            source=source,
        )

        if not response.body:
            continue
        if "text/html" not in response.headers.get("content-type", "").lower():
            continue

        parser = _HTMLMapParser()
        parser.feed(response.body)

        for raw_link in parser.links:
            absolute = _strip_fragment(urljoin(normalized, raw_link))
            if not absolute.startswith(("http://", "https://")):
                continue
            if not _same_host(absolute, base_url):
                continue
            link_params = _query_param_names(absolute)
            link_key = f"GET::{absolute}::{','.join(link_params)}"
            if link_key not in endpoints:
                endpoints[link_key] = Endpoint(
                    url=absolute,
                    method="GET",
                    parameters=link_params,
                    default_params=_query_param_defaults(absolute),
                    source="link",
                )
            if depth + 1 <= config.max_depth:
                queue.append((absolute, depth + 1, "link"))

        for form in parser.forms:
            action = form.action or normalized
            form_url = _strip_fragment(urljoin(normalized, action))
            if not form_url.startswith(("http://", "https://")):
                continue
            if not _same_host(form_url, base_url):
                continue
            method = form.method if form.method in {"GET", "POST"} else "GET"
            form_key = f"{method}::{form_url}::{','.join(sorted(form.inputs))}"
            endpoints[form_key] = Endpoint(
                url=form_url,
                method=method,
                parameters=sorted(form.inputs),
                default_params={},
                source="form",
            )

        if config.enable_spa_api_discovery and parser.scripts:
            for raw_script in parser.scripts[: config.max_js_files]:
                script_url = _strip_fragment(urljoin(normalized, raw_script))
                if script_url in visited_js:
                    continue
                visited_js.add(script_url)
                if not _same_host(script_url, base_url):
                    continue
                js_response = send_request(
                    url=script_url,
                    method="GET",
                    headers=headers,
                    timeout_sec=config.request_timeout_sec,
                )
                if js_response.status == 0 or not js_response.body:
                    continue
                for candidate in extract_candidate_endpoints_from_js(
                    js_response.body, base_url
                ):
                    c_params = _query_param_names(candidate)
                    c_key = f"GET::{candidate}::{','.join(c_params)}"
                    if c_key not in endpoints:
                        endpoints[c_key] = Endpoint(
                            url=candidate,
                            method="GET",
                            parameters=c_params,
                            default_params=_query_param_defaults(candidate),
                            source="js",
                        )
                    if depth + 1 <= config.max_depth and candidate not in visited:
                        queue.append((candidate, depth + 1, "js"))

    return list(endpoints.values())
