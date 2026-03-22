from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
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


@dataclass
class _Form:
    action: str
    method: str = "GET"
    inputs: List[str] = field(default_factory=list)


class _HTMLMapParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []
        self.forms: List[_Form] = []
        self._active_form: _Form | None = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        attr_map: Dict[str, str] = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(href)
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
    queue = deque([(base_url, 0)])
    visited: Set[str] = set()
    endpoints: Dict[str, Endpoint] = {}
    headers = {"User-Agent": config.user_agent}

    while queue and len(visited) < config.max_pages:
        current_url, depth = queue.popleft()
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
        if response.status == 0 or not response.body:
            continue
        if "text/html" not in response.headers.get("content-type", "").lower():
            continue

        params = _query_param_names(normalized)
        key = f"GET::{normalized}::{','.join(params)}"
        endpoints[key] = Endpoint(
            url=normalized,
            method="GET",
            parameters=params,
            source="crawl",
        )

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
                    source="link",
                )
            if depth + 1 <= config.max_depth:
                queue.append((absolute, depth + 1))

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
                source="form",
            )

    return list(endpoints.values())

