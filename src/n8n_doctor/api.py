"""A read-only client for the n8n public REST API (``/api/v1``).

Only ``GET`` requests are ever made. The API key is read from ``N8N_API_KEY`` and sent in
the ``X-N8N-API-KEY`` header; it is never printed, and redirects are refused so the key
cannot be forwarded to another host.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any

from . import __version__

# One response at most: parsed, JSON of many small objects (run data items) takes up to ~30 times its size in memory.
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
PAGE_LIMIT = 100  # the API's maximum page size for workflows and executions
DATA_PAGE_LIMIT = 10  # executions per page with includeData=true (each carries its run data)
RUN_TIMEOUT = 300.0  # seconds for all the API calls of one command (--timeout)


class ApiError(Exception):
    pass


class RunTimeout(ApiError):
    """The calls of one command took longer than ``--timeout`` in all."""


class PaginationStalled(ApiError):
    """The instance's cursors go in circles or never end, so entries may be missing from what was read."""


class ResponseTooLarge(ApiError):
    """A response over MAX_RESPONSE_BYTES: :meth:`Client.paginate` asks for smaller pages."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise ApiError(
            f"the server answered with a redirect ({code}) to {_host(newurl)}; set N8N_API_URL to the final address "
            "(redirects are not followed so the API key is never sent elsewhere)"
        )


def _host(url: str) -> str:
    """Only the host of ``url`` (no user info, path or query, which can hold credentials), for messages."""
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        host = None
    return f"host {host}" if host and all(c.isalnum() or c in ".-:" for c in host) else "another address"


def normalize_base(url: str) -> str:
    """``https://n8n.example.com`` or ``.../api/v1/`` -> ``https://n8n.example.com/api/v1``."""
    url = url.strip()
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ApiError("N8N_API_URL must be an http(s) URL with a host, such as https://n8n.example.com (the value given is not shown)")
    if parsed.username or parsed.password:
        raise ApiError("N8N_API_URL must not contain credentials; put the API key in N8N_API_KEY")
    path = parsed.path.rstrip("/")
    if not path.endswith("/api/v1"):
        path += "/api/v1"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class Client:
    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0, total_timeout: float = 120.0, run_timeout: float = RUN_TIMEOUT) -> None:
        if not api_key:
            raise ApiError("N8N_API_KEY is empty")
        self.base = normalize_base(base_url)
        self._key = api_key
        self.timeout = timeout  # one socket operation
        self.total_timeout = total_timeout  # one request
        self.run_timeout = run_timeout  # every request of this client together (--timeout)
        self.run_deadline = time.monotonic() + run_timeout
        self._opener = urllib.request.build_opener(_NoRedirect)
        host = urllib.parse.urlsplit(self.base).hostname or ""
        if self.base.startswith("http://") and host not in ("localhost", "127.0.0.1", "::1"):
            sys.stderr.write("n8n-doctor: warning: N8N_API_URL uses plain http; the API key is sent unencrypted\n")

    @classmethod
    def from_env(cls, base_url: str | None = None, run_timeout: float = RUN_TIMEOUT) -> Client:
        url = base_url or os.environ.get("N8N_API_URL", "")
        key = os.environ.get("N8N_API_KEY", "")
        if not url:
            raise ApiError("set N8N_API_URL (for example https://n8n.example.com) or pass --api-url")
        if not key:
            raise ApiError("set N8N_API_KEY (n8n: Settings > n8n API > Create an API key)")
        return cls(url, key, run_timeout=run_timeout)

    def __repr__(self) -> str:  # never show the key
        return f"Client({self.base!r})"

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        query = {k: ("true" if v is True else "false" if v is False else str(v)) for k, v in (params or {}).items() if v is not None}
        url = f"{self.base}/{path.lstrip('/')}" + (f"?{urllib.parse.urlencode(query)}" if query else "")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={"X-N8N-API-KEY": self._key, "Accept": "application/json", "User-Agent": f"n8n-doctor/{__version__}"},
        )
        now = time.monotonic()
        over_run = f"GET {path}: the n8n API calls took longer than {self.run_timeout:,.0f}s in all (raise it with --timeout)"
        if now >= self.run_deadline:
            raise RunTimeout(over_run)
        deadline = min(now + self.total_timeout, self.run_deadline)
        try:
            with self._opener.open(request, timeout=max(0.1, min(self.timeout, self.run_deadline - now))) as resp:
                chunks: list[bytes] = []
                size = 0
                while size <= MAX_RESPONSE_BYTES:
                    if time.monotonic() > deadline:
                        if deadline == self.run_deadline:
                            raise RunTimeout(over_run)
                        raise ApiError(f"GET {path}: the response took longer than {self.total_timeout:.0f}s")
                    chunk = resp.read1(64 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                body = b"".join(chunks)
        except urllib.error.HTTPError as exc:
            hint = {
                401: "check N8N_API_KEY",
                403: "the API key lacks permission for this (n8n API key scopes)",
                404: "check N8N_API_URL and that the public API is enabled",
            }.get(exc.code, "")
            raise ApiError(f"GET {path} failed: HTTP {exc.code} {exc.reason}" + (f" ({hint})" if hint else "")) from None
        except urllib.error.URLError as exc:
            raise ApiError(f"cannot reach the n8n {_host(self.base)}: {exc.reason}") from None
        except TimeoutError:
            if time.monotonic() >= self.run_deadline:
                raise RunTimeout(over_run) from None
            raise ApiError(f"GET {path} timed out after {self.timeout:.0f}s") from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge(f"GET {path}: response larger than {MAX_RESPONSE_BYTES // (1024 * 1024)} MB")
        try:
            text = body.decode("utf-8")
            del body
            return json.loads(text)
        except ValueError as exc:  # UnicodeDecodeError included
            if "integer string conversion" in str(exc):
                raise ApiError(f"GET {path}: the response holds a number too large to read") from None
            raise ApiError(f"GET {path}: the response is not JSON (is N8N_API_URL the n8n base URL?)") from None
        except RecursionError:
            raise ApiError(f"GET {path}: the response JSON is nested too deeply") from None

    def paginate(
        self, path: str, params: dict[str, Any], max_items: int, page_limit: int = PAGE_LIMIT, fallback: dict[str, Any] | None = None
    ) -> Iterator[dict[str, Any]]:
        """Up to ``max_items`` entries of a list endpoint, ``page_limit`` per page. A page over MAX_RESPONSE_BYTES is
        asked for again in pages half as large; a single entry over it is read with ``fallback`` merged into the
        parameters (``includeData=false``: without its run data) or, without one, is an error. Only one page is
        held at a time. Pages without entries are followed while their cursors are new; a cursor seen before, or more
        pages than ``max_items`` can need, raises :class:`PaginationStalled` after the entries read so far."""
        cursor: str | None = None
        seen = 0
        cursors: set[str] = set()
        limit = max(1, page_limit)
        max_pages = max_items + 1  # a server that returns empty pages with new cursors forever still ends
        pages = 0
        while pages < max_pages:
            query = {**params, "limit": min(limit, max_items - seen), "cursor": cursor}
            try:
                page = self.get(path, query)
            except ResponseTooLarge:
                if query["limit"] > 1:
                    limit = max(1, query["limit"] // 2)
                    continue
                if fallback is None:
                    raise
                page = self.get(path, {**query, **fallback})
            pages += 1
            items = page.get("data") if isinstance(page, dict) else None
            if not isinstance(items, list):
                raise ApiError(f"GET {path}: unexpected response shape (no 'data' list)")
            nxt = page.get("nextCursor")
            del page  # the entries are handed out one by one and dropped from the list: one page in memory at a time
            items = items[: max_items - seen]
            items.reverse()
            while items:
                item = items.pop()
                seen += 1  # count every entry, so junk entries also use up the budget
                if isinstance(item, dict):
                    yield item
                del item
            if seen >= max_items or not isinstance(nxt, str) or not nxt:
                return
            if nxt in cursors:
                raise PaginationStalled(f"GET {path}: the instance repeated a pagination cursor, so results may be missing")
            cursors.add(nxt)
            cursor = nxt
        raise PaginationStalled(f"GET {path}: {pages:,} pages gave only {seen:,} entries, so results may be missing")

    def workflows(self, active_only: bool = False, max_items: int = 1000) -> Iterator[dict[str, Any]]:
        params: dict[str, Any] = {"active": True} if active_only else {}
        yield from self.paginate("workflows", params, max_items)

    def workflow(self, workflow_id: str) -> dict[str, Any]:
        data = self.get(f"workflows/{urllib.parse.quote(workflow_id, safe='')}")
        if not isinstance(data, dict):
            raise ApiError(f"workflow {workflow_id}: unexpected response")
        return data

    def executions(self, status: str | None, workflow_id: str | None, max_items: int, include_data: bool = True) -> Iterator[dict[str, Any]]:
        params: dict[str, Any] = {"status": status, "workflowId": workflow_id, "includeData": include_data}
        page_limit = DATA_PAGE_LIMIT if include_data else PAGE_LIMIT
        yield from self.paginate("executions", params, max_items, page_limit, {"includeData": False} if include_data else None)
