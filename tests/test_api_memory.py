"""Memory of `executions` when the API returns executions with a lot of run data."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlsplit

import pytest

from n8n_doctor.api import MAX_RESPONSE_BYTES, ApiError, Client

KEY = "memory-test-key-123"
COUNT = 100
ITEMS = 120_000  # run data items per execution: about 1.4 MB of JSON each, 144 MB for all of them


def _execution_bytes(i: int, items: int = ITEMS, message: str | None = "Request failed with status code 500") -> bytes:
    error = {"message": message, "node": {"name": "H"}} if message else {"node": {"name": "H"}}
    head = {"id": str(1000 + i), "workflowId": "w1", "status": "error", "startedAt": "2026-11-01T10:00:00.000Z"}
    run = b'{"H":[{"error":{"message":"from run data"},"data":{"main":[[' + b",".join([b'{"json":{}}'] * items) + b"]]}}]}"
    result = b'{"resultData":{"error":' + json.dumps(error).encode() + b',"lastNodeExecuted":"H","runData":' + run + b"}}"
    return json.dumps(head).encode()[:-1] + b',"data":' + result + b"}"


class Big(BaseHTTPRequestHandler):
    body: ClassVar[bytes] = b""
    limits: ClassVar[list[tuple[int, str]]] = []

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if self.headers.get("X-N8N-API-KEY") != KEY:
            self.send_response(401)
            self.end_headers()
            return
        if url.path.endswith("/executions"):
            start, limit = int(q.get("cursor") or 0), int(q["limit"])
            Big.limits.append((limit, q.get("includeData", "")))
            ids = range(start, min(start + limit, COUNT))
            if q.get("includeData") == "true":
                items = [
                    Big.body.replace(b'"1000"', b'"%d"' % (1000 + i), 1) if i != 7 else _execution_bytes(i, items=1_500_000) for i in ids
                ]  # one execution of 18 MB
            else:
                items = [json.dumps({"id": str(1000 + i), "workflowId": "w1", "status": "error"}).encode() for i in ids]
            nxt = b'"%d"' % (start + len(items)) if start + len(items) < COUNT else b"null"
            raw = b'{"data":[' + b",".join(items) + b'],"nextCursor":' + nxt + b"}"
        elif url.path.endswith("/workflows/w1"):
            raw = json.dumps({"id": "w1", "name": "Big", "nodes": [], "connections": {}}).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture
def big_server() -> Iterator[str]:
    Big.body = _execution_bytes(0)
    Big.limits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Big)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


_RUN = """
import json, resource, sys
from n8n_doctor.cli import main
code = main(["executions", "--limit", "100", "--format", "json"])
print(json.dumps({"code": code, "rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024}), file=sys.stderr)
"""


def test_executions_with_large_run_data_stay_small_in_memory(big_server: str) -> None:
    env = {**os.environ, "N8N_API_URL": big_server, "N8N_API_KEY": KEY}
    done = subprocess.run([sys.executable, "-c", _RUN], env=env, capture_output=True, text=True, timeout=300, check=False)
    stats = json.loads(done.stderr.strip().splitlines()[-1])
    result = json.loads(done.stdout)
    assert result["executions"] == COUNT
    assert sum(g["count"] for g in result["groups"]) == COUNT
    assert stats["rss_mb"] < 500, stats
    assert all(limit <= 10 for limit, data in Big.limits if data == "true")


def test_pages_too_large_are_read_in_smaller_pages(big_server: str) -> None:
    client = Client(big_server, KEY)
    got = list(client.executions("error", None, 20))
    assert [e["id"] for e in got] == [str(1000 + i) for i in range(20)]
    assert "data" not in got[7] and "data" in got[6]  # the 18 MB execution is read without its data
    assert MAX_RESPONSE_BYTES == 16 * 1024 * 1024


def test_a_single_response_over_the_limit_is_an_error_naming_it(big_server: str) -> None:
    client = Client(big_server, KEY)
    with pytest.raises(ApiError, match="larger than 16 MB"):
        client.get("executions", {"includeData": True, "cursor": 7, "limit": 1})
