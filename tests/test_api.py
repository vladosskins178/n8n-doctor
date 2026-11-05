"""The read-only API client and the commands that use it, against a local fake n8n."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlsplit

import pytest

from n8n_doctor.api import ApiError, Client, PaginationStalled, normalize_base
from n8n_doctor.cli import main
from n8n_doctor.executions import normalize, summarize

from .conftest import link, node, trigger, workflow

KEY = "test-key-value-123"
WF = {**workflow([trigger(), node("H", "httpRequest", {"url": "https://x.example.com"}, 4.2)], link("Start", "H"), name="Remote"), "id": "w1"}


def _execution(i: int, node_name: str, message: str, wid: str = "w1") -> dict[str, Any]:
    return {
        "id": str(100 + i),
        "workflowId": wid,
        "status": "error",
        "startedAt": f"2026-11-0{1 + i % 3}T10:00:00.000Z",
        "data": {"resultData": {"error": {"message": message, "node": {"name": node_name}}, "lastNodeExecuted": node_name}},
    }


EXECUTIONS = [
    _execution(0, "H", "Request failed with status code 429"),
    _execution(1, "H", "Request failed with status code 429"),
    _execution(2, "H", "Request failed with status code 500"),
    _execution(3, "Code", "Cannot read properties of undefined (reading 'id') [line 12345678]"),
    _execution(4, "Code", "Cannot read properties of undefined (reading 'id') [line 87654321]"),
    {"id": "200", "workflowId": "w2", "status": "error", "startedAt": "2026-11-03T00:00:00Z"},
]


HEADER_SECRET = "Zq7Wv2Lp9Rk4Tn8Ym3Xc"
HEADERS = {"parameters": [{"name": "X-Api-Key", "value": HEADER_SECRET}]}
NODATA_WF = {
    **workflow(
        [
            trigger(),
            node("H", "httpRequest", {"url": "https://x.example.com", "sendHeaders": True, "headerParameters": HEADERS}, 4.2),
        ]
    ),
    "id": "w9",
    "name": "No copy",
}
NODATA_EXECUTIONS = [
    _execution(0, "H", f"Request failed: header value {HEADER_SECRET} rejected", "w9"),
    _execution(1, "H", "The secret 'Hk3pQ9vL2xx' is wrong", "w9"),
    _execution(2, "H", "connect postgres://admin:Hk3!pQ9#vL2@wX7z@db:5432/app failed", "w9"),
]


class Fake(BaseHTTPRequestHandler):
    seen: ClassVar[list[tuple[str, str, str | None]]] = []

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, code: int, body: Any, headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        Fake.seen.append(("GET", url.path, self.headers.get("X-N8N-API-KEY")))
        if self.headers.get("X-N8N-API-KEY") != KEY:
            return self._send(401, {"message": "unauthorized"})
        if url.path == "/redirect/api/v1/workflows":
            return self._send(302, {}, {"Location": "http://elsewhere.example.com/"})
        if url.path == "/loop/api/v1/executions":
            return self._send(200, {"data": [1, 2, 3], "nextCursor": "same"})
        if url.path == "/stuck/api/v1/executions":  # empty pages and a cursor that repeats
            return self._send(200, {"data": [], "nextCursor": "same"})
        if url.path == "/fresh/api/v1/executions":  # an empty page with a new cursor is not the end
            if not q.get("cursor"):
                return self._send(200, {"data": [], "nextCursor": "more"})
            return self._send(200, {"data": EXECUTIONS[:1], "nextCursor": None})
        if url.path == "/repeat/api/v1/executions":  # one page of results, then the cursor repeats
            return self._send(200, {"data": EXECUTIONS[:1], "nextCursor": "same"})
        if url.path == "/slow/api/v1/workflows":
            self.send_response(200)
            self.send_header("Content-Length", "100000")
            self.end_headers()
            for _ in range(25):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.1)
            return None
        if url.path == "/nodata/api/v1/executions":  # no workflowData: the masker comes from the workflow itself
            return self._send(200, {"data": NODATA_EXECUTIONS, "nextCursor": None})
        if url.path == "/nodata/api/v1/workflows/w9":
            return self._send(200, NODATA_WF)
        if url.path == "/many/api/v1/workflows":  # 5 workflows, 2 per page
            start = int(q.get("cursor") or 0)
            page = [{**WF, "id": f"m{i}"} for i in range(start, min(start + min(int(q["limit"]), 2), 5))]
            return self._send(200, {"data": page, "nextCursor": str(start + len(page)) if start + len(page) < 5 else None})
        if url.path == "/api/v1/workflows":
            return self._send(200, {"data": [WF], "nextCursor": None})
        if url.path == "/api/v1/workflows/w1":
            return self._send(200, WF)
        if url.path == "/api/v1/workflows/w2":
            return self._send(404, {"message": "not found"})
        if url.path == "/api/v1/executions":
            assert q.get("status") == "error" and q.get("includeData") == "true"
            items = [e for e in EXECUTIONS if "workflowId" not in q or e["workflowId"] == q["workflowId"]]
            start = int(q.get("cursor", 0))
            limit = int(q["limit"])
            page = items[start : start + min(limit, 2)]  # small pages to exercise the cursor
            nxt = str(start + len(page)) if start + len(page) < len(items) else None
            return self._send(200, {"data": page, "nextCursor": nxt})
        return self._send(404, {"message": "no"})

    def _refuse(self) -> None:
        Fake.seen.append((self.command, self.path, None))
        self._send(405, {})

    do_POST = do_PUT = do_PATCH = do_DELETE = _refuse


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    Fake.seen = []
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    monkeypatch.setenv("N8N_API_URL", base)
    monkeypatch.setenv("N8N_API_KEY", KEY)
    yield base
    httpd.shutdown()
    assert all(method == "GET" for method, _, _ in Fake.seen)


def test_normalize_base() -> None:
    assert normalize_base("https://n8n.example.com/") == "https://n8n.example.com/api/v1"
    assert normalize_base("https://n8n.example.com/api/v1/") == "https://n8n.example.com/api/v1"
    assert normalize_base("https://x.example.com/n8n") == "https://x.example.com/n8n/api/v1"
    for bad in ("ftp://x", "n8n.example.com", "https://user:pw@x.example.com"):
        with pytest.raises(ApiError):
            normalize_base(bad)


def test_client_never_shows_key(server: str) -> None:
    client = Client.from_env()
    assert KEY not in repr(client)
    with pytest.raises(ApiError) as exc:
        Client(server, "wrong-key").get("workflows")
    assert "401" in str(exc.value) and "wrong-key" not in str(exc.value)


def test_redirects_are_refused(server: str) -> None:
    with pytest.raises(ApiError, match="redirect"):
        Client(server + "/redirect", KEY).get("workflows")
    assert not any("elsewhere" in path for _, path, _ in Fake.seen)


def test_plain_http_warning(capsys: pytest.CaptureFixture[str]) -> None:
    Client("http://n8n.example.com", KEY)
    assert "unencrypted" in capsys.readouterr().err
    Client("http://localhost:5678", KEY)
    assert capsys.readouterr().err == ""


def test_unreachable_and_non_json(server: str) -> None:
    with pytest.raises(ApiError, match="cannot reach"):
        Client("http://127.0.0.1:1", KEY, timeout=2).get("workflows")
    with pytest.raises(ApiError, match="404"):
        Client(server, KEY).get("nothing")


def test_normalize_messages() -> None:
    assert normalize("failed  at 2026-11-01T10:00:00.000Z id 3f2b1c4d-1111-2222-3333-444455556666") == "failed at <time> id <uuid>"
    assert normalize("status code 429") == "status code 429"
    assert normalize("GET https://x.example.com/a?token=abc failed") == "GET https://x.example.com/a?<query> failed"


def test_summarize_groups(server: str) -> None:
    result = summarize(Client.from_env(), None, 100)
    assert result["executions"] == 6
    groups = result["groups"]
    assert [g["count"] for g in groups] == [2, 2, 1, 1]
    top = next(g for g in groups if g["node"] == "H" and g["count"] == 2)
    assert top["workflow"] == "Remote" and "429" in top["error"]
    code = next(g for g in groups if g["node"] == "Code")
    assert code["count"] == 2 and code["first_seen"] < code["last_seen"]
    missing = next(g for g in groups if g["workflow_id"] == "w2")
    assert missing["workflow"] == "workflow w2" and "no error details" in missing["error"]
    assert summarize(Client.from_env(), None, 3)["executions"] == 3


def test_executions_cli(server: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["executions", "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "6 error executions, 4 distinct problems" in out and "Remote > H" in out
    assert main(["executions", "--workflow-id", "w1", "-f", "json", "--fail-on-errors"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["executions"] == 5 and KEY not in json.dumps(payload)


def test_lint_and_explain_from_api(server: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["lint", "--api", "--no-config", "-f", "json", "--fail-on", "never"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["workflows"][0]["file"] == "<api>/workflows/w1"
    assert {f["rule"] for f in payload["findings"]} >= {"N8D302"}
    assert main(["lint", "--api", "--no-config", "--workflow-id", "w1", "-f", "sarif"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "api/workflows/w1"
    assert main(["explain", "--api", "--workflow-id", "w1"]) == 0
    assert 'Workflow "Remote"' in capsys.readouterr().out
    assert main(["explain", "--api"]) == 2


def test_lint_api_says_when_it_stops_at_max_workflows(server: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    many = ["lint", "--api", "--api-url", server + "/many", "--no-config", "--fail-on", "never", "-f", "json"]
    assert main(many) == 0  # 5 workflows, all read
    assert json.loads(capsys.readouterr().out)["summary"]["workflows"] == 5
    monkeypatch.setattr("n8n_doctor.cli.API_MAX_WORKFLOWS", 3)
    assert main(many) == 2  # the default cap is hit: the report covers 3, the run fails and says why
    out, err = capsys.readouterr()
    assert json.loads(out)["summary"]["workflows"] == 3
    assert "more than 3 workflows; only the first 3 were checked (raise --max-workflows)" in err
    assert main([*many, "--max-workflows", "4"]) == 0  # a cap chosen on purpose: a warning only
    out, err = capsys.readouterr()
    assert json.loads(out)["summary"]["workflows"] == 4 and "only the first 4" in err
    assert main([*many, "--max-workflows", "5"]) == 0
    assert capsys.readouterr().err == ""
    assert main([*many, "--max-workflows", "0"]) == 2


def test_executions_without_workflow_copy_are_masked_with_the_fetched_workflow(server: str) -> None:
    result = summarize(Client(server + "/nodata", KEY), None, 100)
    text = json.dumps(result)
    for leaked in (HEADER_SECRET, "Hk3pQ9vL2xx", "Hk3!pQ9", "wX7z"):
        assert leaked not in text
    examples = {g["example"] for g in result["groups"]}
    assert "The secret '***' is wrong" in examples
    assert "connect postgres://***@db:5432/app failed" in examples
    assert {g["workflow"] for g in result["groups"]} == {"No copy"}
    assert sum(1 for _, path, _ in Fake.seen if path == "/nodata/api/v1/workflows/w9") == 1  # fetched once


def test_pagination_cannot_loop_forever(server: str) -> None:
    client = Client(server + "/loop", KEY)
    with pytest.raises(PaginationStalled, match="repeated"):
        list(client.executions("error", None, 1000))
    assert sum(1 for _, path, _ in Fake.seen if path.startswith("/loop")) <= 3


@pytest.mark.parametrize("format_", ["text", "json"])
def test_repeated_cursor_with_empty_pages_is_not_no_errors(server: str, format_: str, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["executions", "--api-url", server + "/stuck", "--no-config", "--format", format_])
    captured = capsys.readouterr()
    assert code == 3
    assert "No error executions" not in captured.out and "repeated" in captured.err
    if format_ == "json":
        assert "repeated" in json.loads(captured.out)["incomplete"]
    else:
        assert "Incomplete" in captured.out


def test_repeated_cursor_keeps_what_was_read(server: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["executions", "--api-url", server + "/repeat", "--no-config", "--format", "json"]) == 3
    assert json.loads(capsys.readouterr().out)["executions"] == 1


def test_an_empty_page_with_a_new_cursor_is_followed(server: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["executions", "--api-url", server + "/fresh", "--no-config", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["executions"] == 1


def test_total_deadline(server: str) -> None:
    client = Client(server + "/slow", KEY, timeout=5, total_timeout=1)
    with pytest.raises(ApiError, match="longer than"):
        client.get("workflows")


def test_run_deadline_covers_every_request(server: str, capsys: pytest.CaptureFixture[str]) -> None:
    client = Client(server + "/slow", KEY, timeout=5, total_timeout=60, run_timeout=1)
    started = time.monotonic()
    with pytest.raises(ApiError, match="--timeout"):
        client.get("workflows")
    assert time.monotonic() - started < 3
    with pytest.raises(ApiError, match="--timeout"):  # nothing more once the run is over its time
        client.get("workflows/w1")
    assert main(["lint", "--api", "--timeout", "1", "--api-url", server + "/slow", "--no-config"]) == 2
    assert "--timeout" in capsys.readouterr().err
