"""CSRF, DNS-rebinding, body-size, and token-hygiene guards on the local viewer."""

from __future__ import annotations

import http.client
import json
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import pytest

from strix.interface.viewer import cli as viewer_cli
from strix.interface.viewer.server import (
    MAX_BODY_BYTES,
    is_loopback_host,
    redact_token,
    serve,
)


if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from http.server import ThreadingHTTPServer
    from pathlib import Path


def _make_run(base: Path) -> Path:
    run_dir = base / "strix_runs" / "run"
    run_dir.mkdir(parents=True)
    record = {"run_name": "run", "status": "running", "end_time": None}
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    return run_dir


@pytest.fixture
def viewer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[ThreadingHTTPServer, str, str, list[tuple[str, str]]]]:
    assets = tmp_path / "bundle"
    assets.mkdir()
    (assets / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setattr("strix.interface.viewer.server.bundle_dir", lambda: assets)
    delivered: list[tuple[str, str]] = []

    def steer(agent_id: str, message: str) -> bool:
        delivered.append((agent_id, message))
        return True

    httpd, url, token = serve(_make_run(tmp_path), open_browser=False, steer_handler=steer)
    try:
        yield httpd, url, token, delivered
    finally:
        httpd.shutdown()
        httpd.server_close()


def _request(
    url: str,
    method: str,
    path: str,
    *,
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, http.client.HTTPMessage]:
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname or "127.0.0.1", parts.port)
    conn.request(method, path, body=body, headers=dict(headers or {}))
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status, resp.headers


def _cookie(url: str, token: str) -> str:
    _, headers = _request(url, "GET", f"/?token={token}")
    return str(headers.get("Set-Cookie", "")).split(";", 1)[0]


def _steer(url: str, cookie: str, **headers: str) -> int:
    base = {"Content-Type": "application/json", "Cookie": cookie}
    base.update(headers)
    status, _ = _request(
        url,
        "POST",
        "/api/agents/steer",
        headers=base,
        body=json.dumps({"agent_id": "root", "message": "hi"}).encode(),
    )
    return status


def test_same_origin_post_is_accepted(viewer: tuple) -> None:
    _, url, token, delivered = viewer
    cookie = _cookie(url, token)
    origin = f"http://{urlsplit(url).netloc}"
    assert _steer(url, cookie, Origin=origin, **{"Sec-Fetch-Site": "same-origin"}) == 200
    assert delivered == [("root", "hi")]


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": "null"},
        {"Origin": "http://127.0.0.1:1"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},
    ],
)
def test_cross_origin_post_is_rejected(viewer: tuple, headers: dict[str, str]) -> None:
    _, url, token, delivered = viewer
    assert _steer(url, _cookie(url, token), **headers) == 403
    assert delivered == []


def test_post_requires_json_content_type(viewer: tuple) -> None:
    _, url, token, delivered = viewer
    cookie = _cookie(url, token)
    for ctype in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
        assert _steer(url, cookie, **{"Content-Type": ctype}) == 415, ctype
    assert delivered == []


def test_oversized_body_is_rejected(viewer: tuple) -> None:
    _, url, token, delivered = viewer
    status, _ = _request(
        url,
        "POST",
        "/api/agents/steer",
        headers={"Content-Type": "application/json", "Cookie": _cookie(url, token)},
        body=b" " * (MAX_BODY_BYTES + 1),
    )
    assert status == 413
    assert delivered == []


def test_event_endpoint_requires_session(viewer: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    _, url, _, _ = viewer
    seen: list[bool] = []
    monkeypatch.setattr("strix.telemetry.posthog.viewer_agent_steered", lambda: seen.append(True))
    status, _ = _request(
        url,
        "POST",
        "/api/event",
        headers={"Content-Type": "text/plain"},
        body=json.dumps({"event": "agent_steered"}).encode(),
    )
    assert status == 403
    assert seen == []


@pytest.mark.parametrize("host", ["evil.example", "attacker.test:{port}", "127.0.0.1:1"])
def test_foreign_host_header_is_rejected(viewer: tuple, host: str) -> None:
    httpd, url, token, _ = viewer
    port = httpd.server_address[1]
    host = host.format(port=port) if "{port}" in host else host
    status, _ = _request(url, "GET", "/api/run", headers={"Host": host})
    assert status == 421
    status, headers = _request(url, "GET", f"/?token={token}", headers={"Host": host})
    assert status == 421
    assert headers.get("Set-Cookie") is None


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_loopback_host_header_is_accepted(viewer: tuple, host: str) -> None:
    httpd, url, _, _ = viewer
    status, _ = _request(
        url, "GET", "/api/capabilities", headers={"Host": f"{host}:{httpd.server_address[1]}"}
    )
    assert status == 200


def test_token_is_redacted_from_logs(viewer: tuple, caplog: pytest.LogCaptureFixture) -> None:
    _, url, token, _ = viewer
    with caplog.at_level(logging.DEBUG, logger="strix.interface.viewer.server"):
        _request(url, "GET", f"/?token={token}")
    assert token not in caplog.text
    assert redact_token(f"GET /?a=1&token={token}&b=2") == "GET /?a=1&token=<redacted>&b=2"


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.1.2.3", True),
        ("::1", True),
        ("[::1]", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("192.168.1.10", False),
        ("example.com", False),
    ],
)
def test_is_loopback_host(host: str, expected: bool) -> None:
    assert is_loopback_host(host) is expected


def test_view_cli_refuses_non_loopback_without_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(viewer_cli, "serve", lambda *_a, **_k: pytest.fail("server started"))
    with pytest.raises(SystemExit) as exc:
        viewer_cli.run_view(["--host", "0.0.0.0", "--no-open"])
    assert exc.value.code == 2
    assert "--insecure-bind" in capsys.readouterr().out


def test_view_cli_insecure_bind_warns_and_proceeds(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class _StopError(Exception):
        pass

    def fake_bundle() -> bool:
        raise _StopError

    monkeypatch.setattr(viewer_cli, "bundle_is_built", fake_bundle)
    with pytest.raises(_StopError):
        viewer_cli.run_view(["--host", "0.0.0.0", "--insecure-bind", "--no-open"])
    assert "WARNING" in capsys.readouterr().out
