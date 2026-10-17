"""Plain-http platform URLs are only accepted for loopback hosts."""

from __future__ import annotations

import pytest
import requests

from strix.interface import platform_cli
from strix.interface.cloud import http


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:3000",
        "http://127.8.9.10",
        "http://[::1]:8080",
        "http://localhost:3000",
        "https://app.strix.ai",
        "https://strix.internal.example",
    ],
)
def test_https_or_loopback_http_is_accepted(url: str) -> None:
    http._parse_origin_url(url, label="configured platform URL")
    record = platform_cli._bind_login_record({"api_token": "t"}, url)
    assert record["app_url"].startswith(url.split(":", 1)[0])


@pytest.mark.parametrize(
    "url",
    [
        "http://app.strix.ai",
        "http://10.0.0.5:3000",
        "http://localhost.evil.example",
        "http://0.0.0.0:3000",
    ],
)
def test_plain_http_to_remote_host_is_rejected(url: str) -> None:
    with pytest.raises(http.CloudError, match="must use https"):
        http._parse_origin_url(url, label="configured platform URL")
    with pytest.raises(platform_cli.PlatformAuthError, match="must use https"):
        platform_cli._bind_login_record({"api_token": "t"}, url)


def test_request_refuses_plain_http_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(http, "_app_url_override", "http://strix.internal.example")
    monkeypatch.setenv("STRIX_API_TOKEN", "secret-token")
    monkeypatch.setattr(
        requests, "request", lambda *_a, **_k: pytest.fail("token sent over plain http")
    )
    with pytest.raises(http.CloudError, match="must use https"):
        http.request("GET", "/scans", token="secret-token")  # noqa: S106  # nosec B106


def test_device_flow_refuses_plain_http_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_cli, "_app_url", lambda: "http://strix.internal.example")
    monkeypatch.setattr(
        requests, "post", lambda *_a, **_k: pytest.fail("login started over plain http")
    )
    with pytest.raises(platform_cli.PlatformAuthError, match="must use https"):
        platform_cli._run_device_flow(platform_cli.Console(), open_browser=False)
