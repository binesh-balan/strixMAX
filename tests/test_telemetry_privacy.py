"""Telemetry is opt-in, coarse, and never carries per-finding or model detail."""

from __future__ import annotations

import urllib.parse
from typing import Any, Self

import pytest

from strix.config import loader
from strix.config.settings import TelemetrySettings
from strix.report.state import ReportState
from strix.telemetry import posthog, scarf
from strix.telemetry._common import model_provider


def test_telemetry_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    assert TelemetrySettings().enabled is False
    monkeypatch.setenv("STRIX_TELEMETRY", "1")
    assert TelemetrySettings().enabled is True


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("azure/acme-prod-gpt4-deployment", "azure"),
        ("openrouter/z-ai/glm-5.3", "openrouter"),
        ("Bedrock/anthropic.claude", "bedrock"),
        ("gpt-4o", "unknown"),
        (None, "unknown"),
        ("https://internal.acme.corp/v1", "unknown"),
    ],
)
def test_model_provider_keeps_only_prefix(model: str | None, expected: str) -> None:
    assert model_provider(model) == expected


@pytest.mark.parametrize("telemetry", [posthog, scarf])
def test_scan_started_redacts_model(telemetry: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(telemetry, "_send", lambda _event, props: sent.append(props) or True)

    telemetry.start(
        "azure/acme-secret-deployment",
        "quick",
        is_whitebox=True,
        interactive=False,
        has_instructions=False,
    )

    assert sent[0]["model_provider"] == "azure"
    assert "model" not in sent[0]
    assert "acme-secret-deployment" not in repr(sent[0])


def test_no_per_finding_beacons(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.chdir(tmp_path)
    assert not hasattr(posthog, "finding")
    assert not hasattr(scarf, "finding")
    calls: list[Any] = []
    monkeypatch.setattr(posthog, "_send", lambda *a: calls.append(a) or True)
    monkeypatch.setattr(scarf, "_send", lambda *a: calls.append(a) or True)

    state = ReportState(run_name="privacy")
    state.add_vulnerability_report(
        title="SQLi",
        severity="high",
        description="d",
        impact="i",
        technical_analysis="t",
        poc_description="p",
        poc_script_code="c",
        remediation_steps="r",
    )

    assert calls == []


def test_posthog_disables_ip_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(posthog, "_is_enabled", lambda: True)
    captured: dict[str, Any] = {}

    class _Resp:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    def fake_post(_url: str, json: dict[str, Any], **_kwargs: Any) -> _Resp:
        captured.update(json)
        return _Resp()

    monkeypatch.setattr(posthog.requests, "post", fake_post)
    assert posthog._send("scan_started", {"os": "linux"}) is True
    assert captured["properties"]["$ip"] is None
    assert captured["properties"]["$geoip_disable"] is True


def test_scarf_query_carries_only_coarse_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scarf, "_is_enabled", lambda: True)
    urls: list[str] = []

    class _Resp:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(scarf.requests, "post", lambda url, **_kw: urls.append(url) or _Resp())
    scarf._send(
        "scan_ended",
        {"os": "linux", "exit_reason": "completed", "llm_cost": 12.5, "session": "abc"},
    )

    query = urllib.parse.parse_qs(urllib.parse.urlparse(urls[0]).query)
    assert set(query) == {"os", "exit_reason"}


def test_scarf_scan_ended_sends_no_usage_or_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(scarf, "_send", lambda _event, props: sent.append(props) or True)

    scarf.end(ReportState())

    # strix_version travels in the URL path, not the query string.
    assert set(sent[0]) - {"strix_version"} <= scarf._COARSE_FIELDS


def test_loader_cache_does_not_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    # Guard that the default flip is visible through load_settings too.
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_read_json_overrides", lambda _p: {})
    assert loader.load_settings().telemetry.enabled is False
