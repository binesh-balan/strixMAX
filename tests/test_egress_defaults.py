"""Outbound-traffic defaults: nothing leaves the host unless the operator opts in."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Self

import pytest

from strix.config import loader
from strix.interface.viewer import auth
from strix.runtime import session_manager


@pytest.fixture(autouse=True)
def _fresh_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", tmp_path / "missing.json")
    for name in ("STRIX_VIEWER_RELAY", "STRIX_OAST_SERVER", "STRIX_OAST_TOKEN"):
        monkeypatch.delenv(name, raising=False)


def test_strix_import_keeps_third_party_libraries_offline() -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("LITELLM_LOCAL_", "HF_HUB_"))}
    code = (
        "import os, strix\n"
        "for n in ('LITELLM_LOCAL_MODEL_COST_MAP', 'LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS',"
        " 'HF_HUB_OFFLINE', 'HF_HUB_DISABLE_TELEMETRY'):\n"
        "    print(n, os.environ[n])\n"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    ).stdout
    assert "LITELLM_LOCAL_MODEL_COST_MAP True" in out
    assert "LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS True" in out
    assert "HF_HUB_OFFLINE 1" in out
    assert "HF_HUB_DISABLE_TELEMETRY 1" in out


def test_operator_can_override_offline_defaults() -> None:
    env = {**os.environ, "LITELLM_LOCAL_MODEL_COST_MAP": "False"}
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os, strix; print(os.environ['LITELLM_LOCAL_MODEL_COST_MAP'])",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert out.strip() == "False"


def test_viewer_relay_is_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("relay must not be contacted")

    monkeypatch.setattr(auth.requests, "post", boom)
    with pytest.raises(auth.RelayError) as exc:
        auth.otp_start("analyst@example.com")
    assert exc.value.code == "unavailable"
    with pytest.raises(auth.RelayError):
        auth.feedback_submit("analyst@example.com", "hi")


def test_viewer_relay_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_VIEWER_RELAY", "true")
    calls: list[str] = []

    class _Resp:
        status_code = 200
        content = b"{}"

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    def fake_post(url: str, **_kwargs: object) -> _Resp:
        calls.append(url)
        return _Resp()

    monkeypatch.setattr(auth.requests, "post", fake_post)
    auth.otp_start("analyst@example.com")
    assert calls == ["https://app.strix.ai/api/oss/otp/start"]


def test_oast_env_absent_by_default() -> None:
    assert session_manager._oast_env() == {}


def test_oast_env_passes_private_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_OAST_SERVER", "https://oast.corp.example")
    monkeypatch.setenv("STRIX_OAST_TOKEN", "tok")
    assert session_manager._oast_env() == {
        "STRIX_OAST_SERVER": "https://oast.corp.example",
        "STRIX_OAST_TOKEN": "tok",
    }


def test_skills_never_point_at_public_oast_servers() -> None:
    skills = Path(session_manager.__file__).resolve().parents[1] / "skills"
    banned = [
        re.compile(r"[\w$()<>-]+\.oast\.(fun|pro|live|site|online|me)\b"),
        re.compile(r"trufflehog filesystem(?![^\n]*--no-verification)"),
        re.compile(r"semgrep [^\n]*--config auto"),
    ]
    offenders = [
        f"{path.relative_to(skills)}: {match.group(0)}"
        for path in skills.rglob("*.md")
        for pattern in banned
        for match in pattern.finditer(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_private_oast_server_is_allowed_through_the_sandbox_firewall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_OAST_SERVER", "https://oast.corp.example")
    monkeypatch.setattr(session_manager, "_resolve_host", lambda _host: ["10.20.30.40"])
    env = session_manager._sandbox_environment(None).value
    assert env["STRIX_OAST_SERVER"] == "https://oast.corp.example"
    assert "10.20.30.40" in env["STRIX_EGRESS_ALLOW"].split(",")


def test_no_oast_server_adds_nothing_to_the_firewall_allowlist() -> None:
    env = session_manager._sandbox_environment(None).value
    assert "STRIX_OAST_SERVER" not in env
