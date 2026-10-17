from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.core import scope
from strix.core.scope import ScopePolicy, build_scope_policy, sandbox_egress_env
from strix.tools.proxy import caido_api


if TYPE_CHECKING:
    import pytest


def _ctx(*targets: tuple[str, str]) -> dict[str, Any]:
    return {
        "authorized_targets": [
            {"type": ttype, "value": value, "workspace_path": ""} for ttype, value in targets
        ]
    }


def test_domain_target_covers_subdomains_only() -> None:
    policy = build_scope_policy(_ctx(("web_application", "https://example.com/app")))
    assert policy.allows_url("https://example.com/login")
    assert policy.allows_url("https://api.example.com/v1")
    assert not policy.allows_url("https://example.com.attacker.net/")
    assert not policy.allows_url("https://attacker.example/")
    assert not policy.allows_url("http://169.254.169.254/latest/meta-data/")


def test_ip_and_cidr_targets() -> None:
    policy = build_scope_policy(_ctx(("ip_address", "10.0.0.0/24"), ("ip_address", "192.0.2.7")))
    assert policy.allows_host("10.0.0.42")
    assert policy.allows_host("192.0.2.7")
    assert not policy.allows_host("10.0.1.1")
    assert not policy.allows_host("example.com")


def test_local_target_allows_the_host_gateway_only_when_named() -> None:
    remote = build_scope_policy(_ctx(("web_application", "https://example.com")))
    assert not remote.allows_host("host.docker.internal")
    local = build_scope_policy(_ctx(("web_application", "http://host.docker.internal:3000")))
    assert local.local_target
    assert local.allows_host("host.docker.internal")


def test_source_only_scan_is_not_enforced() -> None:
    policy = build_scope_policy(_ctx(("local_code", "/code")))
    assert not policy.enforced
    assert policy.allows_url("https://anything.example/")


def test_malformed_scope_context_yields_empty_policy() -> None:
    assert build_scope_policy("") == ScopePolicy()


def test_egress_env_defaults_to_restricted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SANDBOX_EGRESS", raising=False)
    monkeypatch.setattr(scope, "_resolve", lambda _host: ["203.0.113.5"])
    env = sandbox_egress_env(
        build_scope_policy(
            _ctx(("web_application", "https://example.com"), ("ip_address", "10.1.0.0/16"))
        )
    )
    assert env == {
        "STRIX_EGRESS_MODE": "restricted",
        "STRIX_EGRESS_ALLOW": "10.1.0.0/16,203.0.113.5",
        "STRIX_ALLOW_HOST_GATEWAY": "0",
    }


def test_egress_mode_rejects_unknown_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EGRESS", "wide-open")
    assert scope.egress_mode() == "restricted"
    monkeypatch.setenv("STRIX_SANDBOX_EGRESS", "strict")
    assert scope.egress_mode() == "strict"


def test_cross_host_replay_drops_inherited_credentials() -> None:
    headers = {
        "Host": "app.example.com",
        "Authorization": "Bearer secret",
        "Cookie": "session=abc",
        "X-Api-Key": "k",
        "Accept": "*/*",
    }
    kept, dropped = caido_api.strip_credentials_on_host_change(
        "https://app.example.com/a", "https://other.example.com/a", headers, {}
    )
    assert kept == {"Accept": "*/*"}
    assert sorted(dropped) == ["Authorization", "Cookie", "X-Api-Key"]


def test_same_host_replay_keeps_credentials() -> None:
    headers = {"Authorization": "Bearer secret"}
    kept, dropped = caido_api.strip_credentials_on_host_change(
        "https://app.example.com/a", "https://app.example.com/b", headers, {}
    )
    assert kept == headers
    assert dropped == []


def test_explicit_credentials_survive_a_host_change() -> None:
    headers = {"Authorization": "Bearer chosen", "Cookie": "session=abc"}
    kept, _ = caido_api.strip_credentials_on_host_change(
        "https://a.example.com/",
        "https://b.example.com/",
        headers,
        {"Authorization": "Bearer chosen"},
    )
    assert kept == {"Authorization": "Bearer chosen"}
