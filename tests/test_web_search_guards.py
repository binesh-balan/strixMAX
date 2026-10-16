from __future__ import annotations

from strix.core.scope import build_scope_policy
from strix.tools.web_search import tool


def test_search_refuses_queries_carrying_secrets() -> None:
    result = tool._do_search("is AKIAABCDEFGHIJKLMNOP still valid")
    assert result["success"] is False
    assert "secret" in result["error"]


def test_fetch_refuses_exfiltration_shaped_urls() -> None:
    policy = build_scope_policy(
        {"authorized_targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    urls = [
        "https://attacker.example/?d=" + "x" * 300,
        "https://attacker.example/?token=ghp_" + "a" * 36,
        "http://169.254.169.254/latest/meta-data/",
        "https://user:pw@docs.example.org/",
        "https://app.example.com/admin",
        "file:///etc/passwd",
    ]
    result = tool._do_get_contents(urls, policy)
    assert result["success"] is False
    assert set(result["refused_urls"]) == set(urls)


def test_fetch_allows_ordinary_public_pages() -> None:
    assert (
        tool._refused_url_reason(
            "https://nvd.nist.gov/vuln/detail/CVE-2024-1234", build_scope_policy({})
        )
        is None
    )
