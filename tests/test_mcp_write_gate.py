from __future__ import annotations

from types import SimpleNamespace

from strix.tools.mcp.agent_tools import tool_call_permitted
from strix.tools.mcp.config import McpConnectionConfig


def _tool(name: str, read_only: bool | None) -> SimpleNamespace:
    annotations = None if read_only is None else SimpleNamespace(readOnlyHint=read_only)
    return SimpleNamespace(name=name, annotations=annotations)


def _config(**kwargs: object) -> McpConnectionConfig:
    return McpConnectionConfig(name="db", url="https://mcp.example/", **kwargs)  # type: ignore[arg-type]


def test_read_only_tools_are_callable_by_default() -> None:
    assert tool_call_permitted(_config(), _tool("query", read_only=True))


def test_unannotated_and_write_tools_are_blocked_by_default() -> None:
    assert not tool_call_permitted(_config(), _tool("drop_table", read_only=False))
    assert not tool_call_permitted(_config(), _tool("anything", read_only=None))


def test_operator_can_allow_write_tools() -> None:
    assert tool_call_permitted(
        _config(allow_write_tools=True), _tool("drop_table", read_only=False)
    )
    assert tool_call_permitted(
        _config(allowed_tools=["drop_table"]), _tool("drop_table", read_only=False)
    )
