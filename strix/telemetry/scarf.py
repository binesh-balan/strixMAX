from __future__ import annotations

import logging
import urllib.parse
from typing import TYPE_CHECKING, Any

import requests

from strix.config import load_settings
from strix.telemetry._common import (
    SEND_TIMEOUT,
    base_props,
    exception_props,
    get_scan_phase,
    get_version,
    is_first_run,
    model_provider,
)


if TYPE_CHECKING:
    from strix.report.state import ReportState


logger = logging.getLogger(__name__)

_SCARF_ENDPOINT = "https://strix.gateway.scarf.sh"

# Scarf events travel as a URL query string, which ends up in gateway and proxy
# access logs. Only these coarse, low-cardinality fields are ever sent: no
# session id, usage volumes, cost, finding counts, provider tallies, or skills.
_COARSE_FIELDS = frozenset(
    {
        "os",
        "arch",
        "python",
        "model_provider",
        "auth_mode",
        "scan_mode",
        "scan_type",
        "interactive",
        "has_instructions",
        "first_run",
        "exit_reason",
        "error_type",
        "phase",
        "exception_type",
    }
)


def _is_enabled() -> bool:
    return load_settings().telemetry.enabled


def _send(event: str, properties: dict[str, Any]) -> bool:
    if not _is_enabled():
        logger.debug("scarf disabled; skipping event %s", event)
        return False
    try:
        props = dict(properties)
        version = str(props.pop("strix_version", get_version()) or "unknown")
        path = f"/{urllib.parse.quote(event, safe='')}/{urllib.parse.quote(version, safe='')}"
        query = urllib.parse.urlencode(
            {
                k: ("" if v is None else str(v))[:64]
                for k, v in props.items()
                if k in _COARSE_FIELDS
            },
        )
        url = f"{_SCARF_ENDPOINT}{path}"
        if query:
            url = f"{url}?{query}"
        with requests.post(url, timeout=SEND_TIMEOUT):
            pass
    except Exception:  # noqa: BLE001
        logger.debug("scarf send failed for event %s", event, exc_info=True)
        return False
    else:
        logger.debug("scarf event sent: %s", event)
        return True


def start(
    model: str | None,
    scan_mode: str | None,
    is_whitebox: bool,
    interactive: bool,
    has_instructions: bool,
    auth_mode: str | None = None,
) -> None:
    _send(
        "scan_started",
        {
            **base_props(),
            "model_provider": model_provider(model),
            "auth_mode": auth_mode or "api_key",
            "scan_mode": scan_mode or "unknown",
            "scan_type": "whitebox" if is_whitebox else "blackbox",
            "interactive": interactive,
            "has_instructions": has_instructions,
            "first_run": is_first_run(),
        },
    )


def end(report_state: ReportState, exit_reason: str = "completed") -> None:
    if report_state.scarf_scan_ended_sent:
        return
    if report_state.scan_ended_exit_reason is None:
        report_state.scan_ended_exit_reason = exit_reason

    report_state.scarf_scan_ended_sent = _send(
        "scan_ended",
        {
            **base_props(),
            "auth_mode": report_state.run_record.get("auth_mode") or "api_key",
            "exit_reason": report_state.scan_ended_exit_reason,
        },
    )


def error(error_type: str, exc: BaseException | None = None) -> None:
    props: dict[str, Any] = {
        **base_props(),
        "error_type": error_type,
        "phase": get_scan_phase(),
    }
    if exc is not None:
        props.update(exception_props(exc))
    _send("error", props)
