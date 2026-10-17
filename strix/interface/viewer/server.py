"""Local HTTP server that serves the viewer SPA and a run's data from disk.

Design notes:
- Uses only the standard library (no new runtime dependency). The workload is
  serving static files plus a handful of JSON reads off disk, so an async stack
  buys nothing here.
- The browser polls the JSON endpoints (~1s) rather than using SSE: a finished
  run stops polling, and short-lived polls survive sleep/network blips without
  server-side connection state, which suits a stdlib ThreadingHTTPServer.
- All reads happen per-request straight from disk, so the same server serves a
  live in-progress run and a finished one identically; the SPA distinguishes
  them via the ``finished`` flag on /api/run.
- Request hardening: every request's Host header must name this server (a
  loopback name, an IP literal, or the bound host) to defeat DNS rebinding;
  POSTs must be same-origin JSON with a bounded body; and the bootstrap token
  is single-use and stripped from the address bar by a redirect.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import mimetypes
import re
import secrets
import ssl
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from strix.core.paths import run_record_path
from strix.interface.viewer import auth
from strix.interface.viewer.transcript import (
    build_run_state,
    primary_target,
    read_report_markdown,
    read_run_summary,
    read_vulnerabilities,
    severity_counts,
)


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)


def bundle_dir() -> Path:
    """Directory holding the committed, prebuilt SPA (index.html + assets)."""
    return Path(__file__).resolve().parent / "static"


def bundle_is_built() -> bool:
    return (bundle_dir() / "index.html").is_file()


def _iter_run_dirs(base_dir: Path) -> list[Path]:
    """Every run directory under ``base_dir``, newest first by record mtime."""
    if not base_dir.is_dir():
        return []
    run_dirs = [child for child in base_dir.iterdir() if run_record_path(child).is_file()]
    run_dirs.sort(key=lambda child: run_record_path(child).stat().st_mtime, reverse=True)
    return run_dirs


def run_list_entry(run_dir: Path) -> dict[str, Any]:
    """Compact summary of a single run for the history list."""
    record = read_run_summary(run_dir)
    return {
        "name": record.get("run_name") or run_dir.name,
        "target": primary_target(record),
        "scan_mode": record.get("scan_mode"),
        "status": record.get("status"),
        "start_time": record.get("start_time"),
        "end_time": record.get("end_time"),
        "finished": bool(record.get("finished")),
        "severity_counts": severity_counts(read_vulnerabilities(run_dir)),
    }


def build_runs_payload(base_dir: Path, *, verified: bool) -> dict[str, Any]:
    """The /api/runs payload. Gates the run list behind email verification.

    The count is always advertised so the UI can tease the history, but the
    entries only appear once the viewer is verified.
    """
    run_dirs = _iter_run_dirs(base_dir)
    count = len(run_dirs)
    if not verified:
        return {"locked": True, "count": count, "runs": []}
    return {"locked": False, "count": count, "runs": [run_list_entry(d) for d in run_dirs]}


def resolve_run_dir(base_dir: Path, run_param: str | None, default_run_dir: Path) -> Path | None:
    """Resolve a ``?run=`` value to a real run directory under ``base_dir``.

    Returns ``default_run_dir`` when no run is requested. Rejects traversal and
    unknown runs (returns None) so the caller can answer 404.
    """
    if not run_param:
        return default_run_dir
    base = base_dir.resolve()
    candidate = (base / run_param).resolve()
    # Only direct children of the runs base that actually hold a run record.
    if candidate.parent != base or not run_record_path(candidate).is_file():
        return None
    return candidate


# Prefix of the cookie carrying the per-process session capability. The bound
# port is appended (``strix_viewer_session_<port>``) because browsers scope
# cookies by host only, never by port: concurrent viewers on 127.0.0.1 would
# otherwise share one cookie slot and clobber each other's session.
SESSION_COOKIE_PREFIX = "strix_viewer_session"

# Largest POST body the viewer reads. Every endpoint takes a small JSON object;
# anything bigger is refused with 413 before it is read.
MAX_BODY_BYTES = 1 << 20

# POST endpoints that may also arrive as text/plain: the committed SPA bundle
# sends /api/event with navigator.sendBeacon(string), which cannot set a JSON
# content type. It carries only an allowlisted telemetry event name.
_TEXT_PLAIN_POSTS = frozenset({"/api/event"})

_TOKEN_QUERY_RE = re.compile(r"(token=)[^&\s\"]*", re.IGNORECASE)


def redact_token(text: str) -> str:
    """Mask ``token=`` query values so the bootstrap token never reaches a log."""
    return _TOKEN_QUERY_RE.sub(r"\1<redacted>", text)


class _ViewerState:
    def __init__(
        self,
        run_dir: Path,
        assets_dir: Path,
        steer_handler: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.assets_dir = assets_dir
        # The strix_runs directory that holds the launched run; used to
        # enumerate and resolve other runs for the history list.
        self.base_dir = run_dir.parent
        # Set only when the viewer runs inside a live scan process (the TUI
        # launcher), which can deliver a message to a running agent. Absent for
        # standalone ``strix view`` / finished runs, so steering is unavailable.
        self.steer_handler = steer_handler
        # Unguessable per-process bootstrap capability. It is minted here,
        # printed/opened for the operator who started the server (see
        # ``authorized_url``), and exchanged -- once -- for a session cookie.
        # Reachability of the port (e.g. when bound with ``--host``) is not
        # enough to read run data, steer a live scan, trigger a report, or
        # browse history -- the token is never handed to a caller who merely
        # reaches ``/``.
        self.bootstrap_token = secrets.token_urlsafe(32)
        self._bootstrap_used = False
        self._bootstrap_lock = threading.Lock()
        # The cookie value is a separate secret, so the URL token (which can
        # sit in shell scrollback or a TUI screen) is not itself a session.
        self.session_token = secrets.token_urlsafe(32)
        # Finalized in ``serve()`` once the port is known (the server binds
        # after this state is constructed); see SESSION_COOKIE_PREFIX.
        self.cookie_name = SESSION_COOKIE_PREFIX
        self.host = "127.0.0.1"
        self.port = 0

    def redeem_bootstrap(self, supplied: str) -> bool:
        """Accept the bootstrap token exactly once."""
        if not supplied:
            return False
        with self._bootstrap_lock:
            if self._bootstrap_used or not secrets.compare_digest(supplied, self.bootstrap_token):
                return False
            self._bootstrap_used = True
            return True


def _make_handler(state: _ViewerState) -> type[BaseHTTPRequestHandler]:
    class ViewerHandler(BaseHTTPRequestHandler):
        server_version = "StrixViewer/1.0"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            logger.debug("viewer %s - %s", self.address_string(), redact_token(format % args))

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path
            if not self._host_allowed():
                self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "invalid_host"})
                return
            try:
                query = parse_qs(parts.query)
                if "token" in query and not path.startswith("/api/"):
                    self._handle_bootstrap(path, query)
                elif path.startswith("/api/"):
                    self._handle_api(path, query)
                else:
                    self._handle_static(path)
            except BrokenPipeError:
                # The browser closed the connection mid-response (e.g. it
                # navigated away between polls). Not an error.
                logger.debug("viewer client disconnected during %s", path)
            except Exception:
                # A bad request must never kill the worker thread.
                logger.exception("viewer request failed: %s", path)
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            if not self._post_allowed(path):
                return
            try:
                if path == "/api/event":
                    self._handle_event()
                elif path == "/api/auth/otp/start":
                    self._handle_otp_start()
                elif path == "/api/auth/otp/verify":
                    self._handle_otp_verify()
                elif path == "/api/auth/forget":
                    self._handle_forget()
                elif path == "/api/report/send":
                    self._handle_report_send()
                elif path == "/api/feedback":
                    self._handle_feedback()
                elif path == "/api/agents/steer":
                    self._handle_steer()
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
            except BrokenPipeError:
                logger.debug("viewer client disconnected during POST %s", path)
            except Exception:
                # A bad request must never kill the worker thread.
                logger.exception("viewer request failed: POST %s", path)
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

        def _post_allowed(self, path: str) -> bool:
            """CSRF / DNS-rebinding / size gate shared by every POST endpoint.

            Answers the request itself and returns False when it is refused.
            """
            if not self._host_allowed():
                self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "invalid_host"})
                return False
            if not self._origin_allowed():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "cross_origin"})
                return False
            content_type = self.headers.get_content_type()
            allowed_types = {"application/json"}
            if path in _TEXT_PLAIN_POSTS:
                allowed_types.add("text/plain")
            if content_type not in allowed_types:
                self._send_json(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "unsupported_media_type"}
                )
                return False
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_length"})
                return False
            if length > MAX_BODY_BYTES:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "too_large"})
                return False
            self._content_length = length
            return True

        def _host_allowed(self) -> bool:
            """Reject Host headers that don't name this server (DNS rebinding).

            A rebinding page reaches the loopback port under the attacker's own
            hostname, which the browser then sends as Host. Loopback names, IP
            literals (which cannot be rebound), and the bound host are accepted.
            """
            raw = (self.headers.get("Host") or "").strip()
            if not raw:
                return False
            try:
                parsed = urlsplit(f"//{raw}")
                hostname = (parsed.hostname or "").lower()
                port = parsed.port
            except ValueError:
                return False
            if (port or 80) != state.port:
                return False
            if hostname in {"localhost", state.host.lower().strip("[]")}:
                return True
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                return False
            return True

        def _origin_allowed(self) -> bool:
            """Only same-origin browser requests may POST.

            Browsers always send Origin on a cross-origin POST, so a missing
            Origin is refused only when Fetch Metadata says the request came
            from another site. Non-browser clients send neither.
            """
            origin = self.headers.get("Origin")
            if origin is None:
                site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
                return site in {"", "same-origin", "none"}
            expected = f"{self._scheme()}://{self.headers.get('Host', '').strip()}"
            return origin.strip().lower() == expected.lower()

        def _scheme(self) -> str:
            return "https" if isinstance(self.connection, ssl.SSLSocket) else "http"

        def _read_body(self) -> dict[str, Any]:
            length = getattr(self, "_content_length", 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return {}
            return body if isinstance(body, dict) else {}

        # Funnel events the viewer is allowed to forward. This handler is the
        # trust boundary: only these event names, with only their known props,
        # ever reach PostHog. Everything else (including any PII) is dropped.
        _EMAIL_EVENTS = frozenset(
            {"email_submitted", "email_verified", "report_sent", "work_email_required"}
        )

        def _handle_event(self) -> None:
            # Session-gated like every other POST so a page that merely reaches
            # the port cannot inject telemetry.
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            body = self._read_body()
            # Forwarded as anonymous PostHog events that respect the global
            # telemetry opt-out. Never forward the email, code, or report body:
            # only the whitelisted event names and their known props are passed.
            event = body.get("event")
            if event == "cta_clicked":
                from strix.telemetry import posthog

                cta = str(body.get("cta") or "unknown")
                surface = body.get("surface")
                posthog.viewer_cta_clicked(cta, surface=str(surface) if surface else None)
            elif event in self._EMAIL_EVENTS:
                from strix.telemetry import posthog

                purpose = body.get("purpose")
                posthog.viewer_email_event(str(event), purpose=str(purpose) if purpose else None)
            elif event == "agent_steered":
                from strix.telemetry import posthog

                posthog.viewer_agent_steered()
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()

        def _handle_api(self, path: str, query: dict[str, list[str]]) -> None:
            # The cross-run history list (/api/runs) unlocks its entries only for
            # a caller that holds this process's session capability *and* is
            # email verified, so merely reaching an exposed --host port never
            # leaks the run list (the payload still advertises the count as a
            # teaser).
            if path == "/api/runs":
                unlocked = self._has_session() and auth.is_verified()
                payload = build_runs_payload(state.base_dir, verified=unlocked)
                self._send_json(HTTPStatus.OK, payload)
                return
            if path == "/api/capabilities":
                # Steering is only possible when the viewer shares a live scan's
                # coordinator + event loop (the TUI launcher wires a handler).
                self._send_json(HTTPStatus.OK, {"can_steer": state.steer_handler is not None})
                return
            if path == "/api/auth/status":
                self._handle_auth_status()
                return

            # All remaining GET endpoints expose run metadata or scan output.
            # Require the capability even for the run used to launch the viewer;
            # reachability of an exposed --host port must not grant data access.
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return

            run_values = query.get("run")
            run_param = run_values[0] if run_values else None
            run_dir = resolve_run_dir(state.base_dir, run_param, state.run_dir)
            if run_dir is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown run"})
                return

            # Any run other than the one used to launch the viewer is part of the
            # email-gated history. The session check above applies to both paths;
            # verification adds a second gate for historical run data.
            if run_dir.resolve() != state.run_dir.resolve() and not auth.is_verified():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unverified"})
                return

            if path == "/api/run":
                self._send_json(HTTPStatus.OK, read_run_summary(run_dir))
            elif path == "/api/vulnerabilities":
                self._send_json(HTTPStatus.OK, read_vulnerabilities(run_dir))
            elif path == "/api/report":
                self._send_json(HTTPStatus.OK, {"markdown": read_report_markdown(run_dir)})
            elif path == "/api/transcript":
                self._send_json(HTTPStatus.OK, build_run_state(run_dir))
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

        def _handle_auth_status(self) -> None:
            # The cached verified email is only disclosed to a caller holding this
            # process's session capability, so a cookie-less client on an exposed
            # --host port cannot read it; everyone else looks unverified.
            # Verification is reported through is_verified() so an expired record
            # is advertised as unverified -- otherwise the SPA would suppress
            # re-verification while history stays locked, stranding the user.
            if not self._has_session():
                self._send_json(HTTPStatus.OK, {"verified": False, "email": None})
                return
            record = auth.read_auth()
            self._send_json(
                HTTPStatus.OK,
                {
                    "verified": auth.is_verified(),
                    "email": record.get("email") if record else None,
                },
            )

        def _handle_otp_start(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            email = str(self._read_body().get("email") or "").strip()
            if not email:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_email"})
                return
            try:
                auth.otp_start(email)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            self._send_json(HTTPStatus.OK, {"ok": True})

        def _handle_otp_verify(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            body = self._read_body()
            email = str(body.get("email") or "").strip()
            code = str(body.get("code") or "").strip()
            if not email or not code:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_code"})
                return
            try:
                result = auth.otp_verify(email, code)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            auth.write_auth(
                email=result.get("email") or email,
                token=result["token"],
                verified_at=result.get("expires_at") or "",
            )
            verified_email = result.get("email") or email
            self._send_json(HTTPStatus.OK, {"verified": True, "email": verified_email})

        def _handle_forget(self) -> None:
            # Clearing the cached verification is a state change, so it requires
            # this process's session capability: a cookie-less caller on an
            # exposed --host port must not be able to log the operator out.
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            auth.forget()
            self._send_json(HTTPStatus.OK, {"ok": True})

        def _handle_report_send(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            record = auth.read_auth()
            if record is None:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unverified"})
                return
            run_param = str(self._read_body().get("run") or "") or None
            run_dir = resolve_run_dir(state.base_dir, run_param, state.run_dir)
            if run_dir is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown run"})
                return

            summary = read_run_summary(run_dir)
            # Emailing only makes sense for a completed run; a live scan would
            # send a partial report. The UI hides the entry point, but fail
            # closed here too so the endpoint can't be driven mid-scan.
            if not summary.get("finished", False):
                self._send_json(HTTPStatus.CONFLICT, {"error": "run_not_finished"})
                return

            from strix.interface.viewer.report_pdf import build_encrypted_report

            pdf_bytes, password, filename = build_encrypted_report(run_dir)
            run_name = str(summary.get("run_name") or run_dir.name)
            target = primary_target(summary) or "unknown target"
            try:
                # The password is intentionally NOT passed here; only the
                # encrypted PDF bytes reach the relay.
                auth.report_send(record["token"], pdf_bytes, filename, run_name, target)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            # The password is returned only to a session-authorized browser.
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "password": password, "filename": filename},
            )

        # Cap on a feedback message so a runaway client cannot flood the relay.
        _FEEDBACK_MESSAGE_MAX = 5000

        def _handle_feedback(self) -> None:
            # Requires this process's session capability, like the other POSTs,
            # so an exposed --host port can't be used to spam the relay.
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            body = self._read_body()
            email = str(body.get("email") or "").strip()
            message = str(body.get("message") or "").strip()
            if not email:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_email"})
                return
            if not message:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_message"})
                return
            message = message[: self._FEEDBACK_MESSAGE_MAX]
            try:
                auth.feedback_submit(email, message)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            # Server-authoritative: fire only after a successful relay (respects
            # the telemetry opt-out; no message/email content is sent).
            from strix.telemetry import posthog

            posthog.viewer_feedback_submitted()
            self._send_json(HTTPStatus.OK, {"ok": True})

        # Cap on a steering message so a runaway client cannot flood the agent.
        _STEER_MESSAGE_MAX = 4000

        def _handle_steer(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            body = self._read_body()
            agent_id = body.get("agent_id")
            message = body.get("message")
            if not isinstance(agent_id, str) or not agent_id.strip():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_agent_id"})
                return
            if (
                not isinstance(message, str)
                or not message.strip()
                or len(message) > self._STEER_MESSAGE_MAX
            ):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_message"})
                return
            if state.steer_handler is None:
                # Standalone / finished-run viewing has no live scan to steer.
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "steering_unavailable"})
                return
            delivered = state.steer_handler(agent_id, message)
            if delivered:
                self._send_json(HTTPStatus.OK, {"ok": True})
            else:
                self._send_json(HTTPStatus.OK, {"ok": False, "error": "not_delivered"})

        def _send_relay_error(self, exc: auth.RelayError) -> None:
            status_by_code = {
                "rate_limited": HTTPStatus.TOO_MANY_REQUESTS,
                "invalid_email": HTTPStatus.BAD_REQUEST,
                "invalid_message": HTTPStatus.BAD_REQUEST,
                "work_email_required": HTTPStatus.BAD_REQUEST,
                "invalid_code": HTTPStatus.FORBIDDEN,
                "reverify": HTTPStatus.UNAUTHORIZED,
                "forbidden": HTTPStatus.FORBIDDEN,
                "too_large": HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "unavailable": HTTPStatus.BAD_GATEWAY,
            }
            status = status_by_code.get(exc.code, HTTPStatus.BAD_GATEWAY)
            self._send_json(status, {"error": exc.code})

        def _cookies(self) -> dict[str, str]:
            jar: dict[str, str] = {}
            for chunk in (self.headers.get("Cookie") or "").split(";"):
                name, sep, value = chunk.strip().partition("=")
                if sep:
                    jar[name] = value
            return jar

        def _has_session(self) -> bool:
            """True when the request carries this process's session capability.

            The cookie is set only by the single-use bootstrap redirect, so only
            the browser this process handed the link to can pass. A direct
            caller on an exposed port has no cookie and is rejected.
            """
            supplied = self._cookies().get(state.cookie_name, "")
            return bool(supplied) and secrets.compare_digest(supplied, state.session_token)

        def _handle_bootstrap(self, path: str, query: dict[str, list[str]]) -> None:
            """Trade a ``?token=`` page load for the session cookie, then drop the token.

            Always answers with a redirect to the same path without ``token``, so
            the bootstrap token never stays in the address bar, history, or a
            Referer. The cookie is set only the first time the correct token is
            presented; a browser that already holds the cookie keeps working.
            """
            supplied = (query.get("token") or [""])[0]
            remaining = {key: values for key, values in query.items() if key != "token"}
            # Never a scheme-relative (``//host``) location: always this server.
            location = "/" + path.lstrip("/")
            if remaining:
                location += "?" + urlencode(remaining, doseq=True)
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", "0")
            if state.redeem_bootstrap(supplied):
                # HttpOnly (JS never needs it; fetch sends it automatically),
                # SameSite=Strict (never sent from a cross-site context), and
                # Secure whenever the viewer is served over TLS.
                secure = "; Secure" if self._scheme() == "https" else ""
                self.send_header(
                    "Set-Cookie",
                    f"{state.cookie_name}={state.session_token}; Path=/; HttpOnly; "
                    f"SameSite=Strict{secure}",
                )
            self.end_headers()

        def _handle_static(self, path: str) -> None:
            target = self._resolve_asset(path)
            if target is None:
                # SPA fallback: unknown non-asset routes render index.html so
                # client-side deep links work.
                target = state.assets_dir / "index.html"
            if not target.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            content = target.read_bytes()
            content_type, _ = mimetypes.guess_type(str(target))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(content)

        def _resolve_asset(self, path: str) -> Path | None:
            rel = unquote(path).lstrip("/")
            if not rel or rel.endswith("/"):
                return None
            root = state.assets_dir.resolve()
            candidate = (root / rel).resolve()
            # Path-traversal guard: never serve outside the bundle root.
            if root != candidate and root not in candidate.parents:
                logger.warning("viewer rejected traversal attempt: %s", path)
                return None
            return candidate if candidate.is_file() else None

        def _send_json(self, status: HTTPStatus, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ViewerHandler


def is_loopback_host(host: str) -> bool:
    """True for ``localhost`` and loopback IP literals (127.0.0.0/8, ::1)."""
    host = host.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def authorized_url(base_url: str, token: str) -> str:
    """URL that bootstraps the viewer session for the operator.

    Presenting ``token`` on the initial page load is what mints the session
    cookie, so this URL is printed / opened only for the operator who started
    the server. The token is single-use: the first browser to open the link
    gets the session, and the server immediately redirects to a token-free URL.
    """
    return f"{base_url}/?{urlencode({'token': token})}"


def serve(
    run_dir: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = True,
    steer_handler: Callable[[str, str], bool] | None = None,
) -> tuple[ThreadingHTTPServer, str, str]:
    """Start the viewer server on a background thread; return (server, url, token).

    ``url`` is the bare base; pass it through ``authorized_url(url, token)`` to
    build the operator link that authorizes the browser. ``token`` is the
    single-use bootstrap token, not the session cookie value.

    Binds an ephemeral port by default. If a fixed ``port`` is requested but in
    use, falls back to an ephemeral port. Reused by both the ``strix view``
    command and the in-TUI launcher; callers own the server's lifetime.

    ``steer_handler`` is supplied only by the in-TUI launcher, which runs inside
    the live scan process and can forward a message to a running agent. Left
    ``None`` (standalone ``strix view``), steering is reported unavailable.
    """
    assets_dir = bundle_dir()
    state = _ViewerState(run_dir=run_dir, assets_dir=assets_dir, steer_handler=steer_handler)
    handler = _make_handler(state)

    try:
        httpd = ThreadingHTTPServer((host, port), handler)
    except OSError:
        if port == 0:
            raise
        logger.info("viewer port %s unavailable, falling back to an ephemeral port", port)
        httpd = ThreadingHTTPServer((host, 0), handler)

    httpd.daemon_threads = True
    bound_port = int(httpd.server_address[1])
    state.cookie_name = f"{SESSION_COOKIE_PREFIX}_{bound_port}"
    state.host = host
    state.port = bound_port
    url_host = f"[{host}]" if ":" in host else host
    url = f"http://{url_host}:{bound_port}"

    thread = threading.Thread(target=httpd.serve_forever, name="strix-viewer", daemon=True)
    thread.start()

    if open_browser:
        _open_browser(authorized_url(url, state.bootstrap_token))

    return httpd, url, state.bootstrap_token


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001 - launching the browser is best-effort
        logger.debug("could not open browser for %s", redact_token(url), exc_info=True)


__all__ = [
    "MAX_BODY_BYTES",
    "authorized_url",
    "bundle_dir",
    "bundle_is_built",
    "is_loopback_host",
    "redact_token",
    "serve",
]
