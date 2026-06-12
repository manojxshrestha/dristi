"""
Auth session — manages authenticated HTTP sessions for bug bounty hunting.

Provides an AuthSession class that holds credentials (cookies, tokens, headers)
and exports them as environment variables for subprocess consumption.
"""

import argparse
import hashlib
import os


class AuthSession:
    def __init__(self, headers: dict[str, str] | None = None, session_id: str | None = None):
        self._headers = headers or {}
        self._session_id = session_id

    def export_to_env(self, env: dict[str, str]) -> None:
        if self._headers:
            header_lines = "\n".join(
                f"{k}: {v}" for k, v in self._headers.items()
            )
            env["BBHUNT_AUTH_HEADERS"] = header_lines
        if self._session_id:
            env["BBHUNT_SESSION_ID"] = self._session_id

    def is_empty(self) -> bool:
        return not self._headers

    def describe(self) -> str:
        if not self._headers:
            return "Auth: none"
        masked = ", ".join(
            f"{k}: {v[:8]}..." if len(v) > 8 else f"{k}: ***"
            for k, v in self._headers.items()
        )
        sid = f" session={self._session_id}" if self._session_id else ""
        return f"Auth: {masked}{sid}"


def add_cli_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("Authentication")
    group.add_argument("--auth-header", action="append", dest="auth_headers",
                       help="Add an auth header (Name: Value). Repeatable.")
    group.add_argument("--auth-cookie", help="Session cookie string (raw Cookie header value).")
    group.add_argument("--auth-token", help="Bearer token.")
    group.add_argument("--auth-session-id", help="Session ID for correlation.")
    group.add_argument("--auth-no-session", action="store_true",
                       help="Skip session ID generation for this run.")


def session_from_args(args) -> AuthSession:
    headers: dict[str, str] = {}

    if hasattr(args, "auth_headers") and args.auth_headers:
        for h in args.auth_headers:
            if ":" in h:
                name, value = h.split(":", 1)
                headers[name.strip()] = value.strip()

    if hasattr(args, "auth_cookie") and args.auth_cookie:
        headers["Cookie"] = args.auth_cookie

    if hasattr(args, "auth_token") and args.auth_token:
        headers["Authorization"] = f"Bearer {args.auth_token}"

    session_id = None
    if headers and not (hasattr(args, "auth_no_session") and args.auth_no_session):
        raw = "\n".join(f"{k}: {v}" for k, v in sorted(headers.items()))
        session_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    if hasattr(args, "auth_session_id") and args.auth_session_id:
        session_id = args.auth_session_id

    return AuthSession(headers=headers, session_id=session_id)
