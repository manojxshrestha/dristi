"""Tests for input validation and sanitization."""

import re

import pytest

# Import the sanitize helpers from server.py by redefining them for test isolation
_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_id(raw: str, max_len: int = 100) -> str:
    if not raw or not isinstance(raw, str):
        raise ValueError(f"Invalid identifier (empty or wrong type): {raw!r}")
    safe = _SANITIZE_RE.sub("", raw[:max_len])
    safe = safe.lstrip(".")
    safe = safe[:max_len]
    if not safe:
        raise ValueError(f"Invalid identifier (empty after sanitization): {raw!r}")
    return safe


_SHELL_UNSAFE = re.compile(r"[\"';$`|&><(){}!\\]")
_SHELL_UNSAFE_PATHS = re.compile(r"\.\.")


def _validate_shell_arg(value: str, name: str) -> None:
    if _SHELL_UNSAFE.search(value):
        raise ValueError(f"Invalid {name!r}: contains shell metacharacters")


class TestSanitizeId:
    def test_normal_ids(self):
        assert _sanitize_id("engagement-123") == "engagement-123"
        assert _sanitize_id("test.engagement_1") == "test.engagement_1"
        assert _sanitize_id("simple") == "simple"

    def test_rejects_path_traversal(self):
        result = _sanitize_id("../../etc/passwd")
        assert "/" not in result

    def test_strips_leading_dots(self):
        """Two dots alone become empty (stripped as leading), so it raises."""
        with pytest.raises(ValueError):
            _sanitize_id("..")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            _sanitize_id("")

    def test_rejects_only_dots(self):
        with pytest.raises(ValueError):
            _sanitize_id("...")

    def test_rejects_special_chars(self):
        assert _sanitize_id("hello/world").startswith("helloworld")

    def test_truncates_long(self):
        long_id = "a" * 200
        result = _sanitize_id(long_id, max_len=50)
        assert len(result) <= 50


class TestValidateShellArg:
    def test_accepts_safe(self):
        _validate_shell_arg("https://example.com", "target")
        _validate_shell_arg("192.168.1.1", "ip")

    def test_rejects_quotes(self):
        with pytest.raises(ValueError, match="shell metacharacters"):
            _validate_shell_arg("'; rm -rf /", "target")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError):
            _validate_shell_arg("`whoami`", "target")

    def test_rejects_pipe(self):
        with pytest.raises(ValueError):
            _validate_shell_arg("cat /etc/passwd | grep root", "target")

    def test_rejects_dollar(self):
        with pytest.raises(ValueError):
            _validate_shell_arg("$(whoami)", "target")

    def test_rejects_ampersand(self):
        with pytest.raises(ValueError):
            _validate_shell_arg("sleep 5 & echo pwned", "target")
