"""Tests for server.py MCP tools (unit-level, no subprocess)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def temp_engagements(tmp_path):
    """Override ENGAGEMENTS_DIR to a temp path."""
    import server as srv
    original = srv.ENGAGEMENTS_DIR
    srv.ENGAGEMENTS_DIR = tmp_path / "engagements"
    yield srv.ENGAGEMENTS_DIR
    srv.ENGAGEMENTS_DIR = original


class TestSanitizeId:
    def _sanitize_id(self, raw):
        import server as srv
        return srv._sanitize_id(raw)

    def test_normal_ids(self):
        assert self._sanitize_id("engagement-123") == "engagement-123"
        assert self._sanitize_id("test.engagement_1") == "test.engagement_1"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            self._sanitize_id("")

    def test_rejects_traversal(self):
        result = self._sanitize_id("../../etc/passwd")
        assert "/" not in result

    def test_rejects_leading_dots(self):
        with pytest.raises(ValueError):
            self._sanitize_id("..")


class TestParseWstgFile:
    def test_parses_frontmatter(self, tmp_path):
        import server as srv
        md = tmp_path / "test.md"
        md.write_text("---\nid: WSTG-TEST-01\ntitle: Test\n---\n\nBody content", encoding="utf-8")
        result = srv._parse_wstg_file(md)
        assert result["id"] == "WSTG-TEST-01"
        assert "Body content" in result["content"]

    def test_no_frontmatter(self, tmp_path):
        import server as srv
        md = tmp_path / "plain.md"
        md.write_text("Just content", encoding="utf-8")
        result = srv._parse_wstg_file(md)
        assert "Just content" in result["content"]


class TestFindTestFile:
    def test_finds_by_id(self):
        import server as srv
        result = srv._find_test_file("WSTG-INFO-01")
        assert result is not None
        assert result.name == "WSTG-INFO-01.md"

    def test_returns_none_for_missing(self):
        import server as srv
        result = srv._find_test_file("WSTG-NONEXISTENT-99")
        assert result is None


class TestValidateShellArg:
    def test_accepts_safe(self):
        import server as srv
        srv._validate_shell_arg("https://example.com", "url")
        srv._validate_shell_arg("192.168.1.1", "ip")

    def test_rejects_quotes(self):
        import server as srv
        with pytest.raises(ValueError, match="shell metacharacters"):
            srv._validate_shell_arg("'; rm -rf /", "bad")

    def test_rejects_backtick(self):
        import server as srv
        with pytest.raises(ValueError):
            srv._validate_shell_arg("`whoami`", "bad")


class TestGetWstgTest:
    def test_valid_test_id(self):
        import server as srv
        result = srv.get_wstg_test("WSTG-INPV-01")
        assert "Summary" in result
        assert "Test Objectives" in result

    def test_lowercase_id(self):
        import server as srv
        result = srv.get_wstg_test("wstg-inpv-01")
        assert "Summary" in result

    def test_invalid_id(self):
        import server as srv
        result = srv.get_wstg_test("INVALID-99")
        assert "not found" in result.lower()


class TestEventLogging:
    def test_track_test_validates_phase(self):
        import server as srv
        result = srv.track_test("test-eng", "WSTG-INFO-01", "completed", "test", domain="test.com")
        assert "Invalid phase" not in result


class TestEngagementPath:
    def test_sanitizes_id(self):
        import server as srv
        path = srv._engagement_path("test-eng-123")
        assert "test-eng-123" in str(path)

    def test_strips_traversal(self):
        import server as srv
        path = srv._engagement_path("../../bad")
        assert ".." not in str(path)
