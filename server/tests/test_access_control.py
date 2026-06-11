"""Tests for role-based access control."""

import tempfile
from pathlib import Path

import pytest

from access_control import (
    acquire_lock,
    check_access,
    configure,
    create_session,
    end_session,
    get_access_grant,
    get_access_log,
    get_active_sessions,
    get_lock_status,
    grant_access,
    release_lock,
    revoke_access,
    role_has_at_least,
    validate_role,
)


@pytest.fixture
def ac_dir():
    with tempfile.TemporaryDirectory() as tmp:
        configure(Path(tmp))
        yield Path(tmp)


class TestRoleValidation:
    def test_valid_roles(self):
        for role in ["admin", "operator", "analyst", "auditor", "service_account"]:
            assert validate_role(role) == role

    def test_invalid_role(self):
        with pytest.raises(ValueError, match="Invalid role"):
            validate_role("hacker")

    def test_role_normalization(self):
        assert validate_role("ADMIN") == "admin"

    def test_role_hierarchy(self):
        assert role_has_at_least("admin", "admin") is True
        assert role_has_at_least("operator", "admin") is False


class TestAccessGrants:
    def test_grant_and_retrieve(self, ac_dir):
        grant_access("eng-1", "op-1", "operator", "editor")
        grant = get_access_grant("eng-1", "op-1")
        assert grant is not None
        assert grant["role"] == "operator"
        assert grant["access_level"] == "editor"

    def test_revoke(self, ac_dir):
        grant_access("eng-2", "op-2", "analyst", "reviewer")
        revoke_access("eng-2", "op-2")
        grant = get_access_grant("eng-2", "op-2")
        assert grant is None

    def test_nonexistent_grant(self, ac_dir):
        grant = get_access_grant("eng-3", "nobody")
        assert grant is None


class TestAccessCheck:
    def test_sufficient_access(self, ac_dir):
        grant_access("eng-4", "op-4", "operator", "editor")
        result = check_access("eng-4", "op-4", required_level="guest")
        assert result["granted"] is True

    def test_insufficient_access(self, ac_dir):
        grant_access("eng-5", "op-5", "operator", "reviewer")
        result = check_access("eng-5", "op-5", required_level="editor")
        assert result["granted"] is False

    def test_no_grant(self, ac_dir):
        result = check_access("eng-6", "stranger", required_level="guest")
        assert result["granted"] is False


class TestLocking:
    def test_acquire_and_release(self, ac_dir):
        result = acquire_lock("eng-7", "op-7", reason="Testing")
        assert result["success"] is True
        assert result["holder"] == "op-7"

        status = get_lock_status("eng-7")
        assert status["locked"] is True
        assert status["holder"] == "op-7"

        release = release_lock("eng-7", "op-7")
        assert release["success"] is True

        status = get_lock_status("eng-7")
        assert status["locked"] is False

    def test_double_lock_fails(self, ac_dir):
        acquire_lock("eng-8", "op-8")
        result = acquire_lock("eng-8", "op-9", timeout=1)
        assert result["success"] is False

    def test_wrong_holder_release(self, ac_dir):
        acquire_lock("eng-9", "op-10")
        result = release_lock("eng-9", "op-11")
        assert result["success"] is False

    def test_unlock_unknown(self, ac_dir):
        result = release_lock("nonexistent", "anyone")
        assert result["success"] is False


class TestSessions:
    def test_create_and_list(self, ac_dir):
        create_session("eng-10", "op-12")
        sessions = get_active_sessions("eng-10")
        assert len(sessions) == 1
        assert sessions[0]["active"] is True

    def test_end_session(self, ac_dir):
        session = create_session("eng-11", "op-13")
        end_session("eng-11", session["session_id"])
        sessions = get_active_sessions("eng-11")
        assert len(sessions) == 0

    def test_multiple_sessions(self, ac_dir):
        s1 = create_session("eng-12", "op-14", session_type="interactive")
        s2 = create_session("eng-12", "op-14", session_type="api")
        assert s1["session_id"] != s2["session_id"]
        sessions = get_active_sessions("eng-12")
        assert len(sessions) == 2


class TestAuditLog:
    def test_events_logged(self, ac_dir):
        acquire_lock("eng-13", "op-15", reason="Audit test")
        release_lock("eng-13", "op-15")
        log = get_access_log("eng-13")
        assert len(log) >= 2
        actions = [entry["action"] for entry in log]
        assert "lock_acquired" in actions
        assert "lock_released" in actions
