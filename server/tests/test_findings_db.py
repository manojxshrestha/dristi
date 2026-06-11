"""Tests for the SQLite findings database."""

import os
import tempfile

import pytest

from findings_db import FindingsDB


@pytest.fixture
def db():
    """Create an isolated FindingsDB in a temp directory."""
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "test.db")
        fdb = FindingsDB(db_path)
        yield fdb
        fdb.close()


class TestFindingsDB:
    """Suite for FindingsDB CRUD operations."""

    def test_init_creates_engagement(self, db):
        result = db.init_engagement(
            engagement_id="test-001",
            client="TestClient",
            etype="web",
            scope="*.test.com",
            notes="test engagement",
        )
        assert result["id"] == "test-001"
        assert result["client"] == "TestClient"
        assert result["status"] == "active"

    def test_add_vuln(self, db):
        db.init_engagement(engagement_id="test-002", client="Client")
        vuln = db.add_vuln(
            engagement_id="test-002",
            title="Test XSS",
            severity="High",
            cvss=6.5,
            affected_url="https://test.com/search",
            affected_parameter="q",
            description="Reflected XSS in search parameter",
            evidence="<script>alert(1)</script> reflected in response",
            poc_output="curl -s 'https://test.com/search?q=<script>alert(1)</script>'",
        )
        assert vuln["title"] == "Test XSS"
        assert vuln["severity"] == "High"
        assert vuln["status"] == "open"
        assert vuln["poc_output"] != ""

    def test_list_vulns_empty(self, db):
        db.init_engagement(engagement_id="test-003", client="Client")
        vulns = db.list_vulns(engagement_id="test-003")
        assert vulns == []

    def test_list_vulns_with_data(self, db):
        db.init_engagement(engagement_id="test-004", client="Client")
        db.add_vuln(
            engagement_id="test-004",
            title="Finding A",
            severity="Critical",
            cvss=9.0,
            affected_url="https://test.com/a",
        )
        db.add_vuln(
            engagement_id="test-004",
            title="Finding B",
            severity="Low",
            cvss=3.0,
            affected_url="https://test.com/b",
        )
        vulns = db.list_vulns(engagement_id="test-004")
        assert len(vulns) == 2
        # Should be sorted by severity descending
        assert vulns[0]["severity"] == "Critical"

    def test_update_vuln(self, db):
        db.init_engagement(engagement_id="test-005", client="Client")
        vuln = db.add_vuln(
            engagement_id="test-005",
            title="Old Title",
            severity="Medium",
            cvss=5.0,
            affected_url="https://test.com/old",
        )
        updated = db.update_vuln(
            vuln["id"],
            severity="High",
            title="Updated Title",
        )
        assert updated["severity"] == "High"
        assert updated["title"] == "Updated Title"

    def test_add_credential(self, db):
        db.init_engagement(engagement_id="test-006", client="Client")
        cred = db.add_credential(
            engagement_id="test-006",
            username="admin",
            secret="s3cret!",  # nosec B106
            secret_type="password",
            domain="test.com",
            access_level="admin",
            source="bruteforce",
        )
        assert cred["username"] == "admin"
        assert cred["secret_type"] == "password"

    def test_engagement_not_found(self, db):
        result = db.init_engagement("nonexistent")
        # Init with same ID should not fail
        result = db.init_engagement("nonexistent", client="New")
        assert result["id"] == "nonexistent"

    def test_vuln_status_filter(self, db):
        db.init_engagement(engagement_id="test-007", client="Client")
        db.add_vuln(
            engagement_id="test-007",
            title="Open Finding",
            severity="High",
            cvss=7.0,
            affected_url="https://test.com/o",
        )
        open_vulns = db.list_vulns(engagement_id="test-007", status="open")
        assert len(open_vulns) == 1
        db.update_vuln(open_vulns[0]["id"], status="fixed")
        still_open = db.list_vulns(engagement_id="test-007", status="open")
        assert len(still_open) == 0
