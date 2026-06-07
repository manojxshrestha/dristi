"""Shared fixtures for Dristi server tests."""

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_data_dir():
    """Provide a temporary directory for test data isolation."""
    with tempfile.TemporaryDirectory() as tmp:
        original = Path.cwd()
        os.chdir(tmp)
        yield Path(tmp)
        os.chdir(original)


@pytest.fixture
def sample_finding():
    """A minimal valid finding dict for unit tests."""
    return {
        "engagement_id": "test-engagement",
        "title": "Test SQL Injection",
        "severity": "High",
        "cvss": 7.5,
        "affected_url": "https://example.com/api/users",
        "affected_parameter": "id",
        "description": "SQL injection in user ID parameter",
        "evidence": "Response shows SQL error",
        "remediation": "Use parameterized queries",
    }


@pytest.fixture
def sample_scope_entry():
    """A minimal valid scope entry."""
    return {
        "domain": "*.example.com",
        "domain_type": "wildcard_domain",
        "eligibility": "critical",
    }
