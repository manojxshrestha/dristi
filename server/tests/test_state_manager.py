"""Tests for enterprise state management."""

import tempfile
from pathlib import Path

import pytest

from state_manager import configure, create_checkpoint, get_engagement_status, list_checkpoints


@pytest.fixture
def state_dir():
    with tempfile.TemporaryDirectory() as tmp:
        configure(Path(tmp))
        yield Path(tmp)


class TestStateManager:
    def test_create_checkpoint(self, state_dir):
        result = create_checkpoint("test-eng", "tester", "Initial checkpoint")
        assert "checkpoint_id" in result
        assert result["description"] == "Initial checkpoint"
        cp_id = result["checkpoint_id"]

        checkpoints = list_checkpoints("test-eng")
        assert len(checkpoints) >= 1
        assert checkpoints[0]["checkpoint_id"] == cp_id

    def test_list_checkpoints(self, state_dir):
        create_checkpoint("test-eng", "tester", "First")
        create_checkpoint("test-eng", "tester", "Second")
        checkpoints = list_checkpoints("test-eng")
        assert len(checkpoints) == 2

    def test_multiple_engagements(self, state_dir):
        create_checkpoint("eng-a", "tester", "Checkpoint A")
        create_checkpoint("eng-b", "tester", "Checkpoint B")
        assert len(list_checkpoints("eng-a")) == 1
        assert len(list_checkpoints("eng-b")) == 1

    def test_unknown_engagement(self, state_dir):
        status = get_engagement_status("nonexistent")
        assert isinstance(status, dict)

    def test_checkpoint_disk_persistence(self, state_dir):
        result = create_checkpoint("disk-eng", "tester", "Disk test")
        cp_id = result["checkpoint_id"]

        checkpoints = list_checkpoints("disk-eng")
        assert len(checkpoints) == 1
        assert checkpoints[0]["checkpoint_id"] == cp_id

    def test_wal_logging(self, state_dir):
        create_checkpoint("wal-eng", "tester", "WAL entry 1")
        create_checkpoint("wal-eng", "tester", "WAL entry 2")
        from state_manager import get_wal

        wal = get_wal("wal-eng")
        assert len(wal) >= 2
