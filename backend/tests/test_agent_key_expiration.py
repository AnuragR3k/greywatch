"""Regression tests for API-key expiration validation.

The authentication path must parse stored expiration values strictly and
always compare timezone-aware UTC datetimes. A naive timestamp is interpreted
as UTC for backward compatibility; ``Z`` suffixes and explicit UTC offsets are
supported; malformed values reject the key instead of making it non-expiring.

Tests use an isolated migrated database and a small PBKDF2 iteration count.
The current-time helper is injectable so the exact expiration boundary can be
tested without wall-clock races.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from backend.app import agents as agents_module
from backend.app.agents import (
    authenticate_api_key,
    create_agent,
    create_api_key,
    get_api_key,
    get_audit_log,
)
from backend.app.migration_state import ensure_database_file_exists
from backend.app.migrations.runner import migrate


# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #


@pytest.fixture
def agents_db(tmp_path, monkeypatch):
    """Create an isolated, fully migrated agents database for one test."""
    db_path = tmp_path / "agents.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    # Keep PBKDF2 cheap; authentication uses the same configured count.
    monkeypatch.setenv("GREYWATCH_KEY_HASH_ITERATIONS", "1000")
    ensure_database_file_exists(db_path)
    migrate(str(db_path), dry_run=False)
    return db_path


@pytest.fixture
def agent(agents_db):
    return create_agent("expiration-test-agent")


def _make_key(agent, expires_at):
    return create_api_key(agent.id, expires_at=expires_at)


def _auth_failure_entry(agent_id: int, key_id: int) -> dict:
    """Return the single audit-log auth failure for this agent/key."""
    entries = get_audit_log(agent_id=agent_id, event_type="auth_failure")
    assert len(entries) == 1, entries
    entry = entries[0]
    assert entry["agent_id"] == agent_id
    assert entry["api_key_id"] == key_id
    assert entry["actor"] == "system"
    return entry


def _auth_failure_reason(entry: dict) -> str:
    return json.loads(entry["detail"])["reason"]


# --------------------------------------------------------------------------- #
# Parsing and timezone normalization
# --------------------------------------------------------------------------- #


def test_naive_expiration_is_interpreted_as_utc():
    """A timestamp without an explicit timezone is normalized to UTC."""
    parsed = agents_module._parse_expiration_timestamp("2030-01-01T12:34:56")

    assert parsed == datetime(2030, 1, 1, 12, 34, 56, tzinfo=timezone.utc)
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timedelta(0)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (
            "2030-01-01T00:00:00Z",
            datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        ),
        (
            "2030-01-01T00:00:00+05:30",
            datetime(2029, 12, 31, 18, 30, 0, tzinfo=timezone.utc),
        ),
        (
            "2030-01-01T00:00:00-08:00",
            datetime(2030, 1, 1, 8, 0, 0, tzinfo=timezone.utc),
        ),
    ],
    ids=["z-suffix", "positive-offset", "negative-offset"],
)
def test_explicit_offsets_normalize_to_utc(raw, expected):
    """``Z`` and explicit offsets are preserved and converted to UTC."""
    parsed = agents_module._parse_expiration_timestamp(raw)

    assert parsed == expected
    assert parsed.utcoffset() == timedelta(0)


# --------------------------------------------------------------------------- #
# Authentication behavior
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "expires_at",
    [
        "2999-01-01T00:00:00",  # naive -> UTC (legacy compatibility)
        "2999-01-01T00:00:00Z",
        "2999-01-01T00:00:00+05:30",
        "2999-01-01T00:00:00-08:00",
    ],
    ids=["naive-utc", "z-suffix", "positive-offset", "negative-offset"],
)
def test_valid_future_expiration_is_accepted(agent, expires_at):
    """Future timestamps in every supported format authenticate successfully."""
    key = _make_key(agent, expires_at)

    result = authenticate_api_key(key.plaintext_key)

    assert result is not None
    assert result.api_key.id == key.id
    assert result.api_key.expires_at == expires_at


def test_expired_key_is_rejected_and_audited(agent):
    """An expiration in the past rejects the key with the existing audit reason."""
    key = _make_key(agent, "2000-01-01T00:00:00Z")

    assert authenticate_api_key(key.plaintext_key) is None
    assert get_api_key(key.id).last_used_at is None

    entry = _auth_failure_entry(agent.id, key.id)
    assert _auth_failure_reason(entry) == "key_expired"


@pytest.mark.parametrize(
    "expires_at",
    [
        "not-a-timestamp",
        "",  # empty must not be treated like a missing/NULL expiration
        "2026-01-01T00:00:00+25:00",  # invalid UTC offset
    ],
    ids=["garbage", "empty", "invalid-offset"],
)
def test_malformed_expiration_is_rejected(agent, expires_at):
    """Malformed expirations fail closed and never become non-expiring keys."""
    key = _make_key(agent, expires_at)

    assert authenticate_api_key(key.plaintext_key) is None
    assert get_api_key(key.id).last_used_at is None

    entry = _auth_failure_entry(agent.id, key.id)
    assert _auth_failure_reason(entry) == "invalid_expiration"


def test_expiration_equal_to_now_is_rejected(agent, monkeypatch):
    """A key expiring exactly at the current instant is already expired."""
    fixed_now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(agents_module, "_utc_now_datetime", lambda: fixed_now)
    key = _make_key(agent, fixed_now.isoformat())

    assert authenticate_api_key(key.plaintext_key) is None

    entry = _auth_failure_entry(agent.id, key.id)
    assert _auth_failure_reason(entry) == "key_expired"
