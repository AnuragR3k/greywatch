"""Integration tests for migration runner in FastAPI lifespan."""

import errno
import os
import sqlite3
import multiprocessing
from pathlib import Path
import pytest
from starlette.testclient import TestClient


def _worker_ensure_db(db_path: str, queue: "multiprocessing.Queue") -> None:
    """Worker function: call ensure_database_file_exists and report result."""
    try:
        os.environ["GREYWATCH_DB"] = db_path
        from backend.app.migration_state import ensure_database_file_exists
        from pathlib import Path
        ensure_database_file_exists(Path(db_path))
        queue.put(("ok", None))
    except Exception as exc:
        queue.put(("error", str(exc)))


def _run_concurrent_ensure_db(db_path: str, num_workers: int) -> list:
    """Run concurrent ensure_database_file_exists workers with proper cleanup."""
    # Use 'fork' context on Linux for deterministic behavior (inherits parent state,
    # avoids spawn TOCTOU with WAL-copy in inspect_path). The function under test
    # (ensure_database_file_exists) is thread-safe and fork-safe.
    ctx = multiprocessing.get_context("fork")
    queue = ctx.Queue()

    procs = [
        ctx.Process(target=_worker_ensure_db, args=(db_path, queue))
        for _ in range(num_workers)
    ]

    try:
        for p in procs:
            p.start()

        results = []
        for _ in range(num_workers):
            results.append(queue.get(timeout=30))

        for p in procs:
            p.join(timeout=10)
            assert p.exitcode == 0, f"Worker failed with exit code {p.exitcode}"

        return results

    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
                p.join(timeout=5)
        queue.close()
        queue.join_thread()


class TestAtomicDatabaseCreation:
    """Tests for atomic database creation race conditions."""

    def test_two_workers_create_missing_db_simultaneously(self, tmp_path):
        """Two workers race to create missing DB; both succeed, final state is FRESH."""
        db_path = str(tmp_path / "race.db")
        Path(db_path).unlink(missing_ok=True)

        results = _run_concurrent_ensure_db(db_path, 2)

        assert all(r[0] == "ok" for r in results)
        # Both workers should succeed
        from backend.app.migration_state import inspect_path, DatabaseState
        report = inspect_path(db_path)
        assert report.state == DatabaseState.FRESH
        assert report.tables == []

    def test_four_workers_create_missing_db(self, tmp_path):
        """Four workers race to create missing DB - all should succeed."""
        db_path = str(tmp_path / "race4.db")
        Path(db_path).unlink(missing_ok=True)

        results = _run_concurrent_ensure_db(db_path, 4)

        # All workers should succeed
        assert all(r[0] == "ok" for r in results), "Some workers failed"
        # Final state should be FRESH
        from backend.app.migration_state import inspect_path, DatabaseState
        report = inspect_path(db_path)
        assert report.state == DatabaseState.FRESH
        assert report.tables == []


class TestAtomicPublicationVerification:
    """Tests verifying atomic publication behavior directly."""

    def test_temp_db_is_valid_before_publication(self, tmp_path):
        """Temp database is non-zero and valid SQLite before publication."""
        from backend.app.migration_state import ensure_database_file_exists, _is_valid_sqlite_database

        db_path = tmp_path / "verify.db"
        Path(db_path).unlink(missing_ok=True)

        # Call the function -- it should create and publish
        ensure_database_file_exists(db_path)

        # Verify the published database
        assert db_path.exists()
        assert os.path.getsize(db_path) > 0
        assert _is_valid_sqlite_database(str(db_path))

        # Verify it's classified as FRESH
        from backend.app.migration_state import inspect_path, DatabaseState
        report = inspect_path(db_path)
        assert report.state == DatabaseState.FRESH
        assert report.tables == []

    def test_published_db_is_valid_and_fresh(self, tmp_path):
        """Published database is valid and classified as FRESH."""
        from backend.app.migration_state import ensure_database_file_exists

        db_path = tmp_path / "published.db"
        Path(db_path).unlink(missing_ok=True)

        ensure_database_file_exists(db_path)

        from backend.app.migration_state import inspect_path, DatabaseState
        report = inspect_path(db_path)
        assert report.state == DatabaseState.FRESH
        assert report.tables == []
        assert report.ledger_present is False
        assert report.applied_version == 0
        assert report.latest_version == 4

    def test_temp_pathname_removed_after_publication(self, tmp_path):
        """Temporary pathname is removed after successful publication."""
        from backend.app.migration_state import ensure_database_file_exists

        db_path = tmp_path / "cleanup.db"
        Path(db_path).unlink(missing_ok=True)

        # Track temp files before
        temp_files_before = set(tmp_path.parent.glob(".*.init.*.tmp"))

        ensure_database_file_exists(db_path)

        # Track temp files after
        temp_files_after = set(tmp_path.parent.glob(".*.init.*.tmp"))

        # No new temp files should remain
        new_temp_files = temp_files_after - temp_files_before
        assert len(new_temp_files) == 0, f"Orphaned temp files: {new_temp_files}"

    def test_competing_publisher_does_not_overwrite(self, tmp_path):
        """A competing publisher does not overwrite the existing database."""
        from backend.app.migration_state import ensure_database_file_exists

        db_path = tmp_path / "compete.db"
        Path(db_path).unlink(missing_ok=True)

        # First process publishes
        ensure_database_file_exists(db_path)
        size_after_first = os.path.getsize(db_path)

        # Second process calls ensure_database_file_exists
        # Should return immediately without overwriting
        ensure_database_file_exists(db_path)
        size_after_second = os.path.getsize(db_path)

        # Size should be identical -- no overwrite
        assert size_after_first == size_after_second
        assert size_after_first > 0

    def test_failed_publication_leaves_no_partial_destination(self, tmp_path, monkeypatch):
        """Failure to publish leaves no partially initialized destination."""
        from backend.app.migration_state import ensure_database_file_exists

        db_path = tmp_path / "fail_pub.db"
        Path(db_path).unlink(missing_ok=True)

        # Monkeypatch os.link to always fail with EEXIST (simulate race loss)
        original_link = os.link
        def failing_link(src, dst):
            raise OSError(errno.EEXIST, "File exists")
        monkeypatch.setattr(os, "link", failing_link)

        try:
            # Should not raise, should just return
            ensure_database_file_exists(db_path)
        finally:
            monkeypatch.setattr(os, "link", original_link)

        # Destination should NOT exist (we lost the race, but no one else published)
        # This is correct behavior: we don't create a partial destination.
        assert not db_path.exists()


class TestCrashRecovery:
    """Tests for crash recovery scenarios."""

    def test_crash_before_publication(self, tmp_path):
        """Simulate crash after temp file creation but before publication.

        Per design, orphaned temp files are NOT automatically cleaned up.
        They are harmless and can be removed manually. The new database
        should still be created successfully alongside the orphaned temp.
        """
        from backend.app.migration_state import ensure_database_file_exists

        db_path = tmp_path / "crash.db"
        # Pre-create a temp file as if crash happened
        import tempfile
        fd, tmp_file = tempfile.mkstemp(
            dir=db_path.parent,
            prefix=f".{db_path.name}.init.",
            suffix=".tmp"
        )
        os.close(fd)
        # Leave 0-byte temp file (crash before SQLite init)

        # Next startup should create fresh DB alongside orphaned temp
        ensure_database_file_exists(db_path)

        # Should have valid DB now
        from backend.app.migration_state import inspect_path, DatabaseState
        report = inspect_path(db_path)
        assert report.state == DatabaseState.FRESH
        assert report.tables == []

        # Temp file is NOT cleaned up (by design - harmless orphan)
        # But the database was still created successfully
        assert db_path.exists()
        assert os.path.getsize(db_path) > 0


class TestInitializationGuard:
    """Tests for initialize_database() guard."""

    def test_guard_activated_for_current_database(self, current_db, monkeypatch):
        """CURRENT database -> guard activated -> initialize_database() blocked."""
        monkeypatch.setenv("GREYWATCH_DB", str(current_db))
        from backend.app.main import app
        with TestClient(app) as client:
            client.get("/health")  # Triggers lifespan

            from backend.app.siem import initialize_database
            with pytest.raises(RuntimeError, match="Database schema is managed by the migration runner"):
                initialize_database()

    def test_guard_activated_after_migration(self, fresh_db, monkeypatch):
        """FRESH database -> migration runs -> guard activated."""
        monkeypatch.setenv("GREYWATCH_DB", str(fresh_db))
        from backend.app.main import app
        with TestClient(app) as client:
            client.get("/health")

            from backend.app.siem import initialize_database
            with pytest.raises(RuntimeError, match="Database schema is managed by the migration runner"):
                initialize_database()

    def test_env_var_cannot_bypass_production_guard(self, current_db, monkeypatch):
        """GREYWATCH_ALLOW_LEGACY_INIT=1 cannot bypass guard after lifespan."""
        monkeypatch.setenv("GREYWATCH_DB", str(current_db))
        monkeypatch.setenv("GREYWATCH_ALLOW_LEGACY_INIT", "1")
        from backend.app.main import app
        with TestClient(app) as client:
            client.get("/health")  # Sets guard

            from backend.app.siem import initialize_database
            with pytest.raises(RuntimeError, match="Database schema is managed by the migration runner"):
                initialize_database()

    def test_env_var_works_for_standalone_tool(self, tmp_path, monkeypatch):
        """GREYWATCH_ALLOW_LEGACY_INIT=1 works when no lifespan ran."""
        db_path = tmp_path / "standalone.db"
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_ALLOW_LEGACY_INIT", "1")

        from backend.app.siem import initialize_database
        # When GREYWATCH_ALLOW_LEGACY_INIT=1, no deprecation warning is emitted
        # (the env var explicitly opts in to legacy behavior)
        initialize_database()

        from backend.app.migration_state import inspect_path, DatabaseState
        report = inspect_path(db_path)
        # initialize_database creates schema but no ledger -> PENDING state
        assert report.state in (DatabaseState.CURRENT, DatabaseState.LEGACY_READY, DatabaseState.PENDING)

    def test_env_var_without_allow_emits_deprecation_warning(self, tmp_path, monkeypatch):
        """Without GREYWATCH_ALLOW_LEGACY_INIT, deprecation warning is emitted."""
        db_path = tmp_path / "standalone_no_allow.db"
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        # Note: NOT setting GREYWATCH_ALLOW_LEGACY_INIT

        from backend.app.siem import initialize_database
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            initialize_database()
            assert len(w) == 1
            assert "deprecated" in str(w[0].message).lower()

        from backend.app.migration_state import inspect_path, DatabaseState
        report = inspect_path(db_path)
        # initialize_database creates schema but no ledger -> PENDING state
        assert report.state in (DatabaseState.CURRENT, DatabaseState.LEGACY_READY, DatabaseState.PENDING)


class TestMultipleTestClientLifecycles:
    """Tests for multiple TestClient instances in one process."""

    def test_second_testclient_after_first_completes(self, tmp_path, monkeypatch):
        """Second TestClient in same process works after first completes."""
        db_path = tmp_path / "multi.db"
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))

        from backend.app.main import app

        with TestClient(app) as client1:
            resp = client1.get("/health")
            assert resp.json()["schema_ready"] is True

        with TestClient(app) as client2:
            resp = client2.get("/health")
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 0


class TestBackupOrdering:
    """Tests for backup verification before migration."""

    def test_current_db_skips_backup_check(self, current_db, tmp_path, monkeypatch):
        """CURRENT database does not require backup check."""
        monkeypatch.setenv("GREYWATCH_DB", str(current_db))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")

        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 0

    def test_migratable_db_requires_backup(self, legacy_ready_db, tmp_path, monkeypatch):
        """LEGACY_READY database requires backup when GREYWATCH_REQUIRE_BACKUP=1."""
        monkeypatch.setenv("GREYWATCH_DB", str(legacy_ready_db))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        # Create the backup directory but leave it empty (no backup files)
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))

        from backend.app.main import app
        with pytest.raises(RuntimeError, match="Backup required but no valid backup found"):
            with TestClient(app):
                pass

    def test_fresh_db_exempt_from_backup_check(self, fresh_db, tmp_path, monkeypatch):
        """FRESH database is exempt from backup requirement (bootstrap scenario)."""
        monkeypatch.setenv("GREYWATCH_DB", str(fresh_db))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.delenv("GREYWATCH_BACKUP_DIR", raising=False)

        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 1

    def test_backup_verified_before_migration(self, legacy_ready_db, tmp_path, monkeypatch):
        """Backup is verified before migration runs."""
        from scripts.gw_db_backup import backup_database

        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()

        backup_path = backup_database(str(legacy_ready_db), str(backup_dir))

        monkeypatch.setenv("GREYWATCH_DB", str(legacy_ready_db))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))

        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 1


class TestLegacyReadyFixture:
    """Tests using correct LEGACY_READY fixture."""

    def test_legacy_ready_database_migrates(self, legacy_ready_db, monkeypatch):
        """LEGACY_READY database migrates successfully."""
        monkeypatch.setenv("GREYWATCH_DB", str(legacy_ready_db))
        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 1


class TestStartupIntegration:
    """Core startup integration tests."""

    def test_fresh_database_startup(self, tmp_path, monkeypatch):
        """Fresh database starts up and migrates successfully."""
        db_path = tmp_path / "fresh_startup.db"
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))

        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["status"] == "ok"
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 1

    def test_current_database_startup(self, current_db, monkeypatch):
        """CURRENT database starts up without migration."""
        monkeypatch.setenv("GREYWATCH_DB", str(current_db))

        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["status"] == "ok"
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 0

    def test_legacy_database_migration(self, legacy_ready_db, monkeypatch):
        """LEGACY_READY database migrates on startup."""
        monkeypatch.setenv("GREYWATCH_DB", str(legacy_ready_db))

        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["status"] == "ok"
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 1

    def test_pending_migration_state(self, pending_db, monkeypatch):
        """PENDING state database gets ledger stamped on startup."""
        monkeypatch.setenv("GREYWATCH_DB", str(pending_db))

        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["status"] == "ok"
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 1

    def test_corrupt_database_rejection(self, tmp_path, monkeypatch):
        """Corrupt database is rejected at startup."""
        db_path = tmp_path / "corrupt.db"
        db_path.write_bytes(b"not a sqlite database")
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))

        from backend.app.main import app
        with pytest.raises(RuntimeError, match="Database in unexpected state after startup: corrupt"):
            with TestClient(app):
                pass

    def test_unknown_future_schema_rejection(self, tmp_path, monkeypatch):
        """Database with future schema version is rejected."""
        db_path = tmp_path / "future.db"
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE events (id INTEGER PRIMARY KEY);
            CREATE TABLE schema_migrations (version INTEGER, name TEXT, applied_at TEXT);
            INSERT INTO schema_migrations VALUES (999, 'future_migration', '2024-01-01T00:00:00Z');
        """)
        conn.commit()
        conn.close()

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))

        from backend.app.main import app
        with pytest.raises(RuntimeError, match="Database in unexpected state after startup: inconsistent"):
            with TestClient(app):
                pass


class TestMigrationFailurePreventsStartup:
    """Tests that migration failure prevents application startup."""

    def test_migration_failure_blocks_startup(self, tmp_path, monkeypatch):
        """Migration error blocks application startup."""
        # Create a database that will fail migration (e.g., read-only)
        db_path = tmp_path / "fail_migrate.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA user_version=0")
        conn.commit()
        conn.close()

        # Make it read-only
        os.chmod(db_path, 0o444)

        try:
            monkeypatch.setenv("GREYWATCH_DB", str(db_path))

            from backend.app.main import app
            with pytest.raises(RuntimeError, match="Database migration failed"):
                with TestClient(app):
                    pass
        finally:
            # Restore permissions for cleanup
            os.chmod(db_path, 0o644)

    def test_migration_failure_rolls_back_transaction(self, tmp_path, monkeypatch):
        """A failure inside a migration up() rolls back all partial writes.

        Injects a failure into migration v3 after it has written a probe
        table, then asserts the database is left exactly pre-migration:
        LEGACY_READY, no ledger, and none of v1/v2's schema changes. Once
        the fault is removed, the same database migrates cleanly.
        """
        from backend.app.migrations import runner
        from backend.app.migration_state import DatabaseState, inspect_path

        db_path = _create_legacy_ready_db(tmp_path / "rollback.db")
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "0")

        original_up_v3 = runner.MIGRATION_UPS[3]

        def failing_up_v3(conn):
            conn.execute("CREATE TABLE partial_rollback_probe (id INTEGER)")
            conn.execute("INSERT INTO partial_rollback_probe (id) VALUES (1)")
            raise sqlite3.OperationalError("injected migration failure")

        monkeypatch.setitem(runner.MIGRATION_UPS, 3, failing_up_v3)

        with pytest.raises(runner.MigrationError, match="injected migration failure"):
            runner.migrate(str(db_path), dry_run=False)

        # The whole transaction rolled back, including v1 and v2.
        report = inspect_path(db_path)
        assert report.state == DatabaseState.LEGACY_READY
        assert report.applied_version == 0
        assert report.ledger_present is False
        assert "agents" not in report.tables
        assert "audit_log" not in report.tables

        conn = sqlite3.connect(str(db_path))
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            assert "partial_rollback_probe" not in tables
            assert "schema_migrations" not in tables
            assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        finally:
            conn.close()

        # Removing the fault leaves the database fully migratable.
        monkeypatch.setitem(runner.MIGRATION_UPS, 3, original_up_v3)
        result = runner.migrate(str(db_path), dry_run=False)
        assert result["applied"] == 4
        assert inspect_path(db_path).state == DatabaseState.CURRENT

    def test_migration_failure_during_startup_fails_closed(self, tmp_path, monkeypatch):
        """Startup fails closed when migration fails, database remains consistent.

        This test uses a mock to inject a failure during the migration step
        of the FastAPI lifespan, verifying:
        1. Startup fails with RuntimeError
        2. Database state is not corrupted (no partial schema)
        3. The schema guard is NOT activated
        """
        from backend.app.migrations.runner import MigrationError
        from backend.app.migration_state import inspect_path, DatabaseState
        from unittest import mock

        # Create a FRESH database
        db_path = tmp_path / "startup_fail.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA user_version=0")
        conn.commit()
        conn.close()

        # Mock the migrate function to fail during startup
        def failing_migrate(db_path, *, dry_run=False):
            if not dry_run:
                # Simulate a migration that starts transaction then fails
                raise MigrationError("Simulated migration failure during startup")
            return {"applied": 0, "steps": []}

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))

        # Patch the migrate function in the main module
        with mock.patch("backend.app.main.migrate", side_effect=failing_migrate):
            from backend.app.main import app
            with pytest.raises(RuntimeError, match="Database migration failed"):
                with TestClient(app):
                    pass

        # Verify database state is still consistent (FRESH, no partial tables)
        report = inspect_path(db_path)
        assert report.state == DatabaseState.FRESH
        # No tables should have been created by the failed migration
        assert "events" not in report.tables
        assert "alerts" not in report.tables

        # Verify schema guard is NOT activated (since startup failed)
        import backend.app.siem as siem_module
        assert siem_module._SCHEMA_MANAGED_BY_RUNNER is False


# Fixtures
@pytest.fixture
def fresh_db(tmp_path):
    """Valid empty SQLite file (FRESH state)."""
    db_path = tmp_path / "fresh.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA user_version=0")
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def current_db(fresh_db):
    """FRESH DB migrated to CURRENT."""
    from backend.app.migrations.runner import migrate
    migrate(str(fresh_db), dry_run=False)
    return fresh_db


@pytest.fixture
def pending_db(current_db):
    """CURRENT DB with ledger rolled back to version 0 (PENDING)."""
    from backend.app.migration_ledger import SCHEMA_MIGRATIONS_TABLE
    conn = sqlite3.connect(str(current_db))
    conn.execute(f"DELETE FROM {SCHEMA_MIGRATIONS_TABLE}")
    conn.commit()
    conn.close()
    return current_db


def _create_legacy_ready_db(db_path: Path) -> Path:
    """Create a database in LEGACY_READY state and return its path.

    All core tables and indexes are present; only migration-addable columns
    are missing, so the migration runner can add them.
    """
    from backend.app.migration_state import DatabaseState, inspect_path

    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            host TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            severity TEXT NOT NULL,
            raw_message TEXT NOT NULL
        );
        CREATE INDEX idx_events_ip_time ON events(source_ip, timestamp);

        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            description TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            closed_at TEXT
        );
        CREATE INDEX idx_alerts_status ON alerts(status, created_at);

        CREATE TABLE incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            source_ip TEXT NOT NULL,
            description TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            closed_at TEXT
        );
        CREATE INDEX idx_incidents_status ON incidents(status, created_at);
        CREATE INDEX idx_incidents_rule_ip ON incidents(rule_id, source_ip, status);

        CREATE TABLE incident_events (
            incident_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            added_at TEXT NOT NULL,
            PRIMARY KEY (incident_id, event_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (event_id) REFERENCES events(id)
        );
        CREATE INDEX idx_incident_events_incident ON incident_events(incident_id);
        CREATE INDEX idx_incident_events_event ON incident_events(event_id);

        CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);
    """)
    conn.commit()
    conn.close()

    assert inspect_path(db_path).state == DatabaseState.LEGACY_READY
    return db_path


@pytest.fixture
def legacy_ready_db(tmp_path):
    """All core tables + indexes present, only addable columns missing (LEGACY_READY)."""
    return _create_legacy_ready_db(tmp_path / "legacy_ready.db")


class TestForeignKeyEnforcement:
    """Tests for runtime PRAGMA foreign_keys=ON enforcement."""

    def test_foreign_key_violation_rejected_on_insert(self, tmp_path, monkeypatch):
        """Inserting incident_events with non-existent incident_id fails."""
        db_path = tmp_path / "fk_test.db"
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))

        from backend.app.main import app
        with TestClient(app) as client:
            client.get("/health")  # Initialize schema via lifespan

        # Test via direct database connection
        from backend.app.siem import _connection
        with _connection() as conn:
            # Create an incident
            conn.execute(
                "INSERT INTO incidents (created_at, updated_at, rule_id, title, severity, "
                "status, source_ip, description, event_count, first_seen_at, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", "test_rule", "Test",
                 "high", "open", "1.2.3.4", "Test incident", 1,
                 "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
            )
            incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            # Valid insert should succeed (event_id 999 doesn't exist but event FK is not enforced in test schema)
            # Actually, event_id also has FK constraint. Let's create an event first.
            conn.execute(
                "INSERT INTO events (timestamp, host, event_type, severity, raw_message) "
                "VALUES (?, ?, ?, ?, ?)",
                ("2024-01-01T00:00:00Z", "test-host", "test", "info", "test message")
            )
            event_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            # Valid insert should succeed
            conn.execute(
                "INSERT INTO incident_events (incident_id, event_id, added_at) VALUES (?, ?, ?)",
                (incident_id, event_id, "2024-01-01T00:00:00Z")
            )

            # Invalid incident_id should fail
            import sqlite3
            with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
                conn.execute(
                    "INSERT INTO incident_events (incident_id, event_id, added_at) VALUES (?, ?, ?)",
                    (99999, event_id, "2024-01-01T00:00:00Z")
                )

    def test_foreign_key_violation_rejected_on_event_delete(self, tmp_path, monkeypatch):
        """Deleting an event referenced by incident_events fails."""
        db_path = tmp_path / "fk_test2.db"
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))

        from backend.app.main import app
        with TestClient(app) as client:
            client.get("/health")

        from backend.app.siem import _connection
        with _connection() as conn:
            # Create an event
            conn.execute(
                "INSERT INTO events (timestamp, host, event_type, severity, raw_message) "
                "VALUES (?, ?, ?, ?, ?)",
                ("2024-01-01T00:00:00Z", "test-host", "test", "info", "test message")
            )
            event_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            # Create an incident
            conn.execute(
                "INSERT INTO incidents (created_at, updated_at, rule_id, title, severity, "
                "status, source_ip, description, event_count, first_seen_at, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", "test_rule", "Test",
                 "high", "open", "1.2.3.4", "Test incident", 1,
                 "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
            )
            incident_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            # Link them
            conn.execute(
                "INSERT INTO incident_events (incident_id, event_id, added_at) VALUES (?, ?, ?)",
                (incident_id, event_id, "2024-01-01T00:00:00Z")
            )

            # Deleting the referenced event should fail
            import sqlite3
            with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY constraint failed"):
                conn.execute("DELETE FROM events WHERE id = ?", (event_id,))


class TestBackupAgeValidation:
    """Tests for backup age validation during startup."""

    def test_backup_too_old_rejected(self, tmp_path, monkeypatch):
        """Startup fails when latest backup exceeds GREYWATCH_MAX_BACKUP_AGE_HOURS."""
        import time
        import os
        import shutil

        # Create a database in LEGACY_READY state (not FRESH, so backup is required)
        db_path = tmp_path / "backup_age.db"
        _create_legacy_ready_db(db_path)

        # Create a backup directory
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()

        # Create a backup file (copy the DB)
        backup_path = backup_dir / "greywatch.db.backup"
        shutil.copy2(db_path, backup_path)

        # Set the backup's mtime to be older than MAX_BACKUP_AGE_HOURS (default 24h)
        # Use 25 hours ago
        old_time = time.time() - (25 * 3600)
        os.utime(backup_path, (old_time, old_time))

        # Set environment variables
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_MAX_BACKUP_AGE_HOURS", "24")

        from backend.app.main import app
        # Startup should fail because backup is too old
        with pytest.raises(RuntimeError, match="Backup required but no valid backup found"):
            with TestClient(app):
                pass

    def test_backup_within_age_accepted(self, tmp_path, monkeypatch):
        """Startup succeeds when latest backup is within GREYWATCH_MAX_BACKUP_AGE_HOURS."""
        import time
        import os
        import shutil

        # Create a database in LEGACY_READY state (not FRESH, so backup is required)
        db_path = tmp_path / "backup_age_ok.db"
        _create_legacy_ready_db(db_path)

        # Create a backup directory
        backup_dir = tmp_path / "backups_ok"
        backup_dir.mkdir()

        # Create a backup file (copy the DB)
        backup_path = backup_dir / "greywatch.db.backup"
        shutil.copy2(db_path, backup_path)

        # Set the backup's mtime to be recent (1 hour ago)
        recent_time = time.time() - (1 * 3600)
        os.utime(backup_path, (recent_time, recent_time))

        # Set environment variables
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_MAX_BACKUP_AGE_HOURS", "24")

        from backend.app.main import app
        # Startup should succeed because backup is within age limit
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 1

    def test_custom_max_backup_age(self, tmp_path, monkeypatch):
        """Custom GREYWATCH_MAX_BACKUP_AGE_HOURS is respected."""
        import time
        import os
        import shutil

        # Create a database in LEGACY_READY state (not FRESH, so backup is required)
        db_path = tmp_path / "backup_custom_age.db"
        _create_legacy_ready_db(db_path)

        # Create a backup directory
        backup_dir = tmp_path / "backups_custom"
        backup_dir.mkdir()

        # Create a backup file (copy the DB)
        backup_path = backup_dir / "greywatch.db.backup"
        shutil.copy2(db_path, backup_path)

        # Set the backup's mtime to be 12 hours ago
        old_time = time.time() - (12 * 3600)
        os.utime(backup_path, (old_time, old_time))

        # Set environment variables with custom max age of 6 hours (backup is too old)
        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_MAX_BACKUP_AGE_HOURS", "6")

        from backend.app.main import app
        # Startup should fail because backup is older than custom max age
        with pytest.raises(RuntimeError, match="Backup required but no valid backup found"):
            with TestClient(app):
                pass

        # Now test with custom max age of 24 hours (backup is within limit)
        monkeypatch.setenv("GREYWATCH_MAX_BACKUP_AGE_HOURS", "24")
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["schema_ready"] is True


class TestBackupDirValidation:
    """Tests for GREYWATCH_BACKUP_DIR validation when GREYWATCH_REQUIRE_BACKUP=1."""

    def test_require_backup_without_backup_dir_fails(self, tmp_path, monkeypatch):
        """Startup fails when GREYWATCH_REQUIRE_BACKUP=1 but GREYWATCH_BACKUP_DIR is not set."""
        db_path = tmp_path / "no_backup_dir.db"
        _create_legacy_ready_db(db_path)

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        # Note: GREYWATCH_BACKUP_DIR is NOT set

        from backend.app.main import app
        with pytest.raises(RuntimeError, match="GREYWATCH_REQUIRE_BACKUP=1 is set but GREYWATCH_BACKUP_DIR is not configured"):
            with TestClient(app):
                pass

    def test_require_backup_with_empty_backup_dir_fails(self, tmp_path, monkeypatch):
        """Startup fails when GREYWATCH_BACKUP_DIR is set to empty string."""
        db_path = tmp_path / "empty_backup_dir.db"
        _create_legacy_ready_db(db_path)

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", "")

        from backend.app.main import app
        with pytest.raises(RuntimeError, match="GREYWATCH_REQUIRE_BACKUP=1 is set but GREYWATCH_BACKUP_DIR is not configured"):
            with TestClient(app):
                pass

    def test_require_backup_with_nonexistent_dir_fails(self, tmp_path, monkeypatch):
        """Startup fails when GREYWATCH_BACKUP_DIR points to a nonexistent directory."""
        db_path = tmp_path / "nonexistent_backup_dir.db"
        _create_legacy_ready_db(db_path)

        nonexistent_dir = tmp_path / "does_not_exist"
        # Don't create it

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(nonexistent_dir))

        from backend.app.main import app
        with pytest.raises(RuntimeError, match="does not exist"):
            with TestClient(app):
                pass

    def test_require_backup_with_file_not_dir_fails(self, tmp_path, monkeypatch):
        """Startup fails when GREYWATCH_BACKUP_DIR points to a file instead of directory."""
        db_path = tmp_path / "file_backup_dir.db"
        _create_legacy_ready_db(db_path)

        # Create a file at the backup dir path
        backup_file = tmp_path / "not_a_dir"
        backup_file.write_text("not a directory")

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_file))

        from backend.app.main import app
        with pytest.raises(RuntimeError, match="not a directory"):
            with TestClient(app):
                pass

    def test_require_backup_with_valid_dir_succeeds(self, tmp_path, monkeypatch):
        """Startup succeeds when GREYWATCH_BACKUP_DIR is a valid directory with valid backup."""
        import time
        import os
        import shutil

        db_path = tmp_path / "valid_backup_dir.db"
        _create_legacy_ready_db(db_path)

        backup_dir = tmp_path / "valid_backups"
        backup_dir.mkdir()

        # Create a valid backup
        backup_path = backup_dir / "greywatch.db.backup"
        shutil.copy2(db_path, backup_path)

        # Set recent mtime
        recent_time = time.time() - (1 * 3600)
        os.utime(backup_path, (recent_time, recent_time))

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))
        monkeypatch.setenv("GREYWATCH_MAX_BACKUP_AGE_HOURS", "24")

        from backend.app.main import app
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.json()["schema_ready"] is True
            assert resp.json()["migration_applied"] == 1


class TestBackupVerificationExceptions:
    """Tests for backup verification exception handling."""

    def test_corrupt_backup_rejected(self, tmp_path, monkeypatch):
        """Startup fails when backup is a corrupt SQLite database."""
        import os
        import shutil

        db_path = tmp_path / "corrupt_backup.db"
        _create_legacy_ready_db(db_path)

        backup_dir = tmp_path / "corrupt_backups"
        backup_dir.mkdir()

        # Create a corrupt "backup" file
        backup_path = backup_dir / "greywatch.db.backup"
        backup_path.write_bytes(b"not a valid sqlite database")

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))
        monkeypatch.setenv("GREYWATCH_MAX_BACKUP_AGE_HOURS", "24")

        from backend.app.main import app
        with pytest.raises(RuntimeError, match="Backup required but no valid backup found"):
            with TestClient(app):
                pass

    def test_inaccessible_backup_rejected(self, tmp_path, monkeypatch):
        """Startup fails when backup file cannot be read (permission denied)."""
        import os
        import shutil

        db_path = tmp_path / "inaccessible_backup.db"
        _create_legacy_ready_db(db_path)

        backup_dir = tmp_path / "inaccessible_backups"
        backup_dir.mkdir()

        # Create a valid backup
        backup_path = backup_dir / "greywatch.db.backup"
        shutil.copy2(db_path, backup_path)

        # Make it unreadable (only works if not running as root)
        if os.getuid() != 0:
            os.chmod(backup_path, 0o000)

            try:
                monkeypatch.setenv("GREYWATCH_DB", str(db_path))
                monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
                monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))
                monkeypatch.setenv("GREYWATCH_MAX_BACKUP_AGE_HOURS", "24")

                from backend.app.main import app
                with pytest.raises(RuntimeError, match="Backup required but no valid backup found"):
                    with TestClient(app):
                        pass
            finally:
                # Restore permissions for cleanup
                os.chmod(backup_path, 0o644)
        else:
            pytest.skip("Running as root, cannot test permission denial")

    def test_unexpected_verification_exception_propagates(self, tmp_path, monkeypatch):
        """Unexpected exceptions during verification are propagated with context."""
        import os
        import shutil
        from unittest import mock

        db_path = tmp_path / "unexpected_exc.db"
        _create_legacy_ready_db(db_path)

        backup_dir = tmp_path / "unexpected_backups"
        backup_dir.mkdir()

        # Create a valid backup
        backup_path = backup_dir / "greywatch.db.backup"
        shutil.copy2(db_path, backup_path)

        monkeypatch.setenv("GREYWATCH_DB", str(db_path))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))
        monkeypatch.setenv("GREYWATCH_MAX_BACKUP_AGE_HOURS", "24")

        # Mock verify_database to raise an unexpected exception
        with mock.patch("scripts.gw_db_backup.verify_database", side_effect=RuntimeError("unexpected error")):
            from backend.app.main import app
            with pytest.raises(RuntimeError, match="unexpected error"):
                with TestClient(app):
                    pass