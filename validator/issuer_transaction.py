"""Stage 012C offline issuance journal (no GitHub I/O, credentials or authorization).

The SQLite transaction is NOT atomic with external publishing. In doubt, block.
A mock publisher exercises transitions but does not prove exactly-once delivery.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import os
import re
import sqlite3
from typing import Protocol

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SCHEMA = "issuer-transaction-v1"
STATES = ("PREPARED", "PUBLISHING", "PUBLISHED", "BLOCKED")


class BoundaryError(Exception):
    """Expected, sanitized boundary rejection."""


class SimulatedCrash(BaseException):
    """An unhandled process crash during an untrusted external side effect."""


def reject(label: str):
    raise BoundaryError(label)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _hex(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


@dataclass(frozen=True)
class Intent:
    repo: str
    head_sha: str
    evidence_sha256: str
    policy_sha256: str
    app_id: int
    installation_id: int
    check_name: str = "GOV-Protected-Validator"

    def identity(self):
        # All fields are validated before this method is used.
        values = [SCHEMA, self.repo, self.head_sha, self.evidence_sha256,
                  self.policy_sha256, str(self.app_id), str(self.installation_id), self.check_name]
        return _digest("\x00".join(values))


def validate_intent(intent):
    if type(intent) is not Intent:
        reject("INVALID_INTENT_TYPE")
    if intent.repo != "mf002078/GOV-GITHUB":
        reject("UNAPPROVED_REPOSITORY")
    if not _hex(intent.head_sha, SHA40):
        reject("INVALID_HEAD_SHA")
    if not _hex(intent.evidence_sha256, SHA256) or not _hex(intent.policy_sha256, SHA256):
        reject("INVALID_EVIDENCE_OR_POLICY_DIGEST")
    if type(intent.app_id) is not int or intent.app_id != 5475837:
        reject("UNAPPROVED_APP_ID")
    if type(intent.installation_id) is not int or intent.installation_id <= 0:
        reject("INVALID_INSTALLATION_ID")
    if intent.check_name != "GOV-Protected-Validator":
        reject("UNAPPROVED_CHECK_NAME")
    return intent.identity()


class MockPublisher(Protocol):
    def publish(self, intent: Intent, transaction_id: str) -> str: ...


class FakePublisher:
    """In-process deterministic mock; never connects to GitHub."""
    def __init__(self, mode="success"):
        if mode not in ("success", "error", "crash_before", "crash_after", "bad_receipt"):
            raise ValueError("INVALID_MOCK_MODE")
        self.mode = mode
        self.calls = []

    def publish(self, intent, transaction_id):
        self.calls.append(transaction_id)
        if self.mode == "error":
            raise RuntimeError("MOCK_EXTERNAL_FAILURE")
        if self.mode == "crash_before":
            raise SimulatedCrash()
        receipt = "MOCK:" + _digest(transaction_id)
        if self.mode == "crash_after":
            raise SimulatedCrash()
        if self.mode == "bad_receipt":
            return "UNTRUSTED"
        return receipt


class Ledger:
    """Local durable mock journal; unreconciled PUBLISHING states never auto-retry.

    Requires a trusted, persistent local directory; does not authenticate filesystem
    owners, protect against DB rollback/deletion, or guarantee multi-host uniqueness.
    """
    def __init__(self, path):
        self.path = Path(path)
        if (not self.path.parent.is_dir() or self.path.is_symlink() or
            (self.path.exists() and not self.path.is_file())):
            reject("INVALID_LEDGER_LOCATION")

    def _connect(self):
        # On Windows an open SQLite handle prevents TemporaryDirectory cleanup.
        # PRAGMA setup may raise *after* connect succeeds (e.g. corrupt database),
        # so close the partially initialized connection before failing closed.
        c = None
        try:
            c = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
            c.execute("PRAGMA busy_timeout=5000")
            c.execute("PRAGMA synchronous=FULL")
            c.execute("PRAGMA journal_mode=DELETE")
            return c
        except sqlite3.Error:
            if c is not None:
                try:
                    c.close()
                except sqlite3.Error:
                    pass  # Preserve sanitized fail-closed error.
            reject("LEDGER_UNAVAILABLE")

    def _transaction(self, conn):
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS issuance ("
                     "identity TEXT PRIMARY KEY, repo TEXT NOT NULL, head_sha TEXT NOT NULL, "
                     "evidence_sha256 TEXT NOT NULL, policy_sha256 TEXT NOT NULL, "
                     "app_id INTEGER NOT NULL, installation_id INTEGER NOT NULL, "
                     "check_name TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN "
                     "('PREPARED','PUBLISHING','PUBLISHED','BLOCKED')), "
                     "receipt TEXT, reason TEXT, revision INTEGER NOT NULL DEFAULT 0)")

    def prepare(self, intent: Intent):
        key = validate_intent(intent)
        try:
            with closing(self._connect()) as conn:
                self._transaction(conn)
                if conn.execute("SELECT identity FROM issuance WHERE identity=?", (key,)).fetchone():
                    conn.execute("ROLLBACK")
                    reject("REPLAY_INTENT")
                conn.execute("INSERT INTO issuance(identity,repo,head_sha,evidence_sha256,"
                             "policy_sha256,app_id,installation_id,check_name,state) "
                             "VALUES(?,?,?,?,?,?,?,?,?)", (key, intent.repo, intent.head_sha,
                             intent.evidence_sha256, intent.policy_sha256, intent.app_id,
                             intent.installation_id, intent.check_name, "PREPARED"))
                conn.execute("COMMIT")
            return key
        except sqlite3.Error:
            reject("LEDGER_UNAVAILABLE")

    def state(self, key):
        if not _hex(key, SHA256):
            reject("INVALID_TRANSACTION_ID")
        try:
            with closing(self._connect()) as conn:
                self._transaction(conn)
                row = conn.execute("SELECT state FROM issuance WHERE identity=?", (key,)).fetchone()
                conn.execute("COMMIT")
            if row is None:
                reject("UNKNOWN_TRANSACTION")
            return row[0]
        except sqlite3.Error:
            reject("LEDGER_UNAVAILABLE")

    def _transition(self, key, source, target, receipt=None, reason=None):
        if not _hex(key, SHA256) or source not in STATES or target not in STATES:
            reject("INVALID_TRANSITION")
        try:
            with closing(self._connect()) as conn:
                self._transaction(conn)
                changed = conn.execute("UPDATE issuance SET state=?,receipt=?,reason=?,"
                                       "revision=revision+1 WHERE identity=? AND state=?",
                                       (target, receipt, reason, key, source)).rowcount
                if changed != 1:
                    conn.execute("ROLLBACK")
                    reject("STATE_CONFLICT_OR_REPLAY")
                conn.execute("COMMIT")
        except sqlite3.Error:
            reject("LEDGER_UNAVAILABLE")

    def publish_mock(self, intent: Intent, publisher: MockPublisher):
        """Mock only. No network publisher is present or accepted by production code.

        A crash after PREPARED->PUBLISHING cannot be distinguished from a remote
        side effect. Never invoke publisher again on that transaction.
        """
        key = validate_intent(intent)
        if not isinstance(publisher, FakePublisher):
            reject("MOCK_PUBLISHER_REQUIRED")
        self._transition(key, "PREPARED", "PUBLISHING")
        try:
            receipt = publisher.publish(intent, key)
        except Exception:
            # A normal mock exception is conservatively BLOCKED, not retried.
            self._transition(key, "PUBLISHING", "BLOCKED", reason="MOCK_ERROR")
            reject("MOCK_PUBLISH_FAILED")
        # SimulatedCrash intentionally escapes; state stays PUBLISHING.
        if receipt != "MOCK:" + _digest(key):
            self._transition(key, "PUBLISHING", "BLOCKED", reason="INVALID_MOCK_RECEIPT")
            reject("MOCK_RECEIPT_REJECTED")
        self._transition(key, "PUBLISHING", "PUBLISHED", receipt=receipt)
        return {"state": "MOCK_PUBLISHED_NOT_ATTESTED", "transaction_id": key}

    def seal_uncertain(self, key):
        """Operator-directed local quarantine only; does NOT reconcile remote API."""
        self._transition(key, "PUBLISHING", "BLOCKED", reason="UNCERTAIN_EXTERNAL_OUTCOME")
        return "BLOCKED"


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Offline transaction simulator; no API writes")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if not args.self_check:
        print(json.dumps({"state": "BLOCKED", "reason": "OFFLINE_SELF_CHECK_ONLY"}))
        return 2
    print(json.dumps({"state": "OFFLINE_ONLY", "note": "NO_APP_KEY_NO_TOKEN_NO_CHECK_RUN_GATE_A_BLOCKED"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
