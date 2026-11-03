"""Unprivileged issuer-side prototype, not authenticated attestation or publisher.

The trusted operator must build Snapshot from independently authenticated GitHub
API calls, not candidate submissions. No HTTP, credential or Check Run actions.
"""
import datetime as dt
import re
import sqlite3
from dataclasses import dataclass

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
SOURCE = "mf002078/GOV-GITHUB"
VALIDATOR = "mf002078/GOV-PROTECTED-VALIDATOR"
SOURCE_CHECK = "validate"
VALIDATOR_CHECK = "self-test"
ACTIONS_APP_ID = 15368


@dataclass(frozen=True)
class Check:
    repository: str
    context: str
    sha: str
    conclusion: str
    app_id: int
    run_id: int
    attempt: int


@dataclass(frozen=True)
class Snapshot:
    source_repository: str
    source_head: str
    source_base: str
    validator_repository: str
    validator_head: str
    policy_sha256: str
    model_report_sha256: str
    model_state: str
    reviewed_source_head: str
    source_check: Check
    validator_check: Check
    observed_at_utc: str


def _utc(s):
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", s):
        return None
    try:
        return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


def validate_snapshot(s, *, source_head, validator_head, policy_sha256, now_utc):
    """Return BLOCKED or ELIGIBLE_FOR_AUTHENTICATED_ISSUER_RECHECK.

    This is a consistency predicate on *provided* data, not proof API calls
    were real. In particular never use a candidate-built Snapshot for issuance.
    """
    if not isinstance(s, Snapshot) or not all(isinstance(x, str) and SHA40.fullmatch(x)
        for x in (source_head, validator_head, s.source_head, s.source_base, s.validator_head,
                  s.reviewed_source_head)):
        return "BLOCKED"
    if not isinstance(policy_sha256, str) or not SHA64.fullmatch(policy_sha256):
        return "BLOCKED"
    if (s.source_repository != SOURCE or s.validator_repository != VALIDATOR
            or s.source_head != source_head or s.validator_head != validator_head
            or s.source_base == s.source_head or s.policy_sha256 != policy_sha256
            or not isinstance(s.model_report_sha256, str) or not SHA64.fullmatch(s.model_report_sha256)
            or s.reviewed_source_head != source_head
            or s.model_state != "REVIEWED_NO_ATTESTATION"):
        return "BLOCKED"
    now, obs = _utc(now_utc), _utc(s.observed_at_utc)
    if now is None or obs is None or not 0 <= (now-obs).total_seconds() <= 300:
        return "BLOCKED"
    for c, repo, ctx, sha in ((s.source_check, SOURCE, SOURCE_CHECK, source_head),
                              (s.validator_check, VALIDATOR, VALIDATOR_CHECK, validator_head)):
        if not isinstance(c, Check):
            return "BLOCKED"
        if (c.repository != repo or c.context != ctx or c.sha != sha
                or c.conclusion != "success" or type(c.app_id) is not int
                or c.app_id != ACTIONS_APP_ID or type(c.run_id) is not int or c.run_id < 1
                or type(c.attempt) is not int or c.attempt < 1):
            return "BLOCKED"
    return "ELIGIBLE_FOR_AUTHENTICATED_ISSUER_RECHECK"


def reserve_replay(conn, *, source_sha, validator_sha, source_run, source_attempt,
                   validator_run, validator_attempt, model_report_sha256):
    """Atomically reserve an evidence tuple in trusted durable SQLite storage.

    Caller must supply an independently controlled persistent connection. The
    source of each tuple member must be authenticated separately. False means
    duplicate; this function never signs, approves, or publishes anything.
    """
    if not (all(isinstance(s, str) and SHA40.fullmatch(s) for s in (source_sha, validator_sha))
            and isinstance(model_report_sha256, str) and SHA64.fullmatch(model_report_sha256)
            and all(type(x) is int and x > 0 for x in
                    (source_run, source_attempt, validator_run, validator_attempt))):
        return False
    # For concurrency, claim a write transaction before testing/adding tuple.
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS issuer_replay (
            source_sha TEXT NOT NULL, validator_sha TEXT NOT NULL,
            source_run INTEGER NOT NULL, source_attempt INTEGER NOT NULL,
            validator_run INTEGER NOT NULL, validator_attempt INTEGER NOT NULL,
            model_report_sha256 TEXT NOT NULL,
            PRIMARY KEY(source_sha,validator_sha,source_run,source_attempt,
                        validator_run,validator_attempt,model_report_sha256))""")
        conn.execute("""INSERT INTO issuer_replay VALUES(?,?,?,?,?,?,?)""",
                     (source_sha,validator_sha,source_run,source_attempt,
                      validator_run,validator_attempt,model_report_sha256))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        conn.rollback()
        return False
    except Exception:
        conn.rollback()
        raise
