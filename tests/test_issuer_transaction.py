import concurrent.futures
from contextlib import closing
import os
from pathlib import Path
from unittest.mock import patch, Mock
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from validator.issuer_transaction import (
    BoundaryError, SimulatedCrash, Intent, Ledger, FakePublisher, validate_intent,
    SCHEMA, STATES, main,
)


def make_intent():
    return Intent('mf002078/GOV-GITHUB', 'a' * 40, 'b' * 64, 'c' * 64, 5475837, 19)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ledger = Ledger(Path(self.tmp.name) / 'ledger.sqlite')
        self.intent = make_intent()
        self.key = self.intent.identity()

    def blocked(self, fn, *args):
        with self.assertRaises(BoundaryError):
            fn(*args)

    def test_validate_positive(self):
        self.assertEqual(validate_intent(self.intent), self.key)

    def test_schema_and_states(self):
        self.assertEqual(SCHEMA, 'issuer-transaction-v1')
        self.assertEqual(len(STATES), 4)

    def test_invalid_type(self):
        self.blocked(validate_intent, dict(repo=self.intent.repo))

    def test_bad_repo(self):
        self.blocked(validate_intent, replace(self.intent, repo='Pochun2/GOV-TRUSTED-ISSUER'))

    def test_bad_head(self):
        self.blocked(validate_intent, replace(self.intent, head_sha='A' * 40))

    def test_bad_evidence(self):
        self.blocked(validate_intent, replace(self.intent, evidence_sha256='0' * 63))

    def test_bad_policy(self):
        self.blocked(validate_intent, replace(self.intent, policy_sha256='G' * 64))

    def test_wrong_app(self):
        self.blocked(validate_intent, replace(self.intent, app_id=15368))

    def test_boolean_app(self):
        self.blocked(validate_intent, replace(self.intent, app_id=True))

    def test_zero_installation(self):
        self.blocked(validate_intent, replace(self.intent, installation_id=0))

    def test_boolean_installation(self):
        self.blocked(validate_intent, replace(self.intent, installation_id=True))

    def test_bad_check_name(self):
        self.blocked(validate_intent, replace(self.intent, check_name='other'))

    def test_identity_changes_policy(self):
        self.assertNotEqual(self.key, replace(self.intent, policy_sha256='d'*64).identity())

    def test_identity_changes_installation(self):
        self.assertNotEqual(self.key, replace(self.intent, installation_id=21).identity())

    def test_missing_parent(self):
        self.blocked(Ledger, Path(self.tmp.name)/'absent'/'db.sqlite')

    def test_symlink_ledger(self):
        p = Path(self.tmp.name)/'real'; p.touch()
        link = Path(self.tmp.name)/'alias'
        try:
            link.symlink_to(p)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink unavailable')
        self.blocked(Ledger, link)

    def test_prepare(self):
        self.assertEqual(self.ledger.prepare(self.intent), self.key)
        self.assertEqual(self.ledger.state(self.key), 'PREPARED')

    def test_replay_prepare(self):
        self.ledger.prepare(self.intent)
        self.blocked(self.ledger.prepare, self.intent)

    def test_replay_after_publish(self):
        self.ledger.prepare(self.intent)
        self.ledger.publish_mock(self.intent, FakePublisher())
        self.blocked(self.ledger.prepare, self.intent)

    def test_unknown_transaction(self):
        self.blocked(self.ledger.state, 'f'*64)

    def test_invalid_transaction_id(self):
        self.blocked(self.ledger.state, 'bad')

    def test_mock_success(self):
        self.ledger.prepare(self.intent)
        mock = FakePublisher()
        r = self.ledger.publish_mock(self.intent, mock)
        self.assertEqual(r['state'], 'MOCK_PUBLISHED_NOT_ATTESTED')
        self.assertEqual(mock.calls, [self.key])
        self.assertEqual(self.ledger.state(self.key), 'PUBLISHED')

    def test_no_publishing_twice(self):
        self.ledger.prepare(self.intent)
        self.ledger.publish_mock(self.intent, FakePublisher())
        mock = FakePublisher()
        self.blocked(self.ledger.publish_mock, self.intent, mock)
        self.assertEqual(mock.calls, [])

    def test_reject_arbitrary_publisher(self):
        self.ledger.prepare(self.intent)
        self.blocked(self.ledger.publish_mock, self.intent, object())
        self.assertEqual(self.ledger.state(self.key), 'PREPARED')

    def test_mock_failure(self):
        self.ledger.prepare(self.intent)
        self.blocked(self.ledger.publish_mock, self.intent, FakePublisher('error'))
        self.assertEqual(self.ledger.state(self.key), 'BLOCKED')

    def test_bad_receipt(self):
        self.ledger.prepare(self.intent)
        self.blocked(self.ledger.publish_mock, self.intent, FakePublisher('bad_receipt'))
        self.assertEqual(self.ledger.state(self.key), 'BLOCKED')

    def test_crash_before(self):
        self.ledger.prepare(self.intent)
        with self.assertRaises(SimulatedCrash):
            self.ledger.publish_mock(self.intent, FakePublisher('crash_before'))
        self.assertEqual(self.ledger.state(self.key), 'PUBLISHING')

    def test_crash_after(self):
        self.ledger.prepare(self.intent)
        with self.assertRaises(SimulatedCrash):
            self.ledger.publish_mock(self.intent, FakePublisher('crash_after'))
        self.assertEqual(self.ledger.state(self.key), 'PUBLISHING')

    def test_crash_no_retry(self):
        self.ledger.prepare(self.intent)
        with self.assertRaises(SimulatedCrash):
            self.ledger.publish_mock(self.intent, FakePublisher('crash_after'))
        another = FakePublisher()
        self.blocked(self.ledger.publish_mock, self.intent, another)
        self.assertEqual(another.calls, [])

    def test_seal_uncertain(self):
        self.ledger.prepare(self.intent)
        with self.assertRaises(SimulatedCrash):
            self.ledger.publish_mock(self.intent, FakePublisher('crash_after'))
        self.assertEqual(self.ledger.seal_uncertain(self.key), 'BLOCKED')
        self.assertEqual(self.ledger.state(self.key), 'BLOCKED')

    def test_no_seal_prepared(self):
        self.ledger.prepare(self.intent)
        self.blocked(self.ledger.seal_uncertain, self.key)

    def test_no_seal_published(self):
        self.ledger.prepare(self.intent)
        self.ledger.publish_mock(self.intent, FakePublisher())
        self.blocked(self.ledger.seal_uncertain, self.key)

    def test_durable_reopen(self):
        self.ledger.prepare(self.intent)
        self.assertEqual(Ledger(self.ledger.path).state(self.key), 'PREPARED')

    def test_reopen_no_republish(self):
        self.ledger.prepare(self.intent)
        self.ledger.publish_mock(self.intent, FakePublisher())
        self.blocked(Ledger(self.ledger.path).publish_mock, self.intent, FakePublisher())

    def test_ledger_row_integrity(self):
        self.ledger.prepare(self.intent)
        self.ledger.publish_mock(self.intent, FakePublisher())
        with closing(sqlite3.connect(self.ledger.path)) as c:
            r = c.execute('SELECT state, revision, receipt FROM issuance').fetchone()
        self.assertEqual(r[0], 'PUBLISHED')
        self.assertEqual(r[1], 2)
        self.assertTrue(r[2].startswith('MOCK:'))

    def test_concurrent_same_identity_prepare(self):
        def worker(_):
            try:
                self.ledger.prepare(self.intent)
                return 'PASS'
            except BoundaryError:
                return 'BLOCKED'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            result = list(ex.map(worker, range(12)))
        self.assertEqual(result.count('PASS'), 1)
        self.assertEqual(result.count('BLOCKED'), 11)

    def test_concurrent_publish_only_one_call(self):
        self.ledger.prepare(self.intent)
        def worker(_):
            mock = FakePublisher()
            try:
                self.ledger.publish_mock(self.intent, mock)
                return 'PASS', len(mock.calls)
            except BoundaryError:
                return 'BLOCKED', len(mock.calls)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            result = list(ex.map(worker, range(12)))
        self.assertEqual(result.count(('PASS',1)), 1)
        self.assertEqual(result.count(('BLOCKED',0)), 11)

    def test_separate_intents(self):
        k1 = self.ledger.prepare(self.intent)
        other = replace(self.intent, evidence_sha256='e'*64)
        k2 = self.ledger.prepare(other)
        self.assertNotEqual(k1, k2)

    def test_bad_transition_source(self):
        self.ledger.prepare(self.intent)
        self.blocked(self.ledger._transition, self.key, 'PUBLISHED', 'BLOCKED')

    def test_bad_transition_state(self):
        self.ledger.prepare(self.intent)
        self.blocked(self.ledger._transition, self.key, 'INVALID', 'BLOCKED')

    def test_corrupt_database_fails_closed(self):
        self.ledger.path.write_bytes(b'NOT_SQLITE_DATA')
        self.blocked(self.ledger.prepare, self.intent)

    def test_failed_pragma_closes_connection(self):
        # Regression: sqlite3.connect succeeds, PRAGMA raises; no leaked handle.
        fake_connection = Mock()
        fake_connection.execute.side_effect = sqlite3.DatabaseError('corrupt')
        with patch('validator.issuer_transaction.sqlite3.connect', return_value=fake_connection):
            self.blocked(self.ledger.prepare, self.intent)
        fake_connection.close.assert_called_once_with()

    def test_cli_self_check(self):
        self.assertEqual(main(['--self-check']), 0)

    def test_cli_default_blocked(self):
        self.assertEqual(main([]), 2)

    def test_invalid_mock_mode(self):
        with self.assertRaises(ValueError):
            FakePublisher('real')


if __name__ == '__main__':
    unittest.main()
