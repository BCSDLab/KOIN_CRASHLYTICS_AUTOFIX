import hashlib

import pytest

from crashlytics_automation.behavior import (
    VERIFICATION_VERSION, candidate_digest, preservation_test_name,
    prepare_behavior_review, source_digest, validate_review_binding,
    validate_verified_checks,
)
from crashlytics_automation.candidate import canonical_json

IDENTITY = 'a' * 64
SOURCE = 'domain/src/main/kotlin/example/Subject.kt'
CRASH = f'domain/src/test/kotlin/example/CrashlyticsRegression{IDENTITY[:12]}Test.kt'
PRESERVE = f'domain/src/test/kotlin/example/{preservation_test_name(IDENTITY)}'
BASE = 'package example\nclass Subject { fun reset() {} }\n'
AFTER = 'package example\nclass Subject { fun reset() { value = 0 } }\n'
CRASH_BODY = 'package example\nclass RegressionTest\n'
PRESERVE_BODY = 'package example\nclass PreservationTest\n'


def _sha(content):
    return hashlib.sha256(content.encode()).hexdigest()


def _files():
    return [
        {'path': SOURCE, 'kind': 'source', 'beforeSha256': _sha(BASE), 'afterSha256': _sha(AFTER), 'content': AFTER},
        {'path': CRASH, 'kind': 'test', 'beforeSha256': None, 'afterSha256': _sha(CRASH_BODY), 'content': CRASH_BODY},
        {'path': PRESERVE, 'kind': 'test', 'beforeSha256': None, 'afterSha256': _sha(PRESERVE_BODY), 'content': PRESERVE_BODY},
    ]


def _review(files=None):
    return {
        'approved': True,
        'reason': 'The change preserves the reset contract.',
        'unrelatedChanges': [],
        'contracts': [{
            'sourcePath': SOURCE, 'sourceLine': 2, 'behavior': 'Reset clears the value.',
            'testPath': PRESERVE, 'testMethod': 'resetClearsValue',
        }],
        'files': [{'path': PRESERVE, 'content': PRESERVE_BODY}] if files is None else files,
    }


def _checks():
    methods = ['resetClearsValue']
    return [
        {'phase': 'baseline', 'purpose': 'crash', 'path': CRASH, 'exit_code': 1,
         'timed_out': False, 'test_result': 'failed', 'evidence': {'source': 'junit-xml'}, 'methods': []},
        {'phase': 'candidate', 'purpose': 'crash', 'path': CRASH, 'exit_code': 0,
         'timed_out': False, 'test_result': 'passed', 'evidence': {'source': 'junit-xml'}, 'methods': ['crashCase']},
        {'phase': 'baseline', 'purpose': 'preservation', 'path': PRESERVE, 'exit_code': 0,
         'timed_out': False, 'test_result': 'passed', 'evidence': {'source': 'junit-xml'}, 'methods': methods},
        {'phase': 'candidate', 'purpose': 'preservation', 'path': PRESERVE, 'exit_code': 0,
         'timed_out': False, 'test_result': 'passed', 'evidence': {'source': 'junit-xml'}, 'methods': methods},
    ]


def test_preservation_name_and_source_digest_are_stable():
    entries = _files()
    projection = [{'path': SOURCE, 'beforeSha256': _sha(BASE), 'afterSha256': _sha(AFTER)}]
    expected = hashlib.sha256(canonical_json(projection).encode()).hexdigest()
    assert preservation_test_name(IDENTITY) == f'CrashlyticsPreservation{IDENTITY[:12]}Test.kt'
    assert source_digest(entries) == expected


def test_prepare_review_normalizes_and_binds_exact_source_scope():
    entries = _files()
    result = prepare_behavior_review(_review(), entries, {SOURCE: BASE}, IDENTITY)
    assert result == {
        'version': 1, 'approved': True, 'reason': 'The change preserves the reset contract.',
        'unrelatedChanges': [], 'contracts': _review()['contracts'], 'sourceDigest': source_digest(entries),
    }


@pytest.mark.parametrize('mutation', ['rejected', 'unrelated', 'missing-test', 'bad-line', 'new-source', 'wrong-module'])
def test_prepare_review_rejects_incomplete_or_forged_review(mutation):
    entries = _files()
    review = _review()
    baselines = {SOURCE: BASE}
    if mutation == 'rejected':
        review['approved'] = False
    elif mutation == 'unrelated':
        review['unrelatedChanges'] = ['changed timing']
    elif mutation == 'missing-test':
        review['files'] = []
    elif mutation == 'bad-line':
        review['contracts'][0]['sourceLine'] = 99
    elif mutation == 'new-source':
        review['contracts'][0]['sourcePath'] = 'domain/src/main/kotlin/example/Other.kt'
    else:
        review['contracts'][0]['testPath'] = 'data/src/test/kotlin/example/' + preservation_test_name(IDENTITY)
        review['files'][0]['path'] = review['contracts'][0]['testPath']
    with pytest.raises(ValueError):
        prepare_behavior_review(review, entries, baselines, IDENTITY)


def test_candidate_digest_binds_test_bytes_and_review_binding_checks_scope():
    entries = _files()
    normalized = prepare_behavior_review(_review(), entries, {SOURCE: BASE}, IDENTITY)
    validate_review_binding(entries, normalized)
    original = candidate_digest(entries)
    tampered = [dict(entry) for entry in entries]
    tampered[-1]['afterSha256'] = hashlib.sha256(b'other').hexdigest()
    assert original != candidate_digest(tampered)
    tampered_review = dict(normalized)
    tampered_review['sourceDigest'] = '0' * 64
    with pytest.raises(ValueError):
        validate_review_binding(entries, tampered_review)


def _verification(files):
    return {
        'version': VERIFICATION_VERSION, 'passed': True,
        'candidateDigest': candidate_digest(files),
        'behaviorReview': {
            'version': 1, 'approved': True, 'reason': 'Approved', 'unrelatedChanges': [],
            'contracts': _review()['contracts'], 'sourceDigest': source_digest(files),
        },
        'checks': _checks(),
    }


def test_verified_checks_require_baseline_crash_and_actual_preservation_methods():
    entries = _files()
    validate_verified_checks(entries, _verification(entries))


def test_verified_checks_reject_legacy_forged_missing_and_skipped_method_proofs():
    entries = _files()
    valid = _verification(entries)
    with pytest.raises(ValueError):
        validate_verified_checks(entries, {'passed': True, 'checks': valid['checks']})

    forged = _verification(entries)
    forged['behaviorReview']['sourceDigest'] = '0' * 64
    with pytest.raises(ValueError):
        validate_verified_checks(entries, forged)

    forged_candidate = _verification(entries)
    forged_candidate['candidateDigest'] = '0' * 64
    with pytest.raises(ValueError):
        validate_verified_checks(entries, forged_candidate)

    preservation_failure = _verification(entries)
    preservation_failure['checks'][2].update({
        'exit_code': 1, 'test_result': 'failed', 'methods': [],
    })
    with pytest.raises(ValueError):
        validate_verified_checks(entries, preservation_failure)

    timed_out = _verification(entries)
    timed_out['checks'][1]['timed_out'] = True
    with pytest.raises(ValueError):
        validate_verified_checks(entries, timed_out)

    missing = _verification(entries)
    missing['checks'].pop()
    with pytest.raises(ValueError):
        validate_verified_checks(entries, missing)

    skipped = _verification(entries)
    skipped['checks'][2]['methods'] = []
    with pytest.raises(ValueError):
        validate_verified_checks(entries, skipped)


def test_verified_checks_accept_only_strict_android_oom_fatal_proof():
    entries = _files()
    proof = _verification(entries)
    proof['checks'][0].update({
        'exit_code': 1, 'test_result': 'fatal-oom',
        'evidence': {'source': 'android-logcat', 'package': 'example.app', 'pid': 17,
                     'failure': 'fatal OutOfMemoryError', 'testClass': 'example.CrashTest'},
    })
    validate_verified_checks(entries, proof)
    proof['checks'][0]['evidence']['pid'] = '17'
    with pytest.raises(ValueError):
        validate_verified_checks(entries, proof)
