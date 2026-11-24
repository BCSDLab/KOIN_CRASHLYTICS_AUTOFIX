import hashlib

from crashlytics_automation import fix_generation
from crashlytics_automation.candidate import (
    branch_name_for,
    candidate_manifest,
    identity_hash_for,
    is_allowed_source_path,
    is_allowed_test_path,
    manifest_path_for,
    regression_test_name,
    validate_manifest,
)
from crashlytics_automation.models import CrashAlert, ManualReview, SourceLocation
from crashlytics_automation.repository import REPOSITORY

ALERT = CrashAlert('crash-1', '1.2.3', 'event-1', '2026-01-01', 'Crash', 'detail')
BASE_SHA = 'a' * 40
RELEASE_SHA = 'b' * 40
OTHER_RELEASE_SHA = 'c' * 40
SOURCE_PATH = 'domain/src/main/java/org/koin/Thing.java'
SOURCE_BASE = 'package org.koin;\nclass Thing { int value() { return 1; } }\n'
SOURCE_AFTER = 'package org.koin;\nclass Thing { int value() { return 2; } }\n'
IDENTITY_HASH = identity_hash_for(ALERT.issue_id, RELEASE_SHA)
TEST_CLASS = regression_test_name(IDENTITY_HASH).removesuffix('.kt')
TEST_PATH = f'domain/src/androidTest/java/org/koin/{TEST_CLASS}.java'
TEST_CONTENT = f'''package org.koin;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class {TEST_CLASS} {{
    @Test public void thingReturnsFixedValue() {{
        assertEquals(2, new Thing().value());
    }}
}}
'''
DECISION = {
    'decision': 'fix',
    'sourcePath': SOURCE_PATH,
    'sourceLine': 2,
    'files': [
        {'path': SOURCE_PATH, 'content': SOURCE_AFTER},
        {'path': TEST_PATH, 'content': TEST_CONTENT},
    ],
}



def test_release_anchor_rejects_non_app_file_before_github_lookup():
    from crashlytics_automation.release_source import resolve_investigated_source

    class NoRequests:
        def graphql(self, *_args, **_kwargs):
            raise AssertionError('invalid anchor must be rejected before GitHub lookup')

    result = resolve_investigated_source(
        NoRequests(), release_sha=RELEASE_SHA,
        path='third-party/src/main/java/org/koin/Thing.java', line=1,
    )
    assert isinstance(result, ManualReview)

def test_candidate_accepts_java_production_and_instrumentation_test():
    assert is_allowed_source_path(SOURCE_PATH)
    assert is_allowed_test_path(TEST_PATH, IDENTITY_HASH)


def test_unverified_investigation_never_publishes(monkeypatch):
    published = []
    monkeypatch.setattr(fix_generation, 'publish_fix_pull_request', lambda *a, **k: published.append(True))

    result = fix_generation.publish_investigated_fix(
        object(), alert=ALERT, evidence={'status': 'ready'}, decision=DECISION,
        issue_number=1, base_branch='production', base_sha=BASE_SHA,
        release_sha=RELEASE_SHA, bot_login='autofix[bot]', verification={'passed': False},
    )

    assert isinstance(result, ManualReview)
    assert published == []


def test_unknown_baseline_never_publishes(monkeypatch):
    published = []
    monkeypatch.setattr(fix_generation, 'resolve_release_commit', lambda *_a, **_k: RELEASE_SHA)
    monkeypatch.setattr(fix_generation, 'resolve_investigated_source', lambda *_a, **_k: SourceLocation(
        SOURCE_PATH, 2, RELEASE_SHA, 'd' * 40, 'developer',
    ))
    monkeypatch.setattr(fix_generation, 'find_ai_fix_for_line', lambda *_a, **_k: None)
    monkeypatch.setattr(fix_generation, 'read_repository_file', lambda _g, _sha, _path: None)
    monkeypatch.setattr(fix_generation, 'publish_fix_pull_request', lambda *a, **k: published.append(True))

    result = fix_generation.publish_investigated_fix(
        object(), alert=ALERT, evidence={'status': 'ready'}, decision=DECISION,
        issue_number=1, base_branch='production', base_sha=BASE_SHA,
        release_sha=RELEASE_SHA, bot_login='autofix[bot]', verification={'passed': True},
    )

    assert isinstance(result, ManualReview)
    assert published == []


def test_java_instrumentation_test_publishes_release_scoped_manifest(monkeypatch):
    from crashlytics_automation.models import PublishedFix

    monkeypatch.setattr(fix_generation, 'resolve_release_commit', lambda *_a, **_k: RELEASE_SHA)
    monkeypatch.setattr(fix_generation, 'resolve_investigated_source', lambda *_a, **_k: SourceLocation(
        SOURCE_PATH, 2, RELEASE_SHA, 'd' * 40, 'developer',
    ))
    monkeypatch.setattr(fix_generation, 'find_ai_fix_for_line', lambda *_a, **_k: None)

    def read(_github, sha, path):
        assert sha == BASE_SHA
        return SOURCE_BASE if path == SOURCE_PATH else None

    monkeypatch.setattr(fix_generation, 'read_repository_file', read)
    expected = PublishedFix(12, 'e' * 40, BASE_SHA, 'f' * 64, 'production')
    captured = {}

    def publish(_github, *, plan, bot_login):
        captured['plan'] = plan
        captured['bot_login'] = bot_login
        return expected

    monkeypatch.setattr(fix_generation, 'publish_fix_pull_request', publish)
    result = fix_generation.publish_investigated_fix(
        object(), alert=ALERT, evidence={'status': 'ready'}, decision=DECISION,
        issue_number=1, base_branch='production', base_sha=BASE_SHA,
        release_sha=RELEASE_SHA, bot_login='autofix[bot]', verification={'passed': True},
    )

    plan = captured['plan']
    assert result is expected
    assert captured['bot_login'] == 'autofix[bot]'
    assert plan.manifest['version'] == 2
    assert plan.manifest['identityHash'] == IDENTITY_HASH
    assert plan.manifest['sourceSha'] == RELEASE_SHA
    assert {file['path'] for file in plan.manifest['files']} == {SOURCE_PATH, TEST_PATH}
    assert {change.path: change.content for change in plan.changes} == {
        SOURCE_PATH: SOURCE_AFTER, TEST_PATH: TEST_CONTENT,
    }


def test_changed_or_existing_test_baseline_is_rejected(monkeypatch):
    published = []
    monkeypatch.setattr(fix_generation, 'resolve_release_commit', lambda *_a, **_k: RELEASE_SHA)
    monkeypatch.setattr(fix_generation, 'resolve_investigated_source', lambda *_a, **_k: SourceLocation(
        SOURCE_PATH, 2, RELEASE_SHA, 'd' * 40, 'developer',
    ))
    monkeypatch.setattr(fix_generation, 'find_ai_fix_for_line', lambda *_a, **_k: None)
    monkeypatch.setattr(fix_generation, 'read_repository_file', lambda _g, _sha, path:
                        SOURCE_BASE if path == SOURCE_PATH else 'already exists')
    monkeypatch.setattr(fix_generation, 'publish_fix_pull_request', lambda *a, **k: published.append(True))

    result = fix_generation.publish_investigated_fix(
        object(), alert=ALERT, evidence={'status': 'ready'}, decision=DECISION,
        issue_number=1, base_branch='production', base_sha=BASE_SHA,
        release_sha=RELEASE_SHA, bot_login='autofix[bot]', verification={'passed': True},
    )

    assert isinstance(result, ManualReview)
    assert published == []


def test_source_release_changes_branch_test_and_manifest_identity():
    first = identity_hash_for(ALERT.issue_id, RELEASE_SHA)
    second = identity_hash_for(ALERT.issue_id, OTHER_RELEASE_SHA)
    assert first != second
    assert branch_name_for(first, 'production') != branch_name_for(second, 'production')
    assert manifest_path_for(first) != manifest_path_for(second)
    assert regression_test_name(first) != regression_test_name(second)
    assert not is_allowed_test_path(
        f'domain/src/test/java/org/koin/{regression_test_name(first)}', second,
    )

    first_manifest = candidate_manifest(
        issue_id=ALERT.issue_id, identity_hash=first, base_sha=BASE_SHA,
        source_sha=RELEASE_SHA, source_path=SOURCE_PATH,
        files=[
            {'path': SOURCE_PATH, 'kind': 'source', 'beforeSha256': '1' * 64, 'afterSha256': '2' * 64},
            {'path': f'domain/src/test/java/org/koin/{regression_test_name(first)}', 'kind': 'test',
             'beforeSha256': None, 'afterSha256': '3' * 64},
        ],
    )
    second_manifest = candidate_manifest(
        issue_id=ALERT.issue_id, identity_hash=second, base_sha=BASE_SHA,
        source_sha=OTHER_RELEASE_SHA, source_path=SOURCE_PATH,
        files=[
            {'path': SOURCE_PATH, 'kind': 'source', 'beforeSha256': '1' * 64, 'afterSha256': '2' * 64},
            {'path': f'domain/src/test/java/org/koin/{regression_test_name(second)}', 'kind': 'test',
             'beforeSha256': None, 'afterSha256': '3' * 64},
        ],
    )
    assert first_manifest['identityHash'] != second_manifest['identityHash']
    assert validate_manifest(first_manifest)['valid']
    assert validate_manifest(second_manifest)['valid']


def test_existing_fix_does_not_reuse_prior_release_issue_only_branch(monkeypatch):
    legacy_identity = hashlib.sha256(f'{REPOSITORY}/{ALERT.issue_id}'.encode()).hexdigest()
    lookups = []
    monkeypatch.setattr(fix_generation, 'find_target_pull_request',
                        lambda _g, identity, _target: lookups.append(identity))
    monkeypatch.setattr(fix_generation, 'find_branch_head', lambda *_a, **_k: None)

    result = fix_generation.existing_fix(
        object(), alert=ALERT, issue_number=1, base_branch='production',
        bot_login='autofix[bot]', release_sha=OTHER_RELEASE_SHA,
    )

    assert result is None
    assert lookups == [identity_hash_for(ALERT.issue_id, OTHER_RELEASE_SHA)]
    assert lookups[0] != legacy_identity


def test_legacy_v1_manifest_remains_valid_for_historical_merge_and_ownership():
    legacy_identity = hashlib.sha256(f'{REPOSITORY}/{ALERT.issue_id}'.encode()).hexdigest()
    legacy_test_path = f'domain/src/test/kotlin/org/koin/{regression_test_name(legacy_identity)}'
    legacy = {
        'version': 1,
        'issueId': ALERT.issue_id,
        'identityHash': legacy_identity,
        'baseSha': BASE_SHA,
        'sourceSha': RELEASE_SHA,
        'sourcePath': 'domain/src/main/kotlin/org/koin/Thing.kt',
        'files': [
            {'path': 'domain/src/main/kotlin/org/koin/Thing.kt', 'kind': 'source',
             'beforeSha256': '1' * 64, 'afterSha256': '2' * 64},
            {'path': legacy_test_path, 'kind': 'test',
             'beforeSha256': None, 'afterSha256': '3' * 64},
        ],
    }

    assert validate_manifest(legacy)['valid']
    assert validate_manifest(legacy, {'identityHash': legacy_identity})['valid']
    assert not validate_manifest(legacy, {'identityHash': IDENTITY_HASH})['valid']
