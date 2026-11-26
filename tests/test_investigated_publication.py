import hashlib

from crashlytics_automation import fix_generation
from crashlytics_automation.candidate import (
    SHARED_FIX_BRANCH,
    branch_name_for,
    candidate_manifest,
    identity_hash_for,
    is_allowed_source_path,
    is_allowed_test_path,
    regression_test_name,
    validate_manifest,
)
from crashlytics_automation.models import CrashAlert, FileChange, FixPlan, ManualReview, SourceLocation
from crashlytics_automation.pull_requests import publish_fix_pull_request, resume_fix_pull_request
from crashlytics_automation.repository import REPOSITORY

class PublicationStore:
    def __init__(self, record=None, *, fail=False):
        self.records = {}
        self.record = record
        self.fail = fail
        self.events = []

    def put_publication(self, head_sha, base_branch, manifest):
        self.events.append(('put', head_sha, base_branch))
        if self.fail:
            raise ValueError('metadata unavailable')
        self.records[(head_sha, base_branch)] = manifest

    def get_publication(self, head_sha, base_branch):
        self.events.append(('get', head_sha, base_branch))
        return self.records.get((head_sha, base_branch), self.record)


ALERT = CrashAlert('crash-1', '1.2.3', 'event-1', '2026-01-01', 'Crash', 'detail')
BASE_SHA = 'a' * 40
BRANCH_BASE_SHA = 'd' * 40
RELEASE_SHA = 'b' * 40
OTHER_RELEASE_SHA = 'c' * 40
DEVELOP_SHA = 'f' * 40
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
        branch_base_sha=BRANCH_BASE_SHA, release_sha=RELEASE_SHA,
        bot_login='autofix[bot]', verification={'passed': False},
        publication_store=PublicationStore(),
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
        branch_base_sha=BRANCH_BASE_SHA, release_sha=RELEASE_SHA,
        bot_login='autofix[bot]', verification={'passed': True},
        publication_store=PublicationStore(),
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
        assert sha == BRANCH_BASE_SHA
        return SOURCE_BASE if path == SOURCE_PATH else None

    monkeypatch.setattr(fix_generation, 'read_repository_file', read)
    expected = PublishedFix(12, 'e' * 40, BASE_SHA, 'f' * 64, 'production')
    captured = {}

    def publish(_github, *, plan, bot_login, publication_store):
        captured['plan'] = plan
        captured['bot_login'] = bot_login
        captured['publication_store'] = publication_store
        return expected

    monkeypatch.setattr(fix_generation, 'publish_fix_pull_request', publish)
    result = fix_generation.publish_investigated_fix(
        object(), alert=ALERT, evidence={'status': 'ready'}, decision=DECISION,
        issue_number=1, base_branch='production', base_sha=BASE_SHA,
        branch_base_sha=BRANCH_BASE_SHA, release_sha=RELEASE_SHA,
        bot_login='autofix[bot]', verification={'passed': True},
        publication_store=PublicationStore(),
    )

    plan = captured['plan']
    assert result is expected
    assert captured['bot_login'] == 'autofix[bot]'
    assert plan.manifest['version'] == 3
    assert plan.manifest['issueNumber'] == 1
    assert plan.manifest['baseSha'] == BASE_SHA
    assert plan.manifest['branchBaseSha'] == BRANCH_BASE_SHA
    assert plan.branch_base_sha == BRANCH_BASE_SHA
    assert plan.manifest['identityHash'] == IDENTITY_HASH
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
        branch_base_sha=BRANCH_BASE_SHA, release_sha=RELEASE_SHA,
        bot_login='autofix[bot]', verification={'passed': True},
        publication_store=PublicationStore(),
    )

    assert isinstance(result, ManualReview)
    assert published == []


def test_source_release_changes_branch_test_and_manifest_identity():
    first = identity_hash_for(ALERT.issue_id, RELEASE_SHA)
    second = identity_hash_for(ALERT.issue_id, OTHER_RELEASE_SHA)
    assert first != second
    branch = branch_name_for(first, 1)
    match = SHARED_FIX_BRANCH.fullmatch(branch)
    assert match is not None
    assert match.group('issueNumber') == '1'
    assert match.group('identityHash') == first
    assert branch_name_for(first, 1) != branch_name_for(second, 1)
    assert regression_test_name(first) != regression_test_name(second)
    assert not is_allowed_test_path(
        f'domain/src/test/java/org/koin/{regression_test_name(first)}', second,
    )

    first_manifest = candidate_manifest(
        issue_id=ALERT.issue_id, identity_hash=first, issue_number=1,
        base_sha=BASE_SHA, branch_base_sha=BRANCH_BASE_SHA,
        source_sha=RELEASE_SHA, source_path=SOURCE_PATH,
        files=[
            {'path': SOURCE_PATH, 'kind': 'source', 'beforeSha256': '1' * 64, 'afterSha256': '2' * 64},
            {'path': f'domain/src/test/java/org/koin/{regression_test_name(first)}', 'kind': 'test',
             'beforeSha256': None, 'afterSha256': '3' * 64},
        ],
    )
    second_manifest = candidate_manifest(
        issue_id=ALERT.issue_id, identity_hash=second, issue_number=1,
        base_sha=BASE_SHA, branch_base_sha=BRANCH_BASE_SHA,
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
                        lambda _g, identity, _target, _issue: lookups.append(identity))
    monkeypatch.setattr(fix_generation, 'find_branch_head', lambda *_a, **_k: None)

    result = fix_generation.existing_fix(
        object(), alert=ALERT, issue_number=1, base_branch='production',
        bot_login='autofix[bot]', release_sha=OTHER_RELEASE_SHA,
        branch_base_sha=BRANCH_BASE_SHA, publication_store=PublicationStore(),
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
 
def test_develop_publication_commits_production_tree_but_targets_develop():
    manifest = candidate_manifest(
        issue_id=ALERT.issue_id,
        identity_hash=IDENTITY_HASH,
        issue_number=17,
        base_sha=DEVELOP_SHA,
        branch_base_sha=BRANCH_BASE_SHA,
        source_sha=RELEASE_SHA,
        source_path=SOURCE_PATH,
        files=[
            {
                'path': SOURCE_PATH, 'kind': 'source',
                'beforeSha256': hashlib.sha256(SOURCE_BASE.encode()).hexdigest(),
                'afterSha256': hashlib.sha256(SOURCE_AFTER.encode()).hexdigest(),
            },
            {
                'path': TEST_PATH, 'kind': 'test',
                'beforeSha256': None,
                'afterSha256': hashlib.sha256(TEST_CONTENT.encode()).hexdigest(),
            },
        ],
    )
    calls = []

    class Github:
        class Missing(Exception):
            status = 404

        def rest(self, method, path, data=None):
            calls.append((method, path, data))
            if method == 'GET' and path.endswith(f'/git/commits/{BRANCH_BASE_SHA}'):
                return {'tree': {'sha': '1' * 40}}
            if method == 'GET' and path.startswith('/repos/') and '/git/ref/heads/' in path:
                raise self.Missing()
            if method == 'POST' and path.endswith('/git/blobs'):
                return {'sha': '2' * 40}
            if method == 'POST' and path.endswith('/git/trees'):
                return {'sha': '3' * 40}
            if method == 'POST' and path.endswith('/git/commits'):
                return {'sha': '4' * 40}
            if method == 'POST' and path.endswith('/git/refs'):
                return {}
            if method == 'POST' and path.endswith('/pulls'):
                return {'number': 42}
            raise AssertionError((method, path, data))

    plan = FixPlan(
        manifest=manifest,
        changes=(FileChange(SOURCE_PATH, SOURCE_AFTER), FileChange(TEST_PATH, TEST_CONTENT)),
        title='fix',
        issue_number=17,
        base_branch='develop',
        branch_base_sha=BRANCH_BASE_SHA,
    )
    store = PublicationStore()
    result = publish_fix_pull_request(
        Github(), plan=plan, bot_login='autofix[bot]', publication_store=store,
    )

    assert result.base_sha == DEVELOP_SHA
    assert result.base_branch == 'develop'
    tree_call = next(call for call in calls if call[1].endswith('/git/trees'))
    assert tree_call[2]['base_tree'] == '1' * 40
    assert {entry['path'] for entry in tree_call[2]['tree']} == {SOURCE_PATH, TEST_PATH}
    commit_call = next(call for call in calls if call[1].endswith('/git/commits'))
    assert commit_call[2]['parents'] == [BRANCH_BASE_SHA]
    ref_call = next(call for call in calls if call[1].endswith('/git/refs'))
    assert ref_call[2]['ref'] == f'refs/heads/{branch_name_for(IDENTITY_HASH, 17)}'
    pull_call = next(call for call in calls if call[1].endswith('/pulls'))
    assert pull_call[2]['base'] == 'develop'
    assert pull_call[2]['head'] == branch_name_for(IDENTITY_HASH, 17)
    assert pull_call[2]['draft'] is False
    assert 'manifest' not in pull_call[2]['body'].lower()
    assert store.events[0] == ('put', result.head_sha, 'develop')


def test_shared_publication_reuses_one_head_for_both_targets_and_rejects_mismatch():
    from base64 import b64encode

    class Github:
        class Missing(Exception):
            status = 404

        def __init__(self):
            self.branch_head = None
            self.commits = {}
            self.files = {}
            self.pulls = []
            self.commit_posts = 0
            self.ref_posts = 0

        def rest(self, method, path, data=None):
            if method == 'GET' and path.endswith(f'/git/commits/{BRANCH_BASE_SHA}'):
                return {'tree': {'sha': '1' * 40}}
            if method == 'GET' and path.endswith(f'/git/commits/{self.branch_head}'):
                return self.commits[self.branch_head]
            if method == 'GET' and '/git/ref/heads/' in path:
                if self.branch_head is None:
                    raise self.Missing()
                return {'object': {'sha': self.branch_head}}
            if method == 'POST' and path.endswith('/git/blobs'):
                raw = __import__('base64').b64decode(data['content'])
                return {'sha': hashlib.sha1(raw).hexdigest()}
            if method == 'POST' and path.endswith('/git/trees'):
                entries = sorted((entry['path'], entry['sha']) for entry in data['tree'])
                return {'sha': hashlib.sha1(repr(entries).encode()).hexdigest()}
            if method == 'POST' and path.endswith('/git/commits'):
                self.commit_posts += 1
                head = '4' * 40
                self.commits[head] = {
                    'parents': [{'sha': data['parents'][0]}],
                    'tree': {'sha': data['tree']},
                }
                return {'sha': head}
            if method == 'POST' and path.endswith('/git/refs'):
                self.ref_posts += 1
                self.branch_head = data['sha']
                return {}
            if method == 'GET' and path.endswith(f'/commits/{self.branch_head}'):
                return self.commits[self.branch_head]
            if method == 'GET' and '/contents/' in path:
                file_path = path.split('/contents/', 1)[1].split('?ref=', 1)[0]
                content = self.files[file_path]
                return {
                    'type': 'file', 'encoding': 'base64',
                    'content': b64encode(content.encode()).decode(),
                }
            if method == 'GET' and path.endswith('/pulls?head='):
                return self.pulls
            if method == 'GET' and '/pulls?head=' in path:
                return self.pulls
            if method == 'POST' and path.endswith('/pulls'):
                pull = {
                    'number': len(self.pulls) + 1,
                    'head': {'ref': data['head'], 'sha': self.branch_head,
                             'repo': {'full_name': 'BCSDLab/KOIN_ANDROID'}},
                    'base': {'ref': data['base'], 'repo': {'full_name': 'BCSDLab/KOIN_ANDROID'}},
                    'user': {'login': 'autofix[bot]'},
                    'state': 'open', 'merged': False, 'body': data['body'],
                }
                self.pulls.append(pull)
                return pull
            raise AssertionError((method, path, data))

    def make_plan(base_sha, base_branch, test_content=TEST_CONTENT):
        files = [
            {'path': SOURCE_PATH, 'kind': 'source',
             'beforeSha256': hashlib.sha256(SOURCE_BASE.encode()).hexdigest(),
             'afterSha256': hashlib.sha256(SOURCE_AFTER.encode()).hexdigest()},
            {'path': TEST_PATH, 'kind': 'test', 'beforeSha256': None,
             'afterSha256': hashlib.sha256(test_content.encode()).hexdigest()},
        ]
        manifest = candidate_manifest(
            issue_id=ALERT.issue_id, identity_hash=IDENTITY_HASH, issue_number=17,
            base_sha=base_sha, branch_base_sha=BRANCH_BASE_SHA, source_sha=RELEASE_SHA,
            source_path=SOURCE_PATH, files=files,
        )
        return FixPlan(
            manifest=manifest,
            changes=(FileChange(SOURCE_PATH, SOURCE_AFTER), FileChange(TEST_PATH, test_content)),
            title='fix', issue_number=17, base_branch=base_branch,
            branch_base_sha=BRANCH_BASE_SHA,
        )

    github = Github()
    github.files = {SOURCE_PATH: SOURCE_AFTER, TEST_PATH: TEST_CONTENT}
    store = PublicationStore()
    production = publish_fix_pull_request(
        github, plan=make_plan(BASE_SHA, 'production'),
        bot_login='autofix[bot]', publication_store=store,
    )
    develop = publish_fix_pull_request(
        github, plan=make_plan(DEVELOP_SHA, 'develop'),
        bot_login='autofix[bot]', publication_store=store,
    )
    replay = publish_fix_pull_request(
        github, plan=make_plan(BASE_SHA, 'production'),
        bot_login='autofix[bot]', publication_store=store,
    )

    assert production.head_sha == develop.head_sha == replay.head_sha == '4' * 40
    assert production.base_branch == 'production' and develop.base_branch == 'develop'
    assert production.manifest_digest != develop.manifest_digest
    assert github.commit_posts == 1
    assert github.ref_posts == 1
    assert [pull['head']['sha'] for pull in github.pulls] == ['4' * 40, '4' * 40]
    assert [pull['head']['ref'] for pull in github.pulls] == [
        branch_name_for(IDENTITY_HASH, 17), branch_name_for(IDENTITY_HASH, 17),
    ]
    assert [pull['base']['ref'] for pull in github.pulls] == ['production', 'develop']
    assert replay.reused
    mismatch = publish_fix_pull_request(
        github, plan=make_plan(DEVELOP_SHA, 'develop', TEST_CONTENT + '// changed\n'),
        bot_login='autofix[bot]', publication_store=store,
    )
    assert isinstance(mismatch, ManualReview)
    assert github.commit_posts == 1 and github.ref_posts == 1

def test_metadata_persistence_failure_blocks_branch_and_pull_request():
    manifest = candidate_manifest(
        issue_id=ALERT.issue_id, identity_hash=IDENTITY_HASH, issue_number=17,
        base_sha=DEVELOP_SHA, branch_base_sha=BRANCH_BASE_SHA,
        source_sha=RELEASE_SHA, source_path=SOURCE_PATH,
        files=[
            {'path': SOURCE_PATH, 'kind': 'source',
             'beforeSha256': hashlib.sha256(SOURCE_BASE.encode()).hexdigest(),
             'afterSha256': hashlib.sha256(SOURCE_AFTER.encode()).hexdigest()},
            {'path': TEST_PATH, 'kind': 'test', 'beforeSha256': None,
             'afterSha256': hashlib.sha256(TEST_CONTENT.encode()).hexdigest()},
        ],
    )
    calls = []

    class Github:
        class Missing(Exception):
            status = 404

        def rest(self, method, path, data=None):
            calls.append((method, path, data))
            if method == 'GET' and path.endswith(f'/git/commits/{BRANCH_BASE_SHA}'):
                return {'tree': {'sha': '1' * 40}}
            if method == 'GET' and '/git/ref/heads/' in path:
                raise self.Missing()
            if method == 'POST' and path.endswith('/git/blobs'):
                return {'sha': '2' * 40}
            if method == 'POST' and path.endswith('/git/trees'):
                return {'sha': '3' * 40}
            if method == 'POST' and path.endswith('/git/commits'):
                return {'sha': '4' * 40}
            raise AssertionError((method, path, data))

    plan = FixPlan(
        manifest=manifest,
        changes=(FileChange(SOURCE_PATH, SOURCE_AFTER), FileChange(TEST_PATH, TEST_CONTENT)),
        title='fix', issue_number=17, base_branch='develop',
        branch_base_sha=BRANCH_BASE_SHA,
    )
    result = publish_fix_pull_request(
        Github(), plan=plan, bot_login='autofix[bot]',
        publication_store=PublicationStore(fail=True),
    )

    assert isinstance(result, ManualReview)
    assert any(path.endswith('/git/commits') for _method, path, _data in calls)
    assert not any(path.endswith('/git/refs') or path.endswith('/pulls')
                   for _method, path, _data in calls)


def test_resume_refuses_missing_or_tampered_external_publication_record():
    class NoRequests:
        def rest(self, *_args, **_kwargs):
            raise AssertionError('an invalid external record must fail before GitHub lookups')

    class TamperedStore:
        def get_publication(self, _head_sha, _base_branch):
            raise ValueError('tampered publication record')

    for store in (PublicationStore(), TamperedStore()):
        result = resume_fix_pull_request(
            NoRequests(), head_sha='e' * 40, issue_id=ALERT.issue_id,
            identity_hash=IDENTITY_HASH, source_sha=RELEASE_SHA,
            source_path=SOURCE_PATH, branch_base_sha=BRANCH_BASE_SHA,
            title='fix', issue_number=1, base_branch='production',
            bot_login='autofix[bot]', publication_store=store,
        )
        assert isinstance(result, ManualReview)


def test_existing_fix_rejects_a_persisted_origin_mismatch(monkeypatch):
    resumed = []
    manifest = {
        'version': 3,
        'issueNumber': 1,
        'sourceSha': RELEASE_SHA,
        'sourcePath': SOURCE_PATH,
        'branchBaseSha': OTHER_RELEASE_SHA,
    }
    monkeypatch.setattr(fix_generation, 'find_target_pull_request', lambda *_a: None)
    monkeypatch.setattr(fix_generation, 'find_branch_head', lambda *_a: 'e' * 40)
    store = PublicationStore(record=manifest)
    monkeypatch.setattr(
        fix_generation, 'resume_fix_pull_request', lambda *_a, **_k: resumed.append(True),
    )

    result = fix_generation.existing_fix(
        object(), alert=ALERT, issue_number=1, base_branch='develop',
        bot_login='autofix[bot]', release_sha=RELEASE_SHA,
        branch_base_sha=BRANCH_BASE_SHA, publication_store=store,
    )

    assert isinstance(result, ManualReview)
    assert resumed == []
