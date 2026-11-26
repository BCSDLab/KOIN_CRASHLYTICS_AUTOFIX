import base64

import pytest

from crashlytics_automation.candidate import (
    branch_name_for, candidate_manifest, identity_hash_for, manifest_digest, sha256,
)
from crashlytics_automation.merge import attempt_merge
from crashlytics_automation.models import CrashAlert
from crashlytics_automation.repository import OWNER, REPO, REPOSITORY_PATH

BASE = 'a' * 40
BRANCH_BASE = 'd' * 40
HEAD = 'e' * 40
RELEASE = 'b' * 40
ISSUE = 17
ALERT = CrashAlert('crash-1', '1.2.3', 'event-1', '2026-01-01T00:00:00Z', 'Crash', 'detail')
SOURCE = 'domain/src/main/java/org/koin/Thing.java'
TEST = 'domain/src/test/java/org/koin/CrashlyticsRegressionPLACEHOLDERTest.kt'
BEFORE = b'package org.koin;\nclass Thing { fun value() = 1 }\n'
AFTER = b'package org.koin;\nclass Thing { fun value() = 2 }\n'
TEST_BYTES = b'package org.koin\nclass RegressionTest\n'


class Store:
    record = None

    def __init__(self, _github):
        pass

    def get_publication(self, head):
        if self.record == 'missing':
            return None
        if self.record == 'tampered':
            raise ValueError('record digest mismatch')
        assert head == HEAD
        return self.record


class Github:
    def __init__(self, files):
        self.files = files
        self.merged_sha = None
        self.pr = self._pr(12, 'production', HEAD, 'open', False)
        self.peer = self._pr(13, 'develop', 'f' * 40, 'open', False)

    @staticmethod
    def _pr(number, target, head, state, merged):
        identity = identity_hash_for(ALERT.issue_id, RELEASE)
        return {
            'number': number, 'state': state, 'merged': merged, 'draft': False,
            'mergeable': True, 'body': 'Closes #17', 'user': {'login': 'autofix[bot]'},
            'head': {'sha': head, 'ref': branch_name_for(identity, target, ISSUE),
                     'repo': {'full_name': f'{OWNER}/{REPO}'}},
            'base': {'sha': BASE, 'ref': target, 'repo': {'full_name': f'{OWNER}/{REPO}'}},
        }

    def rest(self, method, path, data=None):
        if path == f'{REPOSITORY_PATH}/pulls/12':
            return self.pr
        if path == f'{REPOSITORY_PATH}/pulls/13':
            return self.peer
        if path == f'{REPOSITORY_PATH}/git/ref/heads/production':
            return {'object': {'sha': BASE}}
        if path == f'{REPOSITORY_PATH}/commits/{HEAD}':
            return {'parents': [{'sha': BRANCH_BASE}]}
        if path == f'{REPOSITORY_PATH}/pulls/12/files?per_page=100&page=1':
            return [{'filename': name, 'status': 'modified' if name == SOURCE else 'added'}
                    for name in self.files]
        if path.startswith(f'{REPOSITORY_PATH}/contents/'):
            name, ref = path.split('/contents/', 1)[1].split('?ref=')
            content = self.files.get(name) if ref == HEAD else (BEFORE if name == SOURCE and ref == BRANCH_BASE else None)
            if content is None:
                raise NotFound()
            return {'type': 'file', 'encoding': 'base64',
                    'content': base64.b64encode(content).decode(), 'size': len(content)}
        if path == f'{REPOSITORY_PATH}/commits/{HEAD}/check-runs?filter=latest&per_page=100&page=1':
            return {'check_runs': [
                {'id': i, 'name': name, 'head_sha': HEAD, 'status': 'completed',
                 'conclusion': 'success', 'app': {'slug': 'github-actions'}}
                for i, name in enumerate(('Lint & Format Check', 'Code Coverage'), 1)
            ]}
        if path == f'{REPOSITORY_PATH}/commits/{HEAD}/status?per_page=100&page=1':
            return {'statuses': []}
        if method == 'PUT' and path == f'{REPOSITORY_PATH}/pulls/12/merge':
            self.merged_sha = data['sha']
            return {'merged': True}
        raise AssertionError((method, path))


class NotFound(Exception):
    status = 404


def setup(monkeypatch, *, extra=False):
    identity = identity_hash_for(ALERT.issue_id, RELEASE)
    test_path = TEST.replace('PLACEHOLDER', identity[:12])
    manifest = candidate_manifest(
        issue_id=ALERT.issue_id, issue_number=ISSUE, identity_hash=identity,
        base_sha=BASE, branch_base_sha=BRANCH_BASE, source_sha=RELEASE,
        source_path=SOURCE, files=[
            {'path': SOURCE, 'kind': 'source', 'beforeSha256': sha256(BEFORE), 'afterSha256': sha256(AFTER)},
            {'path': test_path, 'kind': 'test', 'beforeSha256': None, 'afterSha256': sha256(TEST_BYTES)},
        ],
    )
    Store.record = manifest
    files = {SOURCE: AFTER, test_path: TEST_BYTES}
    if extra:
        files['automation/extra.json'] = b'{}'
    github = Github(files)
    job = {
        'alert': ALERT.to_payload(), 'issueNumber': ISSUE, 'pullNumber': 12,
        'headSha': HEAD, 'baseSha': BASE, 'manifestDigest': manifest_digest(manifest),
        'baseBranch': 'production',
        'pullRequests': {'production': {'number': 12, 'headSha': HEAD},
                         'develop': {'number': 13, 'headSha': 'f' * 40}},
    }
    monkeypatch.setattr('crashlytics_automation.merge.InvestigationQueue', Store)
    return github, job, manifest


def test_source_and_test_only_pr_merges_exact_published_head(monkeypatch):
    github, job, _ = setup(monkeypatch)
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result == {'outcome': 'merged', 'complete': False}
    assert github.merged_sha == HEAD


def test_extra_automation_file_is_rejected(monkeypatch):
    github, job, _ = setup(monkeypatch, extra=True)
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'blocked'
    assert github.merged_sha is None


@pytest.mark.parametrize('record', ['missing', 'tampered'])
def test_missing_or_tampered_external_record_blocks(monkeypatch, record):
    github, job, _ = setup(monkeypatch)
    Store.record = record
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'blocked'
    assert github.merged_sha is None


def test_scheduled_digest_mismatch_blocks(monkeypatch):
    github, job, _ = setup(monkeypatch)
    job['manifestDigest'] = '0' * 64
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'blocked'
    assert github.merged_sha is None


def test_moved_head_blocks_before_publication_lookup(monkeypatch):
    github, job, _ = setup(monkeypatch)
    github.pr['head']['sha'] = '9' * 40
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'blocked'
    assert github.merged_sha is None
