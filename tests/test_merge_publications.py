import base64

import pytest

from crashlytics_automation.candidate import (
    branch_name_for, candidate_manifest, identity_hash_for, manifest_digest, sha256,
)
from crashlytics_automation.task_payloads import validate_merge_task
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
BEFORE = b'package org.koin;\nclass Thing { int value() { return 1; } }\n'
AFTER = b'package org.koin;\nclass Thing { int value() { return 2; } }\n'
PRESERVATION = 'domain/src/test/java/org/koin/CrashlyticsPreservationPLACEHOLDERTest.kt'


def _verification(test_path, preservation_path, source_after_sha, test_sha, preservation_sha):
    from crashlytics_automation.behavior import candidate_digest, source_digest

    source_files = [{
        'path': SOURCE, 'kind': 'source', 'beforeSha256': sha256(BEFORE),
        'afterSha256': source_after_sha,
    }]
    review = {
        'version': 1, 'approved': True, 'reason': 'Preserves established behavior.',
        'unrelatedChanges': [],
        'contracts': [{
            'sourcePath': SOURCE, 'sourceLine': 2, 'behavior': 'Existing value remains stable.',
            'testPath': preservation_path, 'testMethod': 'existingValueRemainsStable',
        }],
        'sourceDigest': source_digest(source_files),
    }

    def check(phase, purpose, path, result, exit_code, methods):
        return {
            'phase': phase, 'purpose': purpose, 'path': path, 'exit_code': exit_code,
            'timed_out': False, 'test_result': result,
            'evidence': {'source': 'junit-xml'}, 'methods': methods,
        }

    proof_files = [
        *source_files,
        {'path': test_path, 'kind': 'test', 'beforeSha256': None, 'afterSha256': test_sha},
        {'path': preservation_path, 'kind': 'test', 'beforeSha256': None, 'afterSha256': preservation_sha},
    ]
    return {
        'version': 2, 'passed': True, 'reason': 'Crash fixed and behavior preserved.',
        'candidateDigest': candidate_digest(proof_files), 'behaviorReview': review,
        'checks': [
            check('baseline', 'crash', test_path, 'failed', 1, []),
            check('candidate', 'crash', test_path, 'passed', 0, ['regressionReproduced']),
            check('baseline', 'preservation', preservation_path, 'passed', 0, ['existingValueRemainsStable']),
            check('candidate', 'preservation', preservation_path, 'passed', 0, ['existingValueRemainsStable']),
        ],
    }


class Store:
    record = None

    def __init__(self, _github):
        pass

    def get_publication(self, head, target):
        if self.record == 'missing':
            return None
        if self.record == 'tampered':
            raise ValueError('record digest mismatch')
        assert head == HEAD
        assert target in ('production', 'develop')
        return self.record


class Github:
    def __init__(self, files):
        self.files = files
        self.merged_sha = None
        self.workflow_runs = []
        self.run_targets = {}
        self.check_conclusions = {'production': 'success', 'develop': 'success'}
        self.check_app = 'github-actions'
        self.external_check_runs = []
        self.statuses = []
        self.pr = self._pr(12, 'production', HEAD, 'open', False)
        self.peer = self._pr(13, 'develop', HEAD, 'open', False)
        for workflow_run_id, (number, target) in enumerate(
            ((12, 'production'), (13, 'develop')), start=100,
        ):
            self.run_targets[workflow_run_id] = target
            self.workflow_runs.append({
                'id': workflow_run_id, 'workflow_id': 10, 'run_number': 1,
                'run_attempt': 1, 'head_sha': HEAD,
                'check_suite_id': workflow_run_id + 1000,
                'head_branch': branch_name_for(identity_hash_for(ALERT.issue_id, RELEASE), ISSUE),
                'repository': {'full_name': f'{OWNER}/{REPO}'},
                'head_repository': {'full_name': f'{OWNER}/{REPO}'},
                'pull_requests': [{
                    'number': number,
                    'head': {'ref': branch_name_for(identity_hash_for(ALERT.issue_id, RELEASE), ISSUE),
                             'sha': HEAD, 'repo': {'full_name': f'{OWNER}/{REPO}'}},
                    'base': {'ref': target, 'sha': BASE, 'repo': {'full_name': f'{OWNER}/{REPO}'}},
                }],
            })

    @property
    def check_conclusion(self):
        return self.check_conclusions['production']

    @check_conclusion.setter
    def check_conclusion(self, conclusion):
        self.check_conclusions = {'production': conclusion, 'develop': conclusion}


    def _jobs(self, run_id):
        conclusion = self.check_conclusions[self.run_targets[run_id]]
        return [
            {'name': name, 'run_id': run_id, 'status': 'completed',
             'conclusion': conclusion, 'check_run_url': f'https://api.github.com{REPOSITORY_PATH}/check-runs/{run_id * 10 + index}'}
            for index, name in enumerate(('Lint & Format Check', 'Code Coverage'), 1)
        ]

    def retry_workflow(self, target):
        for run in self.workflow_runs:
            if self.run_targets[run['id']] == target:
                run['run_attempt'] += 1

    @staticmethod
    def _pr(number, target, head, state, merged):
        identity = identity_hash_for(ALERT.issue_id, RELEASE)
        return {
            'number': number, 'state': state, 'merged': merged, 'draft': False,
            'mergeable': True, 'body': 'Closes #17', 'user': {'login': 'autofix[bot]'},
            'head': {'sha': head, 'ref': branch_name_for(identity, ISSUE),
                     'repo': {'full_name': f'{OWNER}/{REPO}'}},
            'base': {'sha': BASE, 'ref': target, 'repo': {'full_name': f'{OWNER}/{REPO}'}},
        }

    def rest(self, method, path, data=None):
        if path.startswith(f'{REPOSITORY_PATH}/pulls/') and path.count('/') == len(REPOSITORY_PATH.split('/')) + 1:
            number = int(path.rsplit('/', 1)[1])
            if number == self.pr['number']:
                return self.pr
            if number == self.peer['number']:
                return self.peer
        if path in (f'{REPOSITORY_PATH}/git/ref/heads/production',
                    f'{REPOSITORY_PATH}/git/ref/heads/develop'):
            return {'object': {'sha': BASE}}
        if path == f'{REPOSITORY_PATH}/commits/{HEAD}':
            return {'parents': [{'sha': BRANCH_BASE}]}
        if path.startswith(f'{REPOSITORY_PATH}/pulls/') and path.endswith('/files?per_page=100&page=1'):
            return [{'filename': name, 'status': 'modified' if name == SOURCE else 'added'}
                    for name in self.files]
        if path.startswith(f'{REPOSITORY_PATH}/contents/'):
            name, ref = path.split('/contents/', 1)[1].split('?ref=')
            content = self.files.get(name) if ref == HEAD else (BEFORE if name == SOURCE and ref == BRANCH_BASE else None)
            if content is None:
                raise NotFound()
            return {'type': 'file', 'encoding': 'base64',
                    'content': base64.b64encode(content).decode(), 'size': len(content)}
        if path == f'{REPOSITORY_PATH}/actions/runs?head_sha={HEAD}&per_page=100&page=1':
            return {'workflow_runs': self.workflow_runs}
        if path.startswith(f'{REPOSITORY_PATH}/actions/runs/') and path.endswith('/jobs?filter=latest&per_page=100&page=1'):
            run_id = int(path.split('/actions/runs/', 1)[1].split('/', 1)[0])
            return {'jobs': self._jobs(run_id)}
        if path.startswith(f'{REPOSITORY_PATH}/check-runs/'):
            check_id = int(path.rsplit('/', 1)[1])
            run_id, index = divmod(check_id, 10)
            name = ('Lint & Format Check', 'Code Coverage')[index - 1]
            return {
                'name': name, 'head_sha': HEAD, 'app': {'slug': self.check_app},
                'check_suite': {'id': run_id + 1000},
            }
        if path == f'{REPOSITORY_PATH}/commits/{HEAD}/check-runs?filter=all&per_page=100&page=1':
            return {'check_runs': self.external_check_runs}
        if path == f'{REPOSITORY_PATH}/commits/{HEAD}/status?per_page=100&page=1':
            return {'statuses': self.statuses}
        if method == 'PUT' and path == f"{REPOSITORY_PATH}/pulls/{self.pr['number']}/merge":
            self.merged_sha = data['sha']
            return {'merged': True}
        raise AssertionError((method, path))


class NotFound(Exception):
    status = 404


def setup(monkeypatch, *, extra=False):
    identity = identity_hash_for(ALERT.issue_id, RELEASE)
    test_path = TEST.replace('PLACEHOLDER', identity[:12])
    preservation_path = PRESERVATION.replace('PLACEHOLDER', identity[:12])
    test_class = test_path.rsplit('/', 1)[1].removesuffix('.kt')
    preservation_class = preservation_path.rsplit('/', 1)[1].removesuffix('.kt')
    test_bytes = (
        f'package org.koin\nclass {test_class} {{\n'
        '  @org.junit.Test fun regressionReproduced() {}\n}\n'
    ).encode()
    preservation_bytes = (
        f'package org.koin\nclass {preservation_class} {{\n'
        '  @org.junit.Test fun existingValueRemainsStable() {}\n}\n'
    ).encode()
    files = [
        {'path': SOURCE, 'kind': 'source', 'beforeSha256': sha256(BEFORE), 'afterSha256': sha256(AFTER)},
        {'path': test_path, 'kind': 'test', 'beforeSha256': None, 'afterSha256': sha256(test_bytes)},
        {'path': preservation_path, 'kind': 'test', 'beforeSha256': None,
         'afterSha256': sha256(preservation_bytes)},
    ]
    manifest = candidate_manifest(
        issue_id=ALERT.issue_id, issue_number=ISSUE, identity_hash=identity,
        base_sha=BASE, branch_base_sha=BRANCH_BASE, source_sha=RELEASE,
        source_path=SOURCE, files=files,
        verification=_verification(
            test_path, preservation_path, sha256(AFTER),
            sha256(test_bytes), sha256(preservation_bytes),
        ),
    )
    Store.record = manifest
    files = {SOURCE: AFTER, test_path: test_bytes, preservation_path: preservation_bytes}
    if extra:
        files['automation/extra.json'] = b'{}'
    github = Github(files)
    job = {
        'alert': ALERT.to_payload(), 'issueNumber': ISSUE, 'pullNumber': 12,
        'headSha': HEAD, 'baseSha': BASE, 'manifestDigest': manifest_digest(manifest),
        'baseBranch': 'production',
        'pullRequests': {'production': {'number': 12, 'headSha': HEAD},
                         'develop': {'number': 13, 'headSha': HEAD}},
    }
    monkeypatch.setattr('crashlytics_automation.merge.InvestigationQueue', Store)
    return github, job, manifest


def test_source_and_test_only_pr_merges_exact_published_head(monkeypatch):
    github, job, _ = setup(monkeypatch)
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result == {'outcome': 'merged', 'complete': False}
    assert github.merged_sha == HEAD


def test_same_head_peer_waits_for_production_then_develop_merges(monkeypatch):
    github, job, _ = setup(monkeypatch)
    job['baseBranch'] = 'develop'
    job['pullNumber'] = 13
    github.pr, github.peer = github.peer, github.pr

    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'pending'
    assert github.merged_sha is None

    github.peer['state'] = 'closed'
    github.peer['merged'] = True
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result == {'outcome': 'merged', 'complete': True}
    assert github.merged_sha == HEAD


def test_merge_task_requires_both_targets_to_pin_the_same_head(monkeypatch):
    _, job, _ = setup(monkeypatch)
    job['pullRequests']['develop']['headSha'] = 'f' * 40
    with pytest.raises(ValueError, match='Inconsistent hotfix pull requests'):
        validate_merge_task(job)


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

def test_legacy_cached_manifest_cannot_authorize_merge(monkeypatch):
    github, job, manifest = setup(monkeypatch)
    legacy = {key: value for key, value in manifest.items() if key != 'verification'}
    legacy['version'] = 3
    Store.record = legacy
    job['manifestDigest'] = manifest_digest(legacy)

    result = attempt_merge(github, job, bot_login='autofix[bot]')

    assert result['outcome'] == 'blocked'
    assert github.merged_sha is None



def _registered_investigation(job, status='merging'):
    return {
        'status': status,
        'verificationPolicy': 2,
        'branches': {
            branch: {
                'pullNumber': pull['number'],
                'headSha': pull['headSha'],
            }
            for branch, pull in job['pullRequests'].items()
        },
    }


def test_failed_target_ci_cannot_be_hidden_by_sibling_and_same_target_retry_merges(monkeypatch):
    from crashlytics_automation import service

    github, job, _ = setup(monkeypatch)
    github.check_conclusions['production'] = 'failure'
    investigation = _registered_investigation(job)

    class Queue:
        def __init__(self, _github):
            pass

        def get(self, _alert):
            return investigation

    monkeypatch.setattr(service, 'InvestigationQueue', Queue)
    monkeypatch.setattr(service, 'verify_crash_issue', lambda *_args: None)
    automation = service.CrashAutomation(github, {'botLogin': 'autofix[bot]'})

    with pytest.raises(RuntimeError, match='retry merge later'):
        automation.process_merge_task(job)
    assert github.merged_sha is None
    assert investigation['status'] == 'merging'

    github.check_conclusions['production'] = 'success'
    github.retry_workflow('production')
    result = automation.process_merge_task(job, retry_count=1)
    assert result == {'outcome': 'merged', 'complete': False}
    assert github.merged_sha == HEAD


@pytest.mark.parametrize('failed_target', [None, 'production', 'develop'])
def test_shared_head_associations_require_each_workflow_run_to_pass(monkeypatch, failed_target):
    github, job, _ = setup(monkeypatch)
    pulls = [run['pull_requests'][0] for run in github.workflow_runs]
    for run in github.workflow_runs:
        run['pull_requests'] = pulls
    if failed_target is not None:
        github.check_conclusions[failed_target] = 'failure'

    result = attempt_merge(github, job, bot_login='autofix[bot]')
    if failed_target is None:
        assert result == {'outcome': 'merged', 'complete': False}
        assert github.merged_sha == HEAD
    else:
        assert result['outcome'] == 'pending'
        assert github.merged_sha is None


@pytest.mark.parametrize('investigation', [None, 'manual', 'wrong-pulls'])
def test_merge_requires_registered_active_matching_investigation(monkeypatch, investigation):
    from crashlytics_automation import service

    github, job, _ = setup(monkeypatch)
    if investigation is None:
        stored = None
    elif investigation == 'manual':
        stored = _registered_investigation(job, 'manual')
    else:
        stored = _registered_investigation(job)
        stored['branches']['production']['headSha'] = '9' * 40

    class Queue:
        def __init__(self, _github):
            pass

        def get(self, _alert):
            return stored

    attempts = []
    monkeypatch.setattr(service, 'InvestigationQueue', Queue)
    monkeypatch.setattr(service, 'verify_crash_issue', lambda *_args: None)
    monkeypatch.setattr(service, 'attempt_merge', lambda *_args, **_kwargs: attempts.append(True))
    result = service.CrashAutomation(github, {'botLogin': 'autofix[bot]'}).process_merge_task(job)
    assert result == {'outcome': 'superseded', 'issueNumber': ISSUE}
    assert attempts == []
    assert github.merged_sha is None


@pytest.mark.parametrize('problem', ['publisher', 'head', 'target', 'old-branch'])
def test_ci_publisher_or_changed_head_or_target_or_branch_remains_blocked(monkeypatch, problem):
    github, job, _ = setup(monkeypatch)
    if problem == 'publisher':
        github.check_app = 'untrusted-app'
    elif problem == 'head':
        github.pr['head']['sha'] = '9' * 40
    elif problem == 'target':
        github.pr['base']['ref'] = 'develop'
    else:
        identity = identity_hash_for(ALERT.issue_id, RELEASE)
        github.pr['head']['ref'] = f'fix/{ISSUE}-crashlytics-production-{identity}'
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'blocked'
    assert github.merged_sha is None


def test_check_run_for_different_target_base_does_not_authorize_merge(monkeypatch):
    github, job, _ = setup(monkeypatch)
    github.workflow_runs[0]['pull_requests'][0]['base']['sha'] = 'c' * 40
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'pending'
    assert github.merged_sha is None


def test_applicable_external_failed_check_remains_pending(monkeypatch):
    github, job, _ = setup(monkeypatch)
    branch = github.pr['head']['ref']
    github.external_check_runs = [{
        'id': 900, 'name': 'SonarCloud Code Analysis', 'head_sha': HEAD,
        'status': 'completed', 'conclusion': 'failure',
        'app': {'slug': 'sonarcloud'},
        'pull_requests': [{
            'number': 12, 'head': {'ref': branch, 'sha': HEAD},
            'base': {'ref': 'production', 'sha': BASE},
        }],
    }]
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'pending'
    assert github.merged_sha is None


def test_sibling_only_external_failure_does_not_block_this_target(monkeypatch):
    github, job, _ = setup(monkeypatch)
    branch = github.peer['head']['ref']
    github.external_check_runs = [{
        'id': 901, 'name': 'CodeRabbit', 'head_sha': HEAD,
        'status': 'completed', 'conclusion': 'failure',
        'app': {'slug': 'coderabbitai'},
        'pull_requests': [{
            'number': 13, 'head': {'ref': branch, 'sha': HEAD},
            'base': {'ref': 'develop', 'sha': BASE},
        }],
    }]
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result == {'outcome': 'merged', 'complete': False}
    assert github.merged_sha == HEAD


def test_same_sha_actions_run_from_old_target_branch_cannot_authorize_new_pr(monkeypatch):
    github, job, _ = setup(monkeypatch)
    identity = identity_hash_for(ALERT.issue_id, RELEASE)
    github.workflow_runs[0]['head_branch'] = f'fix/{ISSUE}-crashlytics-production-{identity}'
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'pending'
    assert github.merged_sha is None


@pytest.mark.parametrize('failure', ['failure', 'cancelled', 'startup_failure', 'commit-status'])
def test_known_ci_failures_are_retryable_and_never_merge(monkeypatch, failure):
    github, job, _ = setup(monkeypatch)
    if failure == 'commit-status':
        github.statuses = [{'state': 'failure'}]
    else:
        github.check_conclusion = failure
    result = attempt_merge(github, job, bot_login='autofix[bot]')
    assert result['outcome'] == 'pending'
    assert github.merged_sha is None


def test_retry_does_not_authorize_a_changed_head(monkeypatch):
    from crashlytics_automation import service

    github, job, _ = setup(monkeypatch)
    github.check_conclusion = 'failure'
    investigation = _registered_investigation(job)

    class Queue:
        def __init__(self, _github):
            pass

        def get(self, _alert):
            return investigation

        def put(self, updated):
            investigation.update(updated)

    monkeypatch.setattr(service, 'InvestigationQueue', Queue)
    monkeypatch.setattr(service, 'verify_crash_issue', lambda *_args: None)
    monkeypatch.setattr(service, 'report_for_human', lambda *_args, **_kwargs: {'outcome': 'manual'})
    automation = service.CrashAutomation(github, {'botLogin': 'autofix[bot]'})

    with pytest.raises(RuntimeError, match='retry merge later'):
        automation.process_merge_task(job)
    github.pr['head']['sha'] = '9' * 40
    result = automation.process_merge_task(job, retry_count=1)
    assert result == {'outcome': 'manual'}
    assert github.merged_sha is None
    assert investigation['status'] == 'manual'


def test_failed_ci_stops_at_existing_retry_deadline_without_merging(monkeypatch):
    from crashlytics_automation import service

    github, job, _ = setup(monkeypatch)
    github.check_conclusion = 'failure'
    investigation = _registered_investigation(job)

    class Queue:
        def __init__(self, _github):
            pass

        def get(self, _alert):
            return investigation

        def put(self, updated):
            investigation.update(updated)

    monkeypatch.setattr(service, 'InvestigationQueue', Queue)
    monkeypatch.setattr(service, 'verify_crash_issue', lambda *_args: None)
    monkeypatch.setattr(service, 'report_for_human', lambda *_args, **_kwargs: {'outcome': 'manual'})
    automation = service.CrashAutomation(github, {'botLogin': 'autofix[bot]'})

    result = automation.process_merge_task(job, retry_count=service.MAX_MERGE_RETRIES)

    assert result == {'outcome': 'manual'}
    assert investigation['status'] == 'manual'
    assert github.merged_sha is None
