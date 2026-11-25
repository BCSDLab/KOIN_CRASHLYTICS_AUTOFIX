import base64
import copy
import hashlib
import json

import pytest
from requests import Timeout

from crashlytics_automation import worker
from crashlytics_automation.candidate import identity_hash_for, regression_test_name
from crashlytics_automation.investigation_jobs import new_job
from crashlytics_automation.models import CrashAlert, PublishedFix, SourceLocation

ALERT = CrashAlert('issue-1', '1.2.3', 'event-1', '2026-01-01T00:00:00Z', 'Crash', 'Details')
EVIDENCE = {'status': 'ready', 'displayVersion': '1.2.3', 'buildVersion': '42', 'breadcrumbs': []}
SOURCE_PATH = 'domain/src/main/kotlin/org/koin/Thing.kt'
RELEASE_SHA = 'a' * 40
BASE_SHA = 'b' * 40


class Queue:
    def __init__(self):
        self.latest = None
        self.history = []

    def get(self, _alert):
        return copy.deepcopy(self.latest)

    def put(self, job):
        self.latest = copy.deepcopy(job)
        self.history.append(copy.deepcopy(job))


class Github:
    def rest(self, method, path, *_args, **_kwargs):
        if method == 'GET' and path.endswith('/issues/17'):
            return {'state': 'open'}
        if method == 'GET' and path == '/repos/BCSDLab/KOIN_ANDROID':
            return {'private': True}
        raise AssertionError((method, path))


def _fix(branch, number):
    head = 'c' * 40 if branch == 'production' else 'd' * 40
    return PublishedFix(number, head, BASE_SHA, 'e' * 64, branch, reused=True)


def _source():
    return SourceLocation(SOURCE_PATH, 2, RELEASE_SHA, 'f' * 40, 'developer').to_payload()


def _base_job(status='queued'):
    job = new_job(ALERT, EVIDENCE, 17)
    job['status'] = status
    return job


def _patch_queue(monkeypatch, queue):
    monkeypatch.setattr('crashlytics_automation.investigation_jobs.InvestigationQueue',
                        lambda _github: queue)


def test_enqueue_task_uses_runtime_oidc_data_envelope_and_stable_id():
    class Response:
        status_code = 409

    class Session:
        def __init__(self):
            self.calls = []

        def post(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return Response()

    session = Session()
    config = {
        'projectId': 'valid-project1',
        'serviceAccount': 'runtime-worker@valid-project1.iam.gserviceaccount.com',
    }
    data = {'alert': ALERT.to_payload()}
    worker.enqueue_task(config, 'generateCrashlyticsFix', 'event-1', data, session=session)
    worker.enqueue_task(config, 'generateCrashlyticsFix', 'event-1', data, session=session)

    url, request_options = session.calls[0]
    task = request_options['json']['task']
    body = json.loads(base64.b64decode(task['httpRequest']['body']))
    expected_id = hashlib.sha256(b'generateCrashlyticsFix/event-1').hexdigest()
    audience = 'https://us-central1-valid-project1.cloudfunctions.net/generateCrashlyticsFix'
    assert url.endswith('/generateCrashlyticsFix/tasks')
    assert task['name'].endswith(f'/tasks/{expected_id}')
    assert session.calls[1][1]['json']['task']['name'] == task['name']
    assert task['httpRequest']['oidcToken'] == {
        'serviceAccountEmail': config['serviceAccount'], 'audience': audience,
    }
    assert body == {'data': data}
    assert request_options['timeout'] == 30
    assert request_options['allow_redirects'] is False


@pytest.mark.parametrize('attempts', [0, 3])
def test_resumed_production_publication_is_retained_and_develop_stays_pending(monkeypatch, attempts):
    from crashlytics_automation import fix_generation, issues

    queue = Queue()
    _patch_queue(monkeypatch, queue)
    job = _base_job()
    job['attempts']['production'] = attempts
    job['sources'] = {'production': _source()}
    job['branchBases'] = {'production': BASE_SHA}
    resumed = _fix('production', 21)
    calls = {'existing': [], 'model': 0}
    monkeypatch.setattr(issues, 'verify_crash_issue', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'record_fix_progress', lambda *_a, **_k: None)
    monkeypatch.setattr(fix_generation, 'existing_fix',
                        lambda *_a, base_branch, **_k: calls['existing'].append(base_branch) or resumed)
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal',
                        lambda *_a, **_k: calls.__setitem__('model', calls['model'] + 1))

    result = worker.run_job(Github(), {'botLogin': 'autofix[bot]'}, job)

    assert result == {'outcome': 'queued', 'issueNumber': 17, 'baseBranch': 'production', 'pullNumber': 21}
    assert queue.latest['status'] == 'queued'
    assert queue.latest['branches']['production'] == resumed.to_payload()
    assert 'develop' not in queue.latest['branches']
    assert calls == {'existing': ['production'], 'model': 0}


@pytest.mark.parametrize('failure', [RuntimeError('task API failure'), Timeout('task API timeout')])
def test_interrupted_merge_delivery_retries_durable_outbox_with_same_task_identities(monkeypatch, failure):
    from crashlytics_automation import fix_generation, issues

    queue = Queue()
    _patch_queue(monkeypatch, queue)
    job = _base_job('delivering')
    fixes = {'production': _fix('production', 31), 'develop': _fix('develop', 32)}
    job['branches'] = {branch: fix.to_payload() for branch, fix in fixes.items()}
    job['sources'] = {branch: _source() for branch in fixes}
    job['branchBases'] = {branch: BASE_SHA for branch in fixes}
    calls = []
    fail_once = {'value': True}
    monkeypatch.setattr(issues, 'verify_crash_issue', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'record_fix_progress', lambda *_a, **_k: None)
    monkeypatch.setattr(fix_generation, 'existing_fix',
                        lambda *_a, base_branch, **_k: fixes[base_branch])
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal',
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('unexpected model call')))

    def enqueue(_config, function, identity, _data):
        assert function == 'mergeCrashlyticsFix'
        calls.append(identity)
        if len(calls) == 2 and fail_once['value']:
            fail_once['value'] = False
            raise failure

    monkeypatch.setattr(worker, 'enqueue_task', enqueue)
    worker.run_job(Github(), {'botLogin': 'autofix[bot]'}, job)
    durable_after_failure = copy.deepcopy(queue.latest)
    second = worker.run_job(Github(), {'botLogin': 'autofix[bot]'}, copy.deepcopy(durable_after_failure))

    expected = [f'{fixes[branch].pull_number}/{fixes[branch].head_sha}'
                for branch in ('production', 'develop')]
    assert durable_after_failure['status'] == 'delivering'
    assert durable_after_failure['branches'] == job['branches']
    assert calls == expected + expected
    assert second == {'outcome': 'merging', 'issueNumber': 17}
    assert queue.latest['status'] == 'merging'


@pytest.mark.parametrize('target', ['production', 'develop'])
def test_failed_trusted_verification_reports_analysis_without_publishing(monkeypatch, target):
    from crashlytics_automation import issues

    identity = identity_hash_for(ALERT.issue_id, RELEASE_SHA)
    test_path = f'domain/src/test/kotlin/org/koin/{regression_test_name(identity)}'
    source_before = 'package org.koin\nclass Thing { fun value() = 1 }\n'
    decision = {
        'decision': 'fix',
        'analysis': 'Observed: repeated calls allocate a temporary list.',
        'reason': 'Confirmed by code inspection.',
        'sourcePath': SOURCE_PATH,
        'sourceLine': 2,
        'files': [
            {'path': SOURCE_PATH, 'content': 'package org.koin\nclass Thing { fun value() = 2 }\n'},
            {'path': test_path, 'content': (
                'package org.koin\nimport org.junit.Test\nimport org.junit.Assert.assertTrue\n'
                + f'class {regression_test_name(identity)[:-3]} {{\n'
                + '    @Test fun valueIsPositive() { assertTrue(Thing().value() > 0) }\n}\n'
            )},
        ],
    }

    class CheckedOutGithub(Github):
        def checkout(self, sha, destination):
            destination.mkdir(parents=True, exist_ok=True)
            if sha == BASE_SHA:
                source_file = destination / SOURCE_PATH
                source_file.parent.mkdir(parents=True, exist_ok=True)
                source_file.write_text(source_before, encoding='utf-8')

    class FailedVerificationSandbox:
        def __init__(self, **kwargs):
            self.artifact_directory = kwargs['target'].parent / 'artifacts'

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, **_kwargs):
            raise AssertionError('provider output is already stubbed')

        def verify_candidate(self, **_kwargs):
            return {'passed': False, 'reason': 'Regression test passed before the fix.'}

    queue = Queue()
    _patch_queue(monkeypatch, queue)
    reports = []
    publications = []
    monkeypatch.setattr(issues, 'verify_crash_issue', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'record_fix_progress', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'report_for_human',
                        lambda _g, context, reason, _c: reports.append((context, reason)) or {'outcome': 'manual'})
    monkeypatch.setattr('crashlytics_automation.fix_generation.existing_fix', lambda *_a, **_k: None)
    monkeypatch.setattr('crashlytics_automation.fix_generation.publish_investigated_fix',
                        lambda *_a, **_k: publications.append(True))
    monkeypatch.setattr('crashlytics_automation.release_source.resolve_release_commit',
                        lambda *_a, **_k: RELEASE_SHA)
    monkeypatch.setattr('crashlytics_automation.pull_requests.branch_head_sha',
                        lambda _g, branch: BASE_SHA if branch == 'production' else '9' * 40)
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal',
                        lambda **_kwargs: decision)
    monkeypatch.setattr('crashlytics_automation.sandbox.InvestigationSandbox', FailedVerificationSandbox)

    monkeypatch.setenv('CRASHLYTICS_OPENAI_API_KEY', 'test-only')
    job = _base_job()
    if target == 'develop':
        job['branches']['production'] = _fix('production', 21).to_payload()
        job['sources'] = {'production': _source()}
        job['branchBases'] = {'production': BASE_SHA}
    result = worker.run_job(CheckedOutGithub(), {'botLogin': 'autofix[bot]'}, job)

    assert result == {'outcome': 'manual'}
    assert queue.latest['status'] == 'manual'
    assert queue.latest['analyses'][target]['analysis'] == decision['analysis']
    assert queue.latest['analyses'][target]['verification'] == {
        'passed': False, 'reason': 'Regression test passed before the fix.',
    }
    assert reports and reports[0][1] == 'Regression test passed before the fix.'
    assert reports[0][0].evidence['investigation']['analyses'][target]['analysis'] == decision['analysis']
    assert publications == []


def test_interrupted_provider_failure_keeps_incremental_trace_and_retries_only_pending_report(monkeypatch, tmp_path):
    from crashlytics_automation import issues
    from crashlytics_automation.investigation_jobs import JobConflict

    class ConflictingReportQueue(Queue):
        conflict_on_clear = True

        def put(self, job):
            if self.conflict_on_clear and job.get('status') == 'manual' and not job.get('reportPending'):
                self.conflict_on_clear = False
                raise JobConflict('another writer updated report bookkeeping')
            super().put(job)

    class CheckedOutGithub(Github):
        def checkout(self, _sha, destination):
            destination.mkdir(parents=True, exist_ok=True)

    class RecordingSandbox:
        def __init__(self, **_kwargs):
            self.artifact_directory = tmp_path / 'artifacts'
            self.artifact_directory.mkdir(exist_ok=True)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, *, command, timeout_seconds):
            assert command == 'printf trace'
            assert timeout_seconds > 0
            return {'exit_code': 0, 'stdout': 'callback output test-only sentinel-private-key', 'stderr': '', 'timed_out': False}

    queue = ConflictingReportQueue()
    _patch_queue(monkeypatch, queue)
    reports = []
    model_calls = []
    monkeypatch.setattr(issues, 'verify_crash_issue', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'record_fix_progress', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'report_for_human',
                        lambda _g, _context, reason, _c: reports.append(reason) or {'outcome': 'manual'})
    monkeypatch.setattr('crashlytics_automation.fix_generation.existing_fix', lambda *_a, **_k: None)
    monkeypatch.setattr('crashlytics_automation.release_source.resolve_release_commit',
                        lambda *_a, **_k: RELEASE_SHA)
    monkeypatch.setattr('crashlytics_automation.pull_requests.branch_head_sha',
                        lambda *_a, **_k: BASE_SHA)

    def fail_after_execution(**kwargs):
        model_calls.append(True)
        kwargs['execute'](command='printf trace', timeout_seconds=30)
        raise RuntimeError('Investigation input budget exceeded')

    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal', fail_after_execution)
    monkeypatch.setattr('crashlytics_automation.sandbox.InvestigationSandbox', RecordingSandbox)
    monkeypatch.setenv('CRASHLYTICS_OPENAI_API_KEY', 'test-only')
    monkeypatch.setenv('CRASHLYTICS_GITHUB_APP_PRIVATE_KEY', 'sentinel-private-key')
    job = _base_job()
    job['analyses']['production'] = {'analysis': 'previous attempt', 'tools': []}

    first = worker.run_job(CheckedOutGithub(), {'botLogin': 'autofix[bot]'}, job)
    pending = copy.deepcopy(queue.latest)
    trace = (tmp_path / 'artifacts' / 'investigation-tool-results.jsonl').read_text(encoding='utf-8')
    record = json.loads(trace.splitlines()[0])

    assert first == {'outcome': 'superseded', 'issueNumber': 17}
    assert record['stdout'] == 'callback output [REDACTED] [REDACTED]'
    assert 'test-only' not in trace and 'sentinel-private-key' not in trace
    assert pending['status'] == 'manual' and pending['reportPending'] is True
    assert pending['reason'] == 'Investigation input budget exceeded'
    assert pending['analyses']['production']['analysis'].startswith('PARTIAL')
    assert pending['analyses']['production']['previous']['analysis'] == 'previous attempt'
    assert pending['analyses']['production']['tools'][0]['outputSummary'] == 'callback output [REDACTED] [REDACTED]\n'
    attempts = copy.deepcopy(pending['attempts'])

    worker.run_job(CheckedOutGithub(), {'botLogin': 'autofix[bot]'}, pending)

    assert model_calls == [True]
    assert queue.latest['attempts'] == attempts
    assert not queue.latest.get('reportPending')
    assert len(reports) == 2 and reports[0] == reports[1] == 'Investigation input budget exceeded'


def test_report_failure_preserves_accepted_merge_tasks_and_retries_only_the_report(monkeypatch):
    from crashlytics_automation import fix_generation, issues
    from crashlytics_automation.github import GitHubError

    queue = Queue()
    _patch_queue(monkeypatch, queue)
    job = _base_job('delivering')
    fixes = {'production': _fix('production', 31), 'develop': _fix('develop', 32)}
    job['branches'] = {branch: fix.to_payload() for branch, fix in fixes.items()}
    job['sources'] = {branch: _source() for branch in fixes}
    job['branchBases'] = {branch: BASE_SHA for branch in fixes}
    deliveries = []
    reports = []
    monkeypatch.setattr(issues, 'verify_crash_issue', lambda *_a, **_k: None)
    monkeypatch.setattr(fix_generation, 'existing_fix',
                        lambda *_a, base_branch, **_k: fixes[base_branch])
    monkeypatch.setattr(worker, 'enqueue_task', lambda _c, _f, identity, _d: deliveries.append(identity))
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal',
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('unexpected model call')))

    def report(_github, context, _config):
        reports.append(context)
        if len(reports) == 1:
            raise GitHubError(502)

    monkeypatch.setattr(issues, 'record_fix_progress', report)
    first = worker.run_job(Github(), {'botLogin': 'autofix[bot]'}, job)
    pending = copy.deepcopy(queue.latest)
    second = worker.run_job(Github(), {'botLogin': 'autofix[bot]'}, copy.deepcopy(pending))

    assert first == second == {'outcome': 'merging', 'issueNumber': 17}
    assert pending['status'] == 'merging' and pending['reportPending'] is True
    assert queue.latest['status'] == 'merging' and not queue.latest.get('reportPending')
    assert len(deliveries) == 2
    assert len(reports) == 2 and reports[-1].pull_numbers == (31, 32)


def test_worker_configuration_builds_the_requested_android_crash_deep_link(monkeypatch):
    from crashlytics_automation import issues, repository

    monkeypatch.setenv('CRASHLYTICS_ENV', '')
    for key, value in {
        'CRASHLYTICS_PROJECT_ID': 'test-project',
        'CRASHLYTICS_APP_ID': 'test-app',
        'AUTOMATION_SERVICE_ACCOUNT': 'runtime@test-project.iam.gserviceaccount.com',
        'CRASHLYTICS_AUTOFIX_BOT_LOGIN': 'autofix[bot]',
        'CRASHLYTICS_GITHUB_APP_ID': '123',
        'CRASHLYTICS_GITHUB_INSTALLATION_ID': '456',
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(repository, 'ANDROID_APPLICATION_ID', 'example.worker.app')

    url = issues._crash_url(ALERT, worker.runtime_config())

    assert url == (
        'https://console.firebase.google.com/project/test-project/'
        'crashlytics/app/android:example.worker.app/issues/issue-1'
    )


class ExistingIssueGithub(Github):
    def rest(self, method, path, *_args, **_kwargs):
        result = super().rest(method, path, *_args, **_kwargs)
        if method == 'GET' and path.endswith('/issues/17'):
            from crashlytics_automation.github import issue_marker
            alert = ALERT.to_payload()
            result['body'] = (
                issue_marker(ALERT.issue_id)
                + f"\n* 발생 버전: {alert['appVersion']}\n* 알림 시각: {alert['time']}\n"
                + f"\n### 어떤 오류인가요?\n* {alert['title']}\n* {alert['subtitle']}\n"
            )
        return result


@pytest.mark.parametrize('attempts', [1, 3])
def test_manual_resume_reuses_captured_evidence_and_preserves_the_model_budget(monkeypatch, attempts):
    from crashlytics_automation import issues

    queue = Queue()
    original = _base_job('manual')
    original['reason'] = 'Previous investigation stopped without a runtime experiment'
    original['attempts']['production'] = attempts
    original['analyses']['production'] = {'analysis': 'Previous inspection', 'tools': []}
    queue.latest = copy.deepcopy(original)
    _patch_queue(monkeypatch, queue)
    monkeypatch.setattr(worker, 'enqueue_task',
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('unexpected capture')))
    reports = []
    monkeypatch.setattr(issues, 'record_fix_progress', lambda _g, context, _c: reports.append(context))

    resumed = worker.prepare_existing_issue(
        ExistingIssueGithub(), {'botLogin': 'autofix[bot]'}, 17,
        resume_manual=True, notes='Zero-width hypothesis; token=private-value',
    )

    assert resumed['status'] == queue.latest['status'] == 'queued'
    assert resumed['alert'] == original['alert']
    assert resumed['evidence'] == original['evidence']
    assert resumed['attempts']['production'] == attempts
    assert resumed['analyses'] == original['analyses']
    assert 'private-value' not in resumed['operatorNotes']
    assert 'reason' not in resumed and 'reportPending' not in resumed
    assert reports[-1].evidence['investigation']['status'] == 'queued'


def test_manual_resume_without_saved_evidence_cannot_request_another_capture(monkeypatch):
    queue = Queue()
    _patch_queue(monkeypatch, queue)
    monkeypatch.setattr(worker, 'enqueue_task',
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('unexpected capture')))

    with pytest.raises(ValueError):
        worker.prepare_existing_issue(ExistingIssueGithub(), {}, 17, resume_manual=True)

    assert queue.history == []


@pytest.mark.parametrize('status', ['running', 'merging', 'complete'])
def test_manual_resume_cannot_reopen_active_or_completed_work(monkeypatch, status):
    queue = Queue()
    original = _base_job(status)
    queue.latest = copy.deepcopy(original)
    _patch_queue(monkeypatch, queue)

    with pytest.raises(ValueError):
        worker.prepare_existing_issue(ExistingIssueGithub(), {}, 17, resume_manual=True)

    assert queue.latest == original and queue.history == []
