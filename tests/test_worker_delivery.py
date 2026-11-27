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
        self.proposals = {}

    def get(self, _alert):
        return copy.deepcopy(self.latest)

    def put(self, job):
        self.latest = copy.deepcopy(job)
        self.history.append(copy.deepcopy(job))

    def get_proposal(self, _job, target):
        return copy.deepcopy(self.proposals.get(target))

    def save_proposal(self, job, target, decision, *, release_sha, branch_base_sha, base_sha):
        envelope = {
            'version': 2,
            'identity': {'jobId': job['id'], 'target': target, 'releaseSha': release_sha,
                         'branchBaseSha': branch_base_sha, 'baseSha': base_sha},
            'proposal': {key: decision[key] for key in (
                'decision', 'analysis', 'reason', 'sourcePath', 'sourceLine', 'files',
                'behaviorReview',
            ) if key in decision},
        }
        self.proposals[target] = copy.deepcopy(envelope)
        job.setdefault('proposals', {})[target] = '1' * 40
        self.put(job)
        return envelope

class Github:
    def rest(self, method, path, *_args, **_kwargs):
        if method == 'GET' and path.endswith('/issues/17'):
            return {'state': 'open'}
        if method == 'GET' and path == '/repos/BCSDLab/KOIN_ANDROID':
            return {'private': True}
        if method == 'GET' and path in (
            '/repos/BCSDLab/KOIN_ANDROID/git/ref/heads/production',
            '/repos/BCSDLab/KOIN_ANDROID/git/ref/heads/develop',
        ):
            return {'object': {'sha': BASE_SHA}}
        raise AssertionError((method, path))


def _fix(branch, number):
    head = 'c' * 40
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
    preservation_path = (
        f'domain/src/test/kotlin/org/koin/CrashlyticsPreservation{identity[:12]}Test.kt'
    )
    source_before = (
        'package org.koin\nclass FixedTicker { var ticks = 0\n'
        'fun reset() { ticks = 0 }\nfun onSwipe() { reset() }\n}\n'
    )
    decision = {
        'decision': 'fix',
        'analysis': 'The crash is fixed, but swipe reset behavior must remain unchanged.',
        'reason': 'The crash path is corrected.',
        'sourcePath': SOURCE_PATH,
        'sourceLine': 2,
        'files': [
            {'path': SOURCE_PATH, 'content': (
                'package org.koin\nclass FixedTicker { var ticks = 0\n'
                'fun reset() { ticks = 0 }\nfun onSwipe() { /* no reset */ }\n}\n'
            )},
            {'path': test_path, 'content': (
                'package org.koin\nimport org.junit.Test\nimport org.junit.Assert.assertEquals\n'
                + f'class {regression_test_name(identity)[:-3]} {{\n'
                + '    @Test fun crashIsPrevented() { assertEquals(0, FixedTicker().ticks) }\n}\n'
            )},
            {'path': preservation_path, 'content': (
                'package org.koin\nimport org.junit.Test\nimport org.junit.Assert.assertEquals\n'
                + f'class CrashlyticsPreservation{identity[:12]}Test {{\n'
                + '    @Test fun swipeResetsTicker() { val ticker = FixedTicker(); ticker.ticks = 3; '
                + 'ticker.onSwipe(); assertEquals(0, ticker.ticks) }\n}\n'
            )},
        ],
    }
    from crashlytics_automation.behavior import source_digest
    changed_source = decision['files'][0]['content']
    review_files = [{
        'path': SOURCE_PATH, 'kind': 'source',
        'beforeSha256': hashlib.sha256(source_before.encode()).hexdigest(),
        'afterSha256': hashlib.sha256(changed_source.encode()).hexdigest(),
    }]
    decision['behaviorReview'] = {
        'version': 1, 'approved': True, 'reason': 'Swipe reset is protected by a preservation test.',
        'unrelatedChanges': [],
        'contracts': [{
            'sourcePath': SOURCE_PATH, 'sourceLine': 2,
            'behavior': 'Swiping resets the ticker.',
            'testPath': preservation_path, 'testMethod': 'swipeResetsTicker',
        }],
        'sourceDigest': source_digest(review_files),
    }



    class CheckedOutGithub(Github):
        def checkout(self, sha, destination):
            destination.mkdir(parents=True, exist_ok=True)
            if sha == BASE_SHA:
                source_file = destination / SOURCE_PATH
                source_file.parent.mkdir(parents=True, exist_ok=True)
                source_file.write_text(source_before, encoding='utf-8')

    verify_calls = []

    class FailedVerificationSandbox:
        def __init__(self, **kwargs):
            self.artifact_directory = kwargs['target'].parent / 'artifacts'

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, **_kwargs):
            raise AssertionError('provider output is already stubbed')

        def verify_candidate(self, *, files, behavior_review, **_kwargs):
            from crashlytics_automation.behavior import candidate_digest
            verify_calls.append(True)
            assert target in queue.proposals
            assert behavior_review == decision['behaviorReview']
            return {
                'version': 2, 'passed': False, 'retryable': False,
                'reason': 'Candidate preservation failed: swipe reset behavior changed.',
                'behaviorReview': behavior_review,
                'candidateDigest': candidate_digest(files),
                'checks': [
                    {'phase': 'baseline', 'purpose': 'crash', 'path': test_path, 'exit_code': 1,
                     'timed_out': False, 'test_result': 'failed',
                     'evidence': {'source': 'junit-xml'}, 'methods': []},
                    {'phase': 'candidate', 'purpose': 'crash', 'path': test_path, 'exit_code': 0,
                     'timed_out': False, 'test_result': 'passed',
                     'evidence': {'source': 'junit-xml'}, 'methods': ['crashIsPrevented']},
                    {'phase': 'baseline', 'purpose': 'preservation', 'path': preservation_path,
                     'exit_code': 0, 'timed_out': False, 'test_result': 'passed',
                     'evidence': {'source': 'junit-xml'}, 'methods': ['swipeResetsTicker']},
                    {'phase': 'candidate', 'purpose': 'preservation', 'path': preservation_path,
                     'exit_code': 1, 'timed_out': False, 'test_result': 'failed',
                     'evidence': {'source': 'junit-xml'}, 'methods': []},
                ],
            }
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

    assert result == {
        'outcome': 'queued', 'issueNumber': 17, 'baseBranch': target, 'behaviorRepair': True,
    }
    assert queue.latest['status'] == 'queued'
    assert queue.latest['analyses'][target]['analysis'] == decision['analysis']
    assert queue.latest['analyses'][target]['verification']['passed'] is False
    assert 'Candidate preservation failed' in queue.latest['analyses'][target]['verification']['reason']
    assert reports == []
    assert publications == []
    assert target not in queue.latest.get('proposals', {})
    assert queue.latest['preservation']['contracts'] == decision['behaviorReview']['contracts']
    assert queue.latest['preservation']['files'][0]['path'] == preservation_path
    assert len(verify_calls) == 1



def test_held_manual_job_with_both_publications_never_delivers(monkeypatch):
    from crashlytics_automation import issues

    queue = Queue()
    _patch_queue(monkeypatch, queue)
    job = _base_job('manual')
    job['reason'] = 'Held for human review'
    job['branches'] = {
        branch: _fix(branch, number).to_payload()
        for branch, number in (('production', 1793), ('develop', 1794))
    }
    job['sources'] = {branch: _source() for branch in job['branches']}
    job['branchBases'] = {branch: BASE_SHA for branch in job['branches']}
    job['reportPending'] = False
    forbidden = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError('held job was reopened'))
    monkeypatch.setattr(issues, 'verify_crash_issue', forbidden)
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal', forbidden)
    monkeypatch.setattr('crashlytics_automation.fix_generation.publish_investigated_fix', forbidden)
    monkeypatch.setattr(worker, 'enqueue_task', forbidden)
    queue.latest = copy.deepcopy(job)

    result = worker.run_job(Github(), {'botLogin': 'autofix[bot]'}, copy.deepcopy(job))

    assert result == {'outcome': 'manual', 'issueNumber': 17}
    assert queue.latest == job

def test_published_pre_policy_job_is_held_without_any_delivery_or_write(monkeypatch):
    from crashlytics_automation import issues

    queue = Queue()
    _patch_queue(monkeypatch, queue)
    job = _base_job()
    job.pop('verificationPolicy', None)
    job['branches'] = {'production': _fix('production', 1789).to_payload()}
    job['sources'] = {'production': _source()}
    job['branchBases'] = {'production': BASE_SHA}
    queue.latest = copy.deepcopy(job)
    writes = []
    forbidden = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError('pre-policy published job must remain write-free')
    )
    monkeypatch.setattr(queue, 'put', forbidden)
    monkeypatch.setattr(issues, 'verify_crash_issue', forbidden)
    monkeypatch.setattr(issues, 'record_fix_progress', forbidden)
    monkeypatch.setattr(issues, 'report_for_human', forbidden)
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal', forbidden)
    monkeypatch.setattr('crashlytics_automation.fix_generation.publish_investigated_fix', forbidden)
    monkeypatch.setattr('crashlytics_automation.fix_generation.existing_fix', forbidden)
    monkeypatch.setattr(worker, 'enqueue_task', lambda *_args, **_kwargs: writes.append('enqueue'))

    class NoGithubWrites:
        def rest(self, method, path, *_args, **_kwargs):
            writes.append((method, path))
            raise AssertionError('pre-policy job must not read or mutate GitHub')

    result = worker.run_job(NoGithubWrites(), {'botLogin': 'autofix[bot]'}, copy.deepcopy(job))

    assert result == {'outcome': 'held-existing', 'issueNumber': 17}
    assert queue.latest == job
    assert writes == []



@pytest.mark.parametrize('interruption', ['none', 'verification', 'publication'])
def test_one_verified_fix_publishes_both_targets_and_recovers_without_reinvestigation(monkeypatch, interruption):
    from crashlytics_automation import issues

    identity = identity_hash_for(ALERT.issue_id, RELEASE_SHA)
    test_path = f'domain/src/test/kotlin/org/koin/{regression_test_name(identity)}'
    preservation_path = (
        f'domain/src/test/kotlin/org/koin/CrashlyticsPreservation{identity[:12]}Test.kt'
    )
    preservation_content = (
        'package org.koin\nimport org.junit.Test\nimport org.junit.Assert.assertEquals\n'
        + f'class CrashlyticsPreservation{identity[:12]}Test {{\n'
        + '    @Test fun originalValueRemainsStable() { assertEquals(1, Thing().originalValue()) }\n}\n'
    )
    candidate_source = 'package org.koin\nclass Thing { fun value() = 2; fun originalValue() = 1 }\n'
    source_before = 'package org.koin\nclass Thing { fun value() = 1; fun originalValue() = 1 }\n'
    regression_content = (
        'package org.koin\nimport org.junit.Test\nimport org.junit.Assert.assertEquals\n'
        + f'class {regression_test_name(identity)[:-3]} {{\n'
        + '    @Test fun valueMatchesExpected() { assertEquals(2, Thing().value()) }\n}\n'
    )
    decision = {
        'decision': 'fix', 'analysis': 'Observed before/after regression.', 'reason': 'Verified correction.',
        'sourcePath': SOURCE_PATH, 'sourceLine': 2,
        'files': [
            {'path': SOURCE_PATH, 'content': candidate_source},
            {'path': test_path, 'content': regression_content},
            {'path': preservation_path, 'content': preservation_content},
        ],
    }
    from crashlytics_automation.behavior import candidate_digest, source_digest
    proof_files = [
        {'path': SOURCE_PATH, 'kind': 'source',
         'beforeSha256': hashlib.sha256(source_before.encode()).hexdigest(),
         'afterSha256': hashlib.sha256(candidate_source.encode()).hexdigest()},
        {'path': test_path, 'kind': 'test', 'beforeSha256': None,
         'afterSha256': hashlib.sha256(regression_content.encode()).hexdigest()},
        {'path': preservation_path, 'kind': 'test', 'beforeSha256': None,
         'afterSha256': hashlib.sha256(preservation_content.encode()).hexdigest()},
    ]
    review = {
        'version': 1, 'approved': True, 'reason': 'Original behavior remains intact.',
        'unrelatedChanges': [],
        'contracts': [{
            'sourcePath': SOURCE_PATH, 'sourceLine': 2,
            'behavior': 'originalValue remains stable.',
            'testPath': preservation_path, 'testMethod': 'originalValueRemainsStable',
        }],
        'sourceDigest': source_digest(proof_files),
    }
    decision['behaviorReview'] = review
    successful_verification = {
        'version': 2, 'passed': True, 'reason': 'Crash fixed and original behavior preserved.',
        'behaviorReview': review, 'candidateDigest': candidate_digest(proof_files),
        'checks': [
            {'phase': 'baseline', 'purpose': 'crash', 'path': test_path, 'exit_code': 1,
             'timed_out': False, 'test_result': 'failed', 'evidence': {'source': 'junit-xml'},
             'methods': []},
            {'phase': 'candidate', 'purpose': 'crash', 'path': test_path, 'exit_code': 0,
             'timed_out': False, 'test_result': 'passed', 'evidence': {'source': 'junit-xml'},
             'methods': ['valueMatchesExpected']},
            *[
                {'phase': phase, 'purpose': 'preservation', 'path': preservation_path, 'exit_code': 0,
                 'timed_out': False, 'test_result': 'passed', 'evidence': {'source': 'junit-xml'},
                 'methods': ['originalValueRemainsStable']}
                for phase in ('baseline', 'candidate')
            ],
        ],
    }
    verification_results = [successful_verification]
    if interruption == 'verification':
        verification_results.insert(0, {
            'version': 2, 'passed': False, 'retryable': True,
            'reason': 'verification command timed out',
        })
    seen_candidates, sandbox_starts = [], []

    class CheckedOutGithub(Github):
        def checkout(self, sha, destination):
            destination.mkdir(parents=True, exist_ok=True)
            if sha == BASE_SHA:
                source = destination / SOURCE_PATH
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(source_before, encoding='utf-8')

    class RetrySandbox:
        def __init__(self, **kwargs):
            sandbox_starts.append(True)
            self.artifact_directory = kwargs['target'].parent / 'artifacts'
            self.artifact_directory.mkdir(exist_ok=True)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, **_kwargs):
            raise AssertionError('unexpected additional investigation')

        def verify_candidate(self, *, files, **_kwargs):
            seen_candidates.append(copy.deepcopy(files))
            return verification_results.pop(0)

    queue = Queue()
    _patch_queue(monkeypatch, queue)
    model_calls, merge_deliveries = [], []
    publications = {}
    publication_interrupted = False

    def publish(_github, *, base_branch, base_sha, **_kwargs):
        nonlocal publication_interrupted
        if interruption == 'publication' and base_branch == 'develop' and not publication_interrupted:
            publication_interrupted = True
            raise Timeout('publication interrupted after the production PR')
        fix = PublishedFix(24 if base_branch == 'production' else 25, 'c' * 40, base_sha, 'e' * 64, base_branch)
        publications[base_branch] = fix
        return fix

    monkeypatch.setattr(issues, 'verify_crash_issue', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'record_fix_progress', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'report_for_human',
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('automatic recovery became manual')))
    monkeypatch.setattr('crashlytics_automation.fix_generation.existing_fix',
                        lambda *_args, base_branch, **_kwargs: publications.get(base_branch))
    monkeypatch.setattr('crashlytics_automation.fix_generation.publish_investigated_fix', publish)
    monkeypatch.setattr('crashlytics_automation.release_source.resolve_release_commit', lambda *_a, **_k: RELEASE_SHA)
    monkeypatch.setattr('crashlytics_automation.release_source.resolve_investigated_source',
                        lambda *_args, **_kwargs: SourceLocation.from_payload(_source()))
    monkeypatch.setattr('crashlytics_automation.pull_requests.branch_head_sha',
                        lambda _g, branch: BASE_SHA if branch == 'production' else '9' * 40)
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal',
                        lambda **_kwargs: model_calls.append(True) or decision)
    monkeypatch.setattr('crashlytics_automation.sandbox.InvestigationSandbox', RetrySandbox)
    monkeypatch.setattr(worker, 'enqueue_task',
                        lambda _config, _function, _identity, data: merge_deliveries.append(data))
    monkeypatch.setenv('CRASHLYTICS_OPENAI_API_KEY', 'test-only')

    result = worker.run_job(CheckedOutGithub(), {'botLogin': 'autofix[bot]'}, _base_job())
    first_checkpoint = copy.deepcopy(queue.proposals['production'])
    if interruption != 'none':
        assert result['outcome'] == 'queued'
        assert merge_deliveries == []
        result = worker.run_job(CheckedOutGithub(), {'botLogin': 'autofix[bot]'}, copy.deepcopy(queue.latest))

    expected_verifications = 2 if interruption == 'verification' else 1
    assert result == {'outcome': 'merging', 'issueNumber': 17}
    assert len(model_calls) == 1
    assert len(sandbox_starts) == expected_verifications
    assert queue.latest['verificationAttempts'] == {'production': expected_verifications}
    assert first_checkpoint == queue.proposals['production']
    assert all(candidate == seen_candidates[0] for candidate in seen_candidates)
    assert set(publications) == {'production', 'develop'}
    assert {fix.head_sha for fix in publications.values()} == {'c' * 40}
    assert publications['production'].base_sha == BASE_SHA
    assert publications['develop'].base_sha == '9' * 40
    assert {task['baseBranch'] for task in merge_deliveries} == {'production', 'develop'}
    assert all(task['headSha'] == 'c' * 40 for task in merge_deliveries)




@pytest.mark.parametrize('prior_attempts', [0, 3])
def test_interrupted_provider_failure_keeps_incremental_trace_and_retries_only_pending_report(monkeypatch, tmp_path, prior_attempts):
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
    job['attempts']['production'] = prior_attempts
    if prior_attempts == 3:
        job['attemptLimits'] = {'production': 4}
    job['analyses']['production'] = {'analysis': 'previous attempt', 'tools': []}

    first = worker.run_job(CheckedOutGithub(), {'botLogin': 'autofix[bot]'}, job)
    pending = copy.deepcopy(queue.latest)
    trace = (tmp_path / 'artifacts' / 'investigation-tool-results.jsonl').read_text(encoding='utf-8')
    record = json.loads(trace.splitlines()[0])

    assert first == {'outcome': 'superseded', 'issueNumber': 17}
    assert record['stdout'] == 'callback output [REDACTED] [REDACTED]'
    assert 'test-only' not in trace and 'sentinel-private-key' not in trace
    assert pending['status'] == 'manual' and pending['reportPending'] is True
    assert pending['attempts']['production'] == prior_attempts + 1
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
@pytest.mark.parametrize('verification_only', [False, True])
def test_manual_resume_reuses_captured_evidence_and_preserves_the_model_budget(monkeypatch, attempts, verification_only):
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
        verification_only=verification_only,
    )

    assert resumed['status'] == queue.latest['status'] == 'queued'
    assert resumed['alert'] == original['alert']
    assert resumed['evidence'] == original['evidence']
    assert resumed['attempts']['production'] == attempts
    assert resumed['analyses'] == original['analyses']
    assert 'private-value' not in resumed['operatorNotes']
    assert 'reason' not in resumed and 'reportPending' not in resumed
    assert reports[-1].evidence['investigation']['status'] == 'queued'
    if verification_only:
        assert resumed['verificationOnly'] is True
        assert all(saved.get('verificationOnly') is True for saved in queue.history)


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


@pytest.mark.parametrize('approved,limit', [(False, 3), (True, 4)])
def test_extra_attempt_is_explicit_scoped_and_does_not_reset_usage(monkeypatch, approved, limit):
    from crashlytics_automation import issues
    queue = Queue()
    original = _base_job('manual')
    original['attempts']['production'] = 3
    queue.latest = copy.deepcopy(original)
    _patch_queue(monkeypatch, queue)
    monkeypatch.setattr(issues, 'record_fix_progress', lambda *_a, **_k: None)
    monkeypatch.setattr(worker, 'enqueue_task',
                        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('unexpected capture')))

    for _ in range(2):
        resumed = worker.prepare_existing_issue(
            ExistingIssueGithub(), {'botLogin': 'autofix[bot]'}, 17,
            resume_manual=True, notes='Operator research requests another attempt',
            allow_extra_attempt=approved,
        )
        assert resumed['attempts'] == original['attempts']
        assert resumed['evidence'] == original['evidence']
        assert resumed.get('attemptLimits', {}).get('production', 3) == limit
        assert 'develop' not in resumed.get('attemptLimits', {})


@pytest.mark.parametrize('used,resume', [(2, True), (4, True), (3, False)])
def test_extra_attempt_cannot_be_pregranted_replenished_or_used_without_resume(monkeypatch, used, resume):
    queue = Queue()
    original = _base_job('manual')
    original['attempts']['production'] = used
    if used == 4:
        original['attemptLimits'] = {'production': 4}
    queue.latest = copy.deepcopy(original)
    _patch_queue(monkeypatch, queue)
    with pytest.raises(ValueError):
        worker.prepare_existing_issue(
            ExistingIssueGithub(), {}, 17, resume_manual=resume, allow_extra_attempt=True,
        )
    assert queue.latest == original and queue.history == []


def test_exhausted_extra_attempt_never_starts_another_model(monkeypatch):
    from crashlytics_automation import issues
    queue = Queue()
    _patch_queue(monkeypatch, queue)
    job = _base_job()
    job['attempts']['production'] = 4
    job['attemptLimits'] = {'production': 4}
    job['releaseSha'] = RELEASE_SHA
    monkeypatch.setattr(issues, 'verify_crash_issue', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'record_fix_progress', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'report_for_human', lambda *_a, **_k: {'outcome': 'manual'})
    monkeypatch.setattr('crashlytics_automation.fix_generation.existing_fix', lambda *_a, **_k: None)
    monkeypatch.setattr('crashlytics_automation.pull_requests.branch_head_sha', lambda *_a, **_k: BASE_SHA)
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal',
                        lambda **_k: (_ for _ in ()).throw(AssertionError('fifth model attempt')))
    worker.run_job(Github(), {'botLogin': 'autofix[bot]'}, job)
    assert queue.latest['attempts']['production'] == 4
    assert queue.latest['status'] == 'manual'


@pytest.mark.parametrize('public', [False, True])
def test_completed_proposal_recovery_survives_conflict_without_exposing_private_source(monkeypatch, tmp_path, public):
    import shutil
    from crashlytics_automation import issues
    from crashlytics_automation.investigation_jobs import JobConflict

    source_before = 'package org.koin\nclass Thing { fun value() = 1; fun originalValue() = 7 }\n'
    identity = identity_hash_for(ALERT.issue_id, RELEASE_SHA)
    test_path = f'domain/src/test/kotlin/org/koin/{regression_test_name(identity)}'
    decision = {
        'decision': 'fix', 'analysis': 'An actual completed analysis.', 'reason': 'A proposed repair.',
        'sourcePath': SOURCE_PATH, 'sourceLine': 2,
        'files': [
            {'path': SOURCE_PATH, 'content': 'package org.koin\nclass Thing { fun value() = 2; fun originalValue() = 7 }\n'},
            {'path': test_path, 'content': (
                'package org.koin\nimport org.junit.Test\nimport org.junit.Assert.assertEquals\n'
                + f'class {regression_test_name(identity)[:-3]} {{\n'
                + '    @Test fun repairedValue() { assertEquals(2, Thing().value()) }\n}\n'
            )},
        ],
    }
    from crashlytics_automation.behavior import preservation_test_name, prepare_behavior_review
    from crashlytics_automation.candidate import validate_candidate
    preservation_path = f'domain/src/test/kotlin/org/koin/{preservation_test_name(identity)}'
    preservation_file = {
        'path': preservation_path,
        'content': (
            f'package org.koin\nclass {preservation_test_name(identity)[:-3]} {{\n'
            '  @org.junit.Test fun originalValueIsPreserved() {\n'
            '    org.junit.Assert.assertEquals(7, Thing().originalValue())\n  }\n}\n'
        ),
    }
    decision['files'].append(preservation_file)
    normalized = validate_candidate(decision['files'], {SOURCE_PATH: source_before}, identity)
    assert normalized['valid']
    decision['behaviorReview'] = prepare_behavior_review({
        'approved': True, 'reason': 'Only the defective return value changes.',
        'unrelatedChanges': [], 'files': [preservation_file],
        'contracts': [{
            'sourcePath': SOURCE_PATH, 'sourceLine': 2, 'behavior': 'originalValue remains seven.',
            'testPath': preservation_path, 'testMethod': 'originalValueIsPreserved',
        }],
    }, normalized['files'], {SOURCE_PATH: source_before}, identity)

    class CheckedOutGithub(Github):
        def rest(self, method, path, *args, **kwargs):
            if method == 'GET' and path == '/repos/BCSDLab/KOIN_ANDROID':
                return {'private': not public}
            return super().rest(method, path, *args, **kwargs)

        def checkout(self, _sha, destination):
            source = destination / SOURCE_PATH
            source.parent.mkdir(parents=True)
            source.write_text(source_before)

    class Sandbox:
        def __init__(self, **kwargs):
            self.artifact_directory = kwargs['target'].parent / 'artifacts'

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def export_artifacts(self, destination):
            shutil.copytree(self.artifact_directory, destination, dirs_exist_ok=True)

        def verify_candidate(self, **_kwargs):
            raise AssertionError('conflicting metadata must block verification/publication')

    class ConflictingQueue(Queue):
        def save_proposal(self, *_args, **_kwargs):
            raise JobConflict('another writer advanced the case')

    queue = ConflictingQueue()
    _patch_queue(monkeypatch, queue)
    model_calls = []
    monkeypatch.setattr(issues, 'verify_crash_issue', lambda *_a, **_k: None)
    monkeypatch.setattr(issues, 'record_fix_progress', lambda *_a, **_k: None)
    monkeypatch.setattr('crashlytics_automation.fix_generation.existing_fix', lambda *_a, **_k: None)
    monkeypatch.setattr('crashlytics_automation.release_source.resolve_release_commit', lambda *_a, **_k: RELEASE_SHA)
    monkeypatch.setattr('crashlytics_automation.pull_requests.branch_head_sha', lambda *_a, **_k: BASE_SHA)
    monkeypatch.setattr('crashlytics_automation.sandbox.InvestigationSandbox', Sandbox)
    monkeypatch.setattr('crashlytics_automation.openai_client.request_fix_proposal',
                        lambda **_kwargs: model_calls.append(True) or decision)
    monkeypatch.setenv('CRASHLYTICS_OPENAI_API_KEY', 'test-only')
    artifacts = tmp_path / 'uploaded'
    monkeypatch.setenv('INVESTIGATION_ARTIFACTS', str(artifacts))
    job = _base_job()

    assert worker.run_job(CheckedOutGithub(), {'botLogin': 'autofix[bot]'}, job) == {
        'outcome': 'superseded', 'issueNumber': 17,
    }
    assert model_calls == [True]
    recovery = artifacts / job['id'] / 'production' / 'proposal.json'
    if public:
        saved = json.loads(recovery.read_text())
        assert saved['identity'] == {
            'jobId': job['id'], 'target': 'production', 'releaseSha': RELEASE_SHA,
            'branchBaseSha': BASE_SHA, 'baseSha': BASE_SHA,
        }
        recovered_files = {item['path']: item['content'] for item in saved['proposal']['files']}
        assert recovered_files == {item['path']: item['content'] for item in decision['files']}
    else:
        assert not artifacts.exists()
