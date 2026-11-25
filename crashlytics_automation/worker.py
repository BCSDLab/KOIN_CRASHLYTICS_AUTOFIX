"""Actions worker: investigate one release lane in isolation, verify, publish, deliver."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from contextlib import ExitStack
from pathlib import Path
from typing import Any


def runtime_config() -> dict[str, Any]:
    for line in os.environ.get('CRASHLYTICS_ENV', '').splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            if re.fullmatch(r'[A-Z][A-Z0-9_]*', key) is None:
                raise ValueError('Invalid runtime configuration key')
            os.environ[key] = value.strip()
    required = ('CRASHLYTICS_PROJECT_ID', 'CRASHLYTICS_APP_ID', 'AUTOMATION_SERVICE_ACCOUNT',
                'CRASHLYTICS_AUTOFIX_BOT_LOGIN', 'CRASHLYTICS_GITHUB_APP_ID',
                'CRASHLYTICS_GITHUB_INSTALLATION_ID')
    if any(not os.environ.get(key, '').strip() for key in required):
        raise ValueError('Missing worker configuration')
    from .repository import ANDROID_APPLICATION_ID
    return {
        'projectId': os.environ['CRASHLYTICS_PROJECT_ID'],
        'appId': os.environ['CRASHLYTICS_APP_ID'],
        'bundleId': ANDROID_APPLICATION_ID,
        'serviceAccount': os.environ['AUTOMATION_SERVICE_ACCOUNT'],
        'botLogin': os.environ['CRASHLYTICS_AUTOFIX_BOT_LOGIN'],
        'priorBotLogins': tuple(value.strip() for value in
                               os.environ.get('CRASHLYTICS_PRIOR_BOT_LOGINS', '').split(',') if value.strip()),
    }


def worker_github() -> Any:
    from .github import create_github
    return create_github(
        os.environ['CRASHLYTICS_GITHUB_APP_ID'], os.environ['CRASHLYTICS_GITHUB_INSTALLATION_ID'],
        os.environ['CRASHLYTICS_GITHUB_APP_PRIVATE_KEY'],
        permissions={'contents': 'write', 'issues': 'write', 'pull_requests': 'write'},
        include_state=True,
    )


def enqueue_task(config: dict[str, Any], function: str, identity: str, data: dict[str, Any], *, session: Any = None) -> None:
    """Use runtime OIDC, never the deployer's identity, for private task invocation."""
    if function not in ('generateCrashlyticsFix', 'mergeCrashlyticsFix'):
        raise ValueError('Unexpected task destination')
    project, account = config['projectId'], config['serviceAccount']
    if re.fullmatch(r'[a-z][a-z0-9-]{4,61}[a-z0-9]', project) is None or not account.endswith('.iam.gserviceaccount.com'):
        raise ValueError('Invalid trusted task configuration')
    if session is None:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
        credentials, _ = google.auth.default(scopes=['https://www.googleapis.com/auth/cloud-platform'])
        session = AuthorizedSession(credentials)
    parent = f'projects/{project}/locations/us-central1/queues/{function}'
    task_id = hashlib.sha256(f'{function}/{identity}'.encode()).hexdigest()
    url = f'https://us-central1-{project}.cloudfunctions.net/{function}'
    response = session.post(f'https://cloudtasks.googleapis.com/v2/{parent}/tasks', json={'task': {
        'name': f'{parent}/tasks/{task_id}',
        'dispatchDeadline': '600s',
        'httpRequest': {
            'httpMethod': 'POST', 'url': url,
            'headers': {'Content-Type': 'application/json'},
            'oidcToken': {'serviceAccountEmail': account, 'audience': url},
            'body': base64.b64encode(json.dumps({'data': data}, ensure_ascii=False).encode()).decode('ascii'),
        },
    }}, timeout=30, allow_redirects=False)
    if response.status_code not in (200, 201, 409):
        raise RuntimeError(f'Cloud Tasks delivery failed (HTTP {response.status_code})')


def prepare_existing_issue(
    github: Any, config: dict[str, Any], issue_number: int, *,
    resume_manual: bool = False, notes: str | None = None,
) -> Any:
    """Capture once, or explicitly resume source investigation from existing evidence."""
    from .github import issue_marker
    from .investigation_jobs import InvestigationQueue, POLICY_VERSION
    from .repository import REPOSITORY_PATH, TARGET_BRANCHES
    from .task_payloads import parse_alert_payload
    from .privacy import safe_text

    issue = github.rest('GET', f'{REPOSITORY_PATH}/issues/{issue_number}')
    body = issue.get('body') or ''
    identity = re.findall(r'<!-- crashlytics-issue:([A-Za-z0-9_-]{1,128}) -->', body)
    fields = {}
    for name, pattern in (
        ('appVersion', r'^\* 발생 버전: (.+)$'), ('time', r'^\* 알림 시각: (.+)$'),
    ):
        found = re.search(pattern, body, re.MULTILINE)
        if found is None:
            raise ValueError('Existing issue lacks original Crashlytics event metadata')
        fields[name] = found.group(1).strip()
    if len(identity) != 1 or issue.get('pull_request') is not None or issue_marker(identity[0]) not in body:
        raise ValueError('Not a genuine Crashlytics issue')
    original = re.search(r'### 어떤 오류인가요\?\s*\n\* ([^\n]+)\n\* ([^\n]+)', body)
    if original is None:
        raise ValueError('Existing issue lacks original crash title and exception')
    alert = parse_alert_payload({
        **fields, 'issueId': identity[0], 'eventId': f'manual-investigation/{issue_number}/policy-{POLICY_VERSION}',
        'title': original.group(1), 'subtitle': original.group(2),
    })
    queue = InvestigationQueue(github)
    job = queue.get(alert)
    if job is None:
        if resume_manual:
            raise ValueError('No saved evidence exists; resume never requests a new capture')
        enqueue_task(config, 'generateCrashlyticsFix', alert.event_id, {'alert': alert.to_payload()})
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            job = queue.get(alert)
            if job is not None:
                break
            time.sleep(5)
        if job is None:
            raise RuntimeError('Evidence snapshot task did not publish investigation state within three minutes')
    changed = False
    if resume_manual:
        if job['status'] not in ('manual', 'queued'):
            raise ValueError('Only manual or queued source investigations can be resumed')
        if all(branch in job['branches'] for branch in TARGET_BRANCHES):
            raise ValueError('Both fixes already exist; source investigation must not be restarted')
        job['status'] = 'queued'
        job.pop('reason', None)
        job.pop('reportPending', None)
        changed = True
    if notes:
        if job['status'] != 'queued':
            raise ValueError('Research notes require a queued or explicitly resumed investigation')
        job['operatorNotes'] = safe_text(notes, 16_000)
        changed = True
    if changed:
        queue.put(job)
        _report(github, queue, job, config)
    return job


def _context(job: dict[str, Any]) -> Any:
    from .models import CrashContext, SourceLocation
    from .repository import TARGET_BRANCHES
    from .task_payloads import parse_alert_payload
    evidence = dict(job['evidence'])
    evidence['investigation'] = {
        'status': job['status'], 'reason': job.get('reason', ''),
        'analyses': job['analyses'], 'runUrl': job.get('runUrl'),
    }
    source = next(iter(job.get('sources', {}).values()), None)
    return CrashContext(
        alert=parse_alert_payload(job['alert']), evidence=evidence,
        issue_number=job['issueNumber'], source=SourceLocation.from_payload(source),
        pull_numbers=tuple(job['branches'][target]['pullNumber'] for target in TARGET_BRANCHES
                           if target in job['branches']),
    )




def _report(github: Any, queue: Any, job: dict[str, Any], config: dict[str, Any]) -> dict[str, Any] | None:
    """Keep report delivery separate from investigation and merge authorization."""
    from requests import RequestException
    from .github import GitHubError
    from .issues import record_fix_progress, report_for_human
    job['reportPending'] = True
    queue.put(job)
    try:
        if job['status'] == 'manual':
            result = report_for_human(github, _context(job), job['reason'], config)
        else:
            record_fix_progress(github, _context(job), config)
            result = None
    except (GitHubError, RequestException):
        return {'outcome': job['status'], 'issueNumber': job['issueNumber'], 'reportPending': True}
    job.pop('reportPending', None)
    queue.put(job)
    return result


def _deliver(github: Any, queue: Any, job: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    from .fix_generation import existing_fix
    from .models import ManualReview, SourceLocation
    from .repository import TARGET_BRANCHES
    from .task_payloads import make_merge_task
    if job.get('deliveryAttempts', 0) >= 3:
        raise ValueError('Merge task delivery limit reached')
    job['deliveryAttempts'] = job.get('deliveryAttempts', 0) + 1
    context = _context(job)
    release = job.get('releaseSha') or next(iter(job['sources'].values()))['sourceSha']
    fixes = []
    for target in TARGET_BRANCHES:
        origin = job.get('branchBases', {}).get(target)
        if origin is None:
            raise ValueError('Published PR has no recorded production origin')
        fix = existing_fix(github, alert=context.alert, issue_number=context.issue_number,
                           base_branch=target, bot_login=config['botLogin'], release_sha=release,
                           branch_base_sha=origin)
        if fix is None or isinstance(fix, ManualReview) or fix.to_payload()['headSha'] != job['branches'][target]['headSha']:
            raise ValueError('Published PR changed before merge delivery')
        fixes.append(fix)
    job['status'] = 'delivering'
    queue.put(job)
    for fix in fixes:
        context.source = SourceLocation.from_payload(job['sources'][fix.base_branch])
        enqueue_task(config, 'mergeCrashlyticsFix', f'{fix.pull_number}/{fix.head_sha}',
                     make_merge_task(context, fix, tuple(fixes)))
    job['status'] = 'merging'
    queue.put(job)
    _report(github, queue, job, config)
    return {'outcome': 'merging', 'issueNumber': context.issue_number}


def _baseline(target: Path, files: list[dict[str, Any]], identity_hash: str) -> dict[str, Any]:
    from .candidate import is_allowed_source_path, is_allowed_test_path
    result: dict[str, Any] = {}
    for entry in files:
        path = entry.get('path') if isinstance(entry, dict) else None
        if not is_allowed_source_path(path) and not is_allowed_test_path(path, identity_hash):
            raise ValueError('Proposal changes an unapproved path')
        location = target / path
        if location.is_symlink() or not location.resolve().is_relative_to(target.resolve()):
            raise ValueError('Proposal path leaves the trusted checkout')
        if location.exists():
            result[path] = location.read_text(encoding='utf-8')
    return result


def run_job(github: Any, config: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    from requests import RequestException
    from .candidate import identity_hash_for, regression_test_name, validate_candidate
    from .fix_generation import existing_fix, publish_investigated_fix
    from .investigation_jobs import InvestigationQueue, JobConflict
    from .issues import verify_crash_issue
    from .models import ManualReview
    from .openai_client import DEFAULT_MODEL, request_fix_proposal
    from .pull_requests import branch_head_sha
    from .release_source import resolve_investigated_source, resolve_release_commit
    from .repository import REPOSITORY, REPOSITORY_PATH, TARGET_BRANCHES
    from .sandbox import InvestigationSandbox

    queue = InvestigationQueue(github)
    context = _context(job)
    verify_crash_issue(github, context)
    issue = github.rest('GET', f'{REPOSITORY_PATH}/issues/{context.issue_number}')
    if issue.get('state') != 'open':
        job['status'], job['reason'] = 'manual', '이슈가 닫혀 있어 자동 조사를 중단했습니다.'
        queue.put(job)
        return {'outcome': 'closed', 'issueNumber': context.issue_number}
    target = next((branch for branch in TARGET_BRANCHES if branch not in job['branches']), None)
    try:
        if job['status'] in ('manual', 'merging', 'complete') and job.get('reportPending') is True:
            result = _report(github, queue, job, config)
            return result or {'outcome': job['status'], 'issueNumber': context.issue_number}
        if target is None:
            return _deliver(github, queue, job, config)
        attempts = job['attempts'].get(target, 0)
        job['status'] = 'running'
        job['startedAt'] = datetime.now(timezone.utc).isoformat()
        if os.environ.get('GITHUB_RUN_ID', '').isdigit():
            job['runUrl'] = f'https://github.com/{os.environ["GITHUB_REPOSITORY"]}/actions/runs/{os.environ["GITHUB_RUN_ID"]}'
        queue.put(job)
        _report(github, queue, job, config)
        release = job.get('releaseSha')
        if release is None and job.get('sources'):
            release = next(iter(job['sources'].values()))['sourceSha']
        if release is None:
            release = resolve_release_commit(github, job['evidence'])
            if isinstance(release, ManualReview):
                raise ValueError(release.reason)
        job['releaseSha'] = release
        origin = job.get('branchBases', {}).get(target)
        if origin is None:
            origin = branch_head_sha(github, 'production')
        resumed = existing_fix(github, alert=context.alert, issue_number=context.issue_number,
                               base_branch=target, bot_login=config['botLogin'], release_sha=release,
                               branch_base_sha=origin)
        if isinstance(resumed, ManualReview):
            raise ValueError(resumed.reason)
        checkpointed = False
        if resumed is not None:
            if target not in job.get('sources', {}):
                raise ValueError('Existing PR has no durable investigated source anchor')
            published = resumed
        else:
            if attempts >= 3:
                raise RuntimeError('The investigation execution limit was reached')
            branch_base = branch_head_sha(github, 'production')
            base = branch_base if target == 'production' else branch_head_sha(github, target)
            job.setdefault('branchBases', {})[target] = branch_base
            identity_hash = identity_hash_for(context.alert.issue_id, release)
            with tempfile.TemporaryDirectory(prefix='crashlytics-investigation-') as temporary:
                root = Path(temporary)
                github.checkout(release, root / 'release')
                github.checkout(branch_base, root / 'target')
                repository = github.rest('GET', REPOSITORY_PATH)
                with InvestigationSandbox(
                    release=root / 'release', target=root / 'target',
                    image=os.environ.get('INVESTIGATION_IMAGE', 'crashlytics-investigator:local'),
                    android_sdk=Path(os.environ['ANDROID_HOME']) if os.environ.get('ANDROID_HOME') else None,
                ) as sandbox, ExitStack() as exports:
                    artifacts = os.environ.get('INVESTIGATION_ARTIFACTS')
                    if artifacts and isinstance(repository, dict) and repository.get('private') is False:
                        exports.callback(sandbox.export_artifacts, Path(artifacts) / job['id'] / target)
                    job['attempts'][target] = attempts + 1
                    queue.put(job)
                    decision = request_fix_proposal(
                        model=os.environ.get('OPENAI_MODEL', DEFAULT_MODEL),
                        api_key=os.environ['CRASHLYTICS_OPENAI_API_KEY'],
                        context={
                            'issue': context.alert.to_payload(),
                            'repository': REPOSITORY, 'releaseSha': release, 'baseBranch': 'production',
                            'pullRequestTarget': target, 'pullRequestBaseSha': base,
                            'operatorNotes': job.get('operatorNotes'),
                            'priorInvestigations': job['analyses'],
                            'baseSha': branch_base, 'crash': job['evidence'], 'identityHash': identity_hash,
                            'regressionTestName': regression_test_name(identity_hash),
                            'workspaces': {'release': '/workspace/release', 'target': '/workspace/target',
                                           'scratch': '/workspace/scratch'},
                        }, execute=sandbox.execute,
                    )
                    if decision.get('toolResults'):
                        (sandbox.artifact_directory / 'investigation-tool-results.json').write_text(
                            json.dumps(decision['toolResults'], ensure_ascii=False, indent=2), encoding='utf-8',
                        )
                    job['analyses'][target] = {
                        'analysis': decision['analysis'], 'reason': decision['reason'],
                        'tools': [{'tool': item.get('tool', 'run_command'),
                                   'command': str(item.get('command', ''))[:500],
                                   'exit_code': item.get('exit_code'), 'timed_out': item.get('timed_out')}
                                  for item in decision.get('toolResults', [])],
                    }
                    queue.put(job)
                    if decision['decision'] != 'fix':
                        job['status'], job['reason'] = 'manual', decision['reason']
                        return _report(github, queue, job, config) or {
                            'outcome': 'manual', 'issueNumber': context.issue_number,
                        }
                    validated = validate_candidate(decision['files'], _baseline(root / 'target', decision['files'], identity_hash), identity_hash)
                    if not validated['valid']:
                        raise ValueError(validated['reason'])
                    verification = sandbox.verify_candidate(files=validated['files'], identity_hash=identity_hash)
                    job['analyses'][target]['verification'] = {
                        'passed': verification.get('passed') is True, 'reason': str(verification.get('reason', ''))[:2000],
                    }
                    if verification.get('passed') is not True:
                        raise ValueError(verification.get('reason') or 'Independent reproduction verification failed')
                    source = resolve_investigated_source(github, release_sha=release,
                                                        path=decision['sourcePath'], line=decision['sourceLine'])
                    if isinstance(source, ManualReview):
                        raise ValueError(source.reason)
                    job.setdefault('sources', {})[target] = source.to_payload()
                    job['analyses'][target]['source'] = f'{source.path}:{source.line}'
                    queue.put(job)
                    published = publish_investigated_fix(
                        github, alert=context.alert, evidence=job['evidence'], decision=decision,
                        issue_number=context.issue_number, base_branch=target, base_sha=base,
                        branch_base_sha=branch_base,
                        release_sha=release, bot_login=config['botLogin'], verification=verification,
                        prior_bot_logins=config.get('priorBotLogins', ()),
                    )
                    if isinstance(published, ManualReview):
                        raise ValueError(published.reason)
                    job['branches'][target] = published.to_payload()
                    job['status'] = 'queued' if len(job['branches']) < len(TARGET_BRANCHES) else 'delivering'
                    queue.put(job)
                    checkpointed = True
        if not checkpointed:
            job['branches'][target] = published.to_payload()
            job['status'] = 'queued' if len(job['branches']) < len(TARGET_BRANCHES) else 'delivering'
            queue.put(job)
        _report(github, queue, job, config)
        if job['status'] == 'delivering':
            return _deliver(github, queue, job, config)
        return {'outcome': 'queued', 'issueNumber': context.issue_number, 'baseBranch': target,
                'pullNumber': published.pull_number}
    except JobConflict:
        return {'outcome': 'superseded', 'issueNumber': context.issue_number}
    except Exception as error:
        from .privacy import safe_text
        text = str(error)
        for key in ('CRASHLYTICS_OPENAI_API_KEY', 'CRASHLYTICS_GITHUB_APP_PRIVATE_KEY'):
            secret = os.environ.get(key)
            if secret:
                text = text.replace(secret, '[REDACTED]')
        reason = safe_text(text, 1000) or type(error).__name__
        if job['status'] == 'merging' or (job['status'] == 'queued' and target in job['branches']):
            job['reason'], job['reportPending'] = reason, True
            queue.put(job)
            return {'outcome': job['status'], 'issueNumber': context.issue_number, 'reportPending': True}
        if job['status'] == 'delivering' and isinstance(error, (RuntimeError, RequestException)) and job.get('deliveryAttempts', 0) < 3:
            job['reason'] = reason
            try:
                queue.put(job)
            except JobConflict:
                return {'outcome': 'superseded', 'issueNumber': context.issue_number}
            _report(github, queue, job, config)
            return {'outcome': 'delivering', 'issueNumber': context.issue_number}
        job['status'], job['reason'] = 'manual', reason
        try:
            queue.put(job)
        except JobConflict:
            return {'outcome': 'superseded', 'issueNumber': context.issue_number}
        return _report(github, queue, job, config) or {'outcome': 'manual', 'issueNumber': context.issue_number}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list-pending', action='store_true')
    parser.add_argument('--issue-number', type=int)
    parser.add_argument('--resume-manual', action='store_true')
    arguments = parser.parse_args()
    if arguments.issue_number is not None and arguments.issue_number < 1:
        parser.error('issue number must be positive')
    notes = os.environ.get('INVESTIGATION_NOTES') or None
    if (arguments.resume_manual or notes) and arguments.issue_number is None:
        parser.error('manual resume and research notes require an issue number')
    config = runtime_config()
    github = worker_github()
    from .investigation_jobs import InvestigationQueue
    from .repository import TARGET_BRANCHES
    jobs = InvestigationQueue(github).pending()
    if arguments.issue_number is not None:
        jobs = [job for job in jobs if job['issueNumber'] == arguments.issue_number]
        if arguments.resume_manual or notes or not jobs:
            prepared = prepare_existing_issue(github, config, arguments.issue_number,
                                              resume_manual=arguments.resume_manual, notes=notes)
            if prepared['status'] == 'queued':
                jobs = [prepared]
    if arguments.list_pending:
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
                output.write(f'pending={"true" if jobs else "false"}\n')
                output.write(f'issue_number={jobs[0]["issueNumber"] if jobs else ""}\n')
                needs_sandbox = bool(jobs and jobs[0]['status'] in ('queued', 'running')
                                     and any(branch not in jobs[0]['branches'] for branch in TARGET_BRANCHES))
                output.write(f'needs_sandbox={"true" if needs_sandbox else "false"}\n')
        print(json.dumps({'pending': len(jobs)}))
        return 0
    if not jobs:
        print(json.dumps({'outcome': 'idle'}))
        return 0
    result = run_job(github, config, jobs[0])
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'Investigation infrastructure failed ({type(error).__name__})', file=sys.stderr)
        raise SystemExit(1) from None
