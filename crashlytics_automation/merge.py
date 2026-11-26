"""Merge only the exact candidate after the required CI checks succeed.

Each issue has two pull requests on one shared fix branch. ``production`` may
merge as soon as its own gate passes; ``develop`` waits for production.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any
from urllib.parse import quote, urlsplit

from .candidate import (
    MAX_FILE_BYTES, MAX_TOTAL_BYTES, SHARED_FIX_BRANCH, branch_name_for,
    manifest_digest, sha256, validate_manifest,
)
from .github import OWNER, REPO, REPOSITORY_PATH
from .investigation_jobs import InvestigationQueue
from .pull_requests import CLOSURE_REFERENCE
from .task_payloads import validate_merge_task

PEER_BRANCH = {'production': 'develop', 'develop': 'production'}
REQUIRED_CHECKS = ('Lint & Format Check', 'Code Coverage')
FAILED_CONCLUSIONS = {'failure', 'timed_out', 'cancelled', 'action_required', 'startup_failure'}


def _pending(reason: str) -> dict[str, str]:
    return {'outcome': 'pending', 'reason': reason}


def _blocked(reason: str) -> dict[str, str]:
    return {'outcome': 'blocked', 'reason': reason}


def _merged(*, complete: bool) -> dict[str, Any]:
    return {'outcome': 'merged', 'complete': complete}




def _closes_tracked_issue(pr: dict[str, Any], job: dict[str, Any]) -> bool:
    body = pr.get('body')
    return (isinstance(body, str)
            and {int(number) for number in CLOSURE_REFERENCE.findall(body)} == {job['issueNumber']})


def _pages(github: Any, path: str, collection: str | None = None) -> list[dict[str, Any]]:
    items = []
    for page in range(1, 31):
        separator = '&' if '?' in path else '?'
        response = github.rest('GET', f'{path}{separator}per_page=100&page={page}')
        batch = response.get(collection) if collection and isinstance(response, dict) else response
        if not isinstance(batch, list):
            raise ValueError('Unexpected GitHub pagination response')
        items.extend(batch)
        if len(batch) < 100:
            return items
    raise ValueError('GitHub pagination limit exceeded')


def _read_file(github: Any, path: str, revision: str) -> dict[str, Any]:
    encoded = '/'.join(quote(part, safe='') for part in path.split('/'))
    try:
        result = github.rest('GET', f'{REPOSITORY_PATH}/contents/{encoded}?ref={revision}')
    except Exception as error:
        if getattr(error, 'status', None) == 404:
            return {'missing': True}
        raise
    if not isinstance(result, dict) or result.get('type') != 'file' or result.get('encoding') != 'base64' or not isinstance(result.get('content'), str):
        return {'invalid': True}
    try:
        content = base64.b64decode(''.join(result['content'].split()), validate=True)
    except (ValueError, binascii.Error):
        return {'invalid': True}
    size = result.get('size')
    if size is not None and (type(size) is not int or size != len(content)):
        return {'invalid': True}
    return {'bytes': content, 'size': len(content)}


def _verify_changes(github: Any, pr: dict[str, Any], manifest: dict[str, Any],
                    job: dict[str, Any]) -> dict[str, str] | None:
    files = _pages(github, f"{REPOSITORY_PATH}/pulls/{pr['number']}/files")
    expected = {file['path']: file for file in manifest['files']}
    if len(files) != len(expected):
        return _blocked('pull request changes do not match the manifest')
    by_name = {}
    for file in files:
        name = file.get('filename')
        if not isinstance(name, str) or name in by_name or name not in expected or file.get('status') not in ('added', 'modified'):
            return _blocked('pull request changes a file outside the manifest')
        by_name[name] = file
    total_bytes = 0
    for entry in manifest['files']:
        head = _read_file(github, entry['path'], job['headSha'])
        if head.get('missing') or head.get('invalid') or head['size'] > MAX_FILE_BYTES:
            return _blocked('candidate file is missing, unsupported or too large')
        total_bytes += head['size']
        if total_bytes > MAX_TOTAL_BYTES or sha256(head['bytes']) != entry['afterSha256']:
            return _blocked('candidate content does not match the manifest')
        branch_base_sha = manifest.get('branchBaseSha', manifest['baseSha'])
        base = _read_file(github, entry['path'], branch_base_sha)
        if entry['beforeSha256'] is None:
            if not base.get('missing'):
                return _blocked('new candidate file already exists on the production branch base')
            if entry['kind'] == 'test' and not _read_file(
                github, entry['path'], job['baseSha'],
            ).get('missing'):
                return _blocked('new regression test already exists on the PR target base')
        elif base.get('missing') or base.get('invalid') or sha256(base['bytes']) != entry['beforeSha256']:
            return _blocked('candidate production baseline does not match the manifest')
    return None


def _matching_pull_request_context(value: dict[str, Any], pr_number: int,
                                  head_sha: str, head_branch: str,
                                  target: str, base_sha: str) -> bool:
    pulls = value.get('pull_requests')
    if not isinstance(pulls, list):
        return False
    matches = []
    for pull in pulls:
        if not isinstance(pull, dict) or pull.get('number') != pr_number:
            continue
        base = pull.get('base') if isinstance(pull.get('base'), dict) else {}
        head = pull.get('head') if isinstance(pull.get('head'), dict) else {}
        matches.append(
            head.get('sha') == head_sha and head.get('ref') == head_branch
            and base.get('ref') == target and base.get('sha') == base_sha
        )
    return len(matches) == 1 and matches[0]


def _run_pull_request(run: dict[str, Any], pr_number: int, head_sha: str,
                      head_branch: str, target: str, base_sha: str) -> bool:
    return (run.get('head_branch') == head_branch
            and _matching_pull_request_context(run, pr_number, head_sha, head_branch, target, base_sha))

def _verify_checks(github: Any, head_sha: str, head_branch: str, pr_number: int,
                   target: str, base_sha: str) -> dict[str, str] | None:
    """Verify checks from the latest PR-specific workflow runs."""
    runs = _pages(
        github, f'{REPOSITORY_PATH}/actions/runs?head_sha={head_sha}', 'workflow_runs',
    )
    matching = []
    for run in runs:
        if not isinstance(run, dict):
            return _pending('workflow run metadata is invalid')
        if run.get('head_sha') != head_sha:
            return _blocked('workflow run does not identify the exact pull request head')
        if not _run_pull_request(run, pr_number, head_sha, head_branch, target, base_sha):
            continue
        repository = run.get('repository') if isinstance(run.get('repository'), dict) else {}
        head_repository = run.get('head_repository') if isinstance(run.get('head_repository'), dict) else {}
        if repository.get('full_name') != f'{OWNER}/{REPO}' \
                or head_repository.get('full_name') != f'{OWNER}/{REPO}':
            return _blocked('workflow run is not from the configured repository')
        if (type(run.get('id')) is not int or type(run.get('workflow_id')) is not int
                or type(run.get('run_number')) is not int or type(run.get('run_attempt')) is not int
                or type(run.get('check_suite_id')) is not int):
            return _pending('workflow run is missing immutable PR context')
        matching.append(run)
    if not matching:
        return _pending('target-specific workflow run has not reported yet')

    latest: dict[int, dict[str, Any]] = {}
    for run in matching:
        workflow_id = run['workflow_id']
        previous = latest.get(workflow_id)
        if previous is None or (run['run_number'], run['run_attempt'], run['id']) > (
            previous['run_number'], previous['run_attempt'], previous['id'],
        ):
            latest[workflow_id] = run

    observed: dict[str, dict[str, Any]] = {}
    for run in latest.values():
        jobs = _pages(
            github, f"{REPOSITORY_PATH}/actions/runs/{run['id']}/jobs?filter=latest", 'jobs',
        )
        for job in jobs:
            if not isinstance(job, dict):
                return _pending('workflow job metadata is invalid')
            name = job.get('name')
            if not isinstance(name, str):
                return _blocked('workflow job has no check name')
            if type(job.get('run_id')) is not int or job['run_id'] != run['id']:
                return _blocked('workflow job does not identify its exact workflow run')
            check_url = job.get('check_run_url')
            expected_prefix = f'{REPOSITORY_PATH}/check-runs/'
            parsed = urlsplit(check_url) if isinstance(check_url, str) else None
            if (parsed is None or not parsed.path.startswith(expected_prefix)
                    or not parsed.path[len(expected_prefix):].isdigit()):
                return _blocked('workflow job has an invalid check-run link')
            check = github.rest('GET', parsed.path)
            if (not isinstance(check, dict) or check.get('name') != name
                    or check.get('head_sha') != head_sha
                    or (check.get('check_suite') or {}).get('id') != run['check_suite_id']):
                return _blocked('check run does not identify the exact workflow run')
            if name in REQUIRED_CHECKS and (check.get('app') or {}).get('slug') != 'github-actions':
                return _blocked(f'required check has an unexpected publisher: {name}')
            if name in observed and name in REQUIRED_CHECKS:
                return _pending(f'required check has ambiguous workflow context: {name}')
            observed[name] = job
            if job.get('status') != 'completed':
                return _pending(f'check is still running: {name}')
            if job.get('conclusion') in FAILED_CONCLUSIONS:
                return _pending(f'check failed: {name}')
    for name in REQUIRED_CHECKS:
        job = observed.get(name)
        if job is None:
            return _pending(f'required check has not reported yet: {name}')
        if job.get('conclusion') != 'success':
            return _pending(f'required check did not succeed: {name}')

    check_runs = _pages(
        github, f'{REPOSITORY_PATH}/commits/{head_sha}/check-runs?filter=all', 'check_runs',
    )
    latest_external: dict[tuple[str, str], dict[str, Any]] = {}
    for check in check_runs:
        if not isinstance(check, dict) or check.get('head_sha') != head_sha:
            return _blocked('check run does not identify the exact pull request head')
        app = check.get('app') if isinstance(check.get('app'), dict) else {}
        if app.get('slug') == 'github-actions':
            continue
        pulls = check.get('pull_requests')
        if not isinstance(pulls, list) or not pulls:
            if check.get('status') != 'completed' or check.get('conclusion') in FAILED_CONCLUSIONS:
                return _pending('unbound external check is failed or pending')
            continue
        if not any(isinstance(pull, dict) and pull.get('number') == pr_number for pull in pulls):
            continue
        name = check.get('name')
        if not isinstance(name, str) or not isinstance(app.get('slug'), str) \
                or type(check.get('id')) is not int:
            return _pending('external check run is missing immutable context')
        key = (app['slug'], name)
        previous = latest_external.get(key)
        if previous is None or check['id'] > previous['id']:
            latest_external[key] = check
    for check in latest_external.values():
        if not _matching_pull_request_context(
            check, pr_number, head_sha, head_branch, target, base_sha,
        ):
            return _pending('external check run has ambiguous target context')
        if check.get('status') != 'completed':
            return _pending(f"check is still running: {check['name']}")
        if check.get('conclusion') in FAILED_CONCLUSIONS:
            return _pending(f"check failed: {check['name']}")

    statuses = _pages(github, f'{REPOSITORY_PATH}/commits/{head_sha}/status', 'statuses')
    if any(status.get('state') in ('failure', 'error') for status in statuses):
        return _pending('a commit status failed')
    if any(status.get('state') != 'success' for status in statuses):
        return _pending('a commit status is pending or unknown')
    return None

def _fixed_repository(pr: dict[str, Any]) -> bool:
    return all((pr.get(side) or {}).get('repo', {}).get('full_name') == f'{OWNER}/{REPO}' for side in ('head', 'base'))


def _hotfix_identity(
    pr: dict[str, Any], _target: str, bot_login: str, issue_number: int,
) -> str | None:
    """Identify the shared issue-scoped automation branch."""
    head = pr.get('head') if isinstance(pr.get('head'), dict) else {}
    branch = head.get('ref')
    match = SHARED_FIX_BRANCH.fullmatch(branch) if isinstance(branch, str) else None
    if (pr.get('user') or {}).get('login') != bot_login or match is None:
        return None
    if int(match[1]) != issue_number:
        return None
    identity_hash = match[2]
    return identity_hash if branch == branch_name_for(identity_hash, issue_number) else None


def _is_current_issue_branch(pr: dict[str, Any], issue_number: int) -> bool:
    head = pr.get('head') if isinstance(pr.get('head'), dict) else {}
    branch = head.get('ref')
    match = SHARED_FIX_BRANCH.fullmatch(branch) if isinstance(branch, str) else None
    return match is not None and int(match[1]) == issue_number


def _verify_peer_pull(
    github: Any, job: dict[str, Any], pins: dict[str, tuple[int, str]], peer_target: str,
    identity_hash: str, bot_login: str,
) -> tuple[bool, dict[str, str] | None]:
    """Validate the peer pull request; report whether it is already merged."""
    number, head_sha = pins[peer_target]
    try:
        peer = github.rest('GET', f'{REPOSITORY_PATH}/pulls/{number}')
    except Exception as error:  # noqa: BLE001 - an unavailable peer blocks the merge
        if getattr(error, 'status', None) in (404, 403, 410):
            return False, _blocked('peer pull request is unavailable')
        raise
    if not isinstance(peer, dict) or peer.get('number') != number or not _fixed_repository(peer):
        return False, _blocked('peer pull request is not against the configured repository')
    if (peer.get('base') or {}).get('ref') != peer_target:
        return False, _blocked('peer pull request targets an unexpected branch')
    if (peer.get('head') or {}).get('sha') != head_sha:
        return False, _blocked('peer pull request head moved after the merge was scheduled')
    if _hotfix_identity(peer, peer_target, bot_login, job['issueNumber']) != identity_hash:
        return False, _blocked('peer pull request is not the automation hotfix for this issue')
    if not _closes_tracked_issue(peer, job):
        return False, _blocked('peer pull request does not close exactly the tracked issue')
    if peer.get('merged') is True:
        if peer.get('state') != 'closed':
            return False, _blocked('peer pull request has inconsistent merge state')
        return True, None
    if peer.get('state') == 'open':
        return False, None
    if peer.get('state') == 'closed':
        return False, _blocked('peer pull request was closed without merging')
    return False, _blocked('peer pull request is in an unknown state')


def attempt_merge(github: Any, job: dict[str, Any], *, bot_login: str) -> dict[str, Any]:
    validate_merge_task(job)
    if not isinstance(bot_login, str) or not bot_login:
        raise ValueError('Invalid merge author configuration')
    target = job['baseBranch']
    pins = {
        branch: (pin['number'], pin['headSha'])
        for branch, pin in job['pullRequests'].items()
    }
    peer_target = PEER_BRANCH[target]
    pr = github.rest('GET', f"{REPOSITORY_PATH}/pulls/{job['pullNumber']}")
    if not isinstance(pr, dict) or pr.get('number') != job['pullNumber'] or not _fixed_repository(pr):
        return _blocked('pull request is not against the configured repository')
    if not _closes_tracked_issue(pr, job):
        return _blocked('pull request does not close exactly the tracked issue')
    identity_hash = _hotfix_identity(pr, target, bot_login, job['issueNumber'])
    if identity_hash is None:
        return _blocked('pull request branch or author is not the automation identity')
    peer_merged, peer_error = _verify_peer_pull(github, job, pins, peer_target, identity_hash, bot_login)
    if peer_error is not None:
        return peer_error
    if pr.get('merged'):
        if pr['base'].get('ref') == target and pr['head'].get('sha') == job['headSha']:
            return _merged(complete=peer_merged)
        return _blocked('pull request was merged under a different target or head')
    if pr.get('state') != 'open' or pr.get('draft') or pr['base'].get('ref') != target:
        return _blocked(f'pull request is not an open non-draft {target} pull request')
    if pr['head'].get('sha') != job['headSha']:
        return _blocked('pull request head moved after the merge was scheduled')
    if pr['base'].get('sha') != job['baseSha']:
        return _pending('pull request base moved after the merge was scheduled')
    if pr.get('mergeable') is False:
        return _blocked('pull request has merge conflicts')
    if target == 'develop' and not peer_merged:
        return _pending('develop waits until the production pull request is merged')
    ref = github.rest('GET', f'{REPOSITORY_PATH}/git/ref/heads/{target}')
    if ref.get('object', {}).get('sha') != job['baseSha']:
        return _pending(f'{target} advanced after the merge was scheduled; a fresh candidate is required')
    try:
        manifest = InvestigationQueue(github).get_publication(job['headSha'], target)
    except (ValueError, TypeError):
        return _blocked('candidate publication metadata is invalid or tampered')
    if manifest is None:
        return _blocked('candidate publication metadata is missing')
    try:
        digest = manifest_digest(manifest)
    except (ValueError, TypeError):
        return _blocked('candidate publication metadata is invalid')
    if digest != job['manifestDigest']:
        return _blocked('candidate publication digest does not match the scheduled job')
    is_current_branch = _is_current_issue_branch(pr, job['issueNumber'])
    if not is_current_branch or manifest.get('version') != 3:
        return _blocked('pull request branch and manifest versions do not match')
    expected_manifest = {
        'issueId': job['alert']['issueId'],
        'identityHash': identity_hash,
        'baseSha': job['baseSha'],
    }
    if manifest.get('version') == 3:
        expected_manifest['issueNumber'] = job['issueNumber']
    if not validate_manifest(manifest, expected_manifest)['valid']:
        return _blocked('candidate manifest is invalid')
    branch_base_sha = manifest.get('branchBaseSha', manifest['baseSha'])
    commit = github.rest('GET', f"{REPOSITORY_PATH}/commits/{job['headSha']}")
    parents = commit.get('parents') if isinstance(commit, dict) else None
    if (
        not isinstance(parents, list) or len(parents) != 1
        or not isinstance(parents[0], dict) or parents[0].get('sha') != branch_base_sha
    ):
        return _blocked('candidate commit does not originate from its pinned branch base')
    for problem in (
        lambda: _verify_changes(github, pr, manifest, job),
        lambda: _verify_checks(
            github, job['headSha'], pr['head']['ref'], job['pullNumber'], target, job['baseSha'],
        ),
    ):
        result = problem()
        if result:
            return result
    current = github.rest('GET', f"{REPOSITORY_PATH}/pulls/{job['pullNumber']}")
    if not _fixed_repository(current) or current.get('state') != 'open' or current.get('draft') or current.get('merged') or current['base'].get('ref') != target:
        return _blocked('pull request changed target or state before merge')
    if current['head'].get('sha') != job['headSha'] or _hotfix_identity(
        current, target, bot_login, job['issueNumber'],
    ) != identity_hash:
        return _blocked('pull request identity moved before merge')
    if not _closes_tracked_issue(current, job):
        return _blocked('pull request issue association changed before merge')
    current_peer_merged, current_peer_error = _verify_peer_pull(
        github, job, pins, peer_target, identity_hash, bot_login,
    )
    if current_peer_error is not None:
        return current_peer_error
    if target == 'develop' and not current_peer_merged:
        return _pending('develop waits until the production pull request is merged')
    current_ref = github.rest('GET', f'{REPOSITORY_PATH}/git/ref/heads/{target}')
    if current['base'].get('sha') != job['baseSha'] or current_ref.get('object', {}).get('sha') != job['baseSha']:
        return _pending(f'{target} advanced before merge; a fresh candidate is required')
    try:
        merged = github.rest('PUT', f"{REPOSITORY_PATH}/pulls/{job['pullNumber']}/merge", {'sha': job['headSha'], 'merge_method': 'merge'})
    except Exception as error:
        status = getattr(error, 'status', None)
        if status in (405, 409, 422):
            return _pending('GitHub branch protection rejected the merge')
        if status in (403, 404):
            return _blocked('GitHub denied the merge or the pull request is unavailable')
        raise
    if not merged.get('merged'):
        return _pending('GitHub did not confirm the merge')
    # The current merge is confirmed now; the peer was validated just before it.
    return _merged(complete=current_peer_merged)
