"""Merge only the exact candidate after the required CI checks succeed.

Each issue has two hotfix pull requests, one per release lane. ``production``
may merge as soon as its own gate passes; ``develop`` must wait until the
``production`` pull request is merged. Only a validated merge of the current
pull request whose scheduled peer is also confirmed merged reports
``complete``, which is what authorizes closing the issue.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any
from urllib.parse import quote

from .candidate import MAX_FILE_BYTES, MAX_TOTAL_BYTES, branch_name_for, identity_hash_for, manifest_digest, manifest_path_for, sha256, validate_manifest
from .github import OWNER, REPO, REPOSITORY_PATH
from .pull_requests import CLOSURE_REFERENCE
from .repository import TARGET_BRANCHES
from .task_payloads import validate_merge_task

PEER_BRANCH = {'production': 'develop', 'develop': 'production'}
HOTFIX_BRANCH = re.compile(rf'hotfix/({"|".join(map(re.escape, TARGET_BRANCHES))})/crashlytics-([0-9a-f]{{64}})')
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


def _verify_changes(github: Any, pr: dict[str, Any], manifest: dict[str, Any], path: str,
                    job: dict[str, Any]) -> dict[str, str] | None:
    files = _pages(github, f"{REPOSITORY_PATH}/pulls/{pr['number']}/files")
    expected = {file['path']: file for file in manifest['files']}
    expected[path] = None
    if len(files) != len(expected):
        return _blocked('pull request changes do not match the manifest')
    by_name = {}
    for file in files:
        name = file.get('filename')
        if not isinstance(name, str) or name in by_name or name not in expected or file.get('status') not in ('added', 'modified'):
            return _blocked('pull request changes a file outside the manifest')
        by_name[name] = file
    if by_name[path]['status'] != 'added' or not _read_file(github, path, job['baseSha']).get('missing'):
        return _blocked('manifest must be newly added on the pull request')
    total_bytes = 0
    for entry in manifest['files']:
        expected_status = 'added' if entry['beforeSha256'] is None else 'modified'
        if by_name[entry['path']]['status'] != expected_status:
            return _blocked('candidate file change status does not match the manifest')
        head = _read_file(github, entry['path'], job['headSha'])
        if head.get('missing') or head.get('invalid') or head['size'] > MAX_FILE_BYTES:
            return _blocked('candidate file is missing, unsupported or too large')
        total_bytes += head['size']
        if total_bytes > MAX_TOTAL_BYTES or sha256(head['bytes']) != entry['afterSha256']:
            return _blocked('candidate content does not match the manifest')
        base = _read_file(github, entry['path'], job['baseSha'])
        if entry['beforeSha256'] is None:
            if not base.get('missing'):
                return _blocked('new candidate file already exists on the base commit')
        elif base.get('missing') or base.get('invalid') or sha256(base['bytes']) != entry['beforeSha256']:
            return _blocked('candidate base content does not match the manifest')
    return None


def _verify_checks(github: Any, head_sha: str) -> dict[str, str] | None:
    runs = _pages(github, f'{REPOSITORY_PATH}/commits/{head_sha}/check-runs?filter=latest', 'check_runs')
    latest: dict[str, dict[str, Any]] = {}
    for run in runs:
        if run.get('head_sha') != head_sha or not isinstance(run.get('name'), str) or type(run.get('id')) is not int:
            return _blocked('check run does not identify the exact pull request head')
        previous = latest.get(run['name'])
        if previous is None or run['id'] > previous['id']:
            latest[run['name']] = run
    for name in REQUIRED_CHECKS:
        run = latest.get(name)
        if run is None:
            return _pending(f'required check has not reported yet: {name}')
        if (run.get('app') or {}).get('slug') != 'github-actions':
            return _blocked(f'required check has an unexpected publisher: {name}')
        if run.get('status') != 'completed':
            return _pending(f'required check is still running: {name}')
        if run.get('conclusion') != 'success':
            return _blocked(f'required check did not succeed: {name}')
    for name, run in latest.items():
        if run.get('conclusion') in FAILED_CONCLUSIONS:
            return _blocked(f'check failed: {name}')
        if run.get('status') != 'completed':
            return _pending(f'check is still running: {name}')
    statuses = _pages(github, f'{REPOSITORY_PATH}/commits/{head_sha}/status', 'statuses')
    if any(status.get('state') in ('failure', 'error') for status in statuses):
        return _blocked('a commit status failed')
    if any(status.get('state') != 'success' for status in statuses):
        return _pending('a commit status is pending or unknown')
    return None


def _fixed_repository(pr: dict[str, Any]) -> bool:
    return all((pr.get(side) or {}).get('repo', {}).get('full_name') == f'{OWNER}/{REPO}' for side in ('head', 'base'))


def _hotfix_identity(pr: dict[str, Any], target: str, bot_login: str) -> str | None:
    """The identity hash pinned by this exact automation hotfix branch."""
    head = pr.get('head') if isinstance(pr.get('head'), dict) else {}
    branch = head.get('ref')
    match = HOTFIX_BRANCH.fullmatch(branch) if isinstance(branch, str) else None
    if match is None or match[1] != target or branch != branch_name_for(match[2], target):
        return None
    if (pr.get('user') or {}).get('login') != bot_login:
        return None
    return match[2]


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
    if _hotfix_identity(peer, peer_target, bot_login) != identity_hash:
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
    identity_hash = identity_hash_for(job['alert']['issueId'])
    if _hotfix_identity(pr, target, bot_login) != identity_hash:
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
    path = manifest_path_for(identity_hash)
    file = _read_file(github, path, job['headSha'])
    if file.get('missing') or file.get('invalid') or file['size'] > MAX_FILE_BYTES:
        return _blocked('candidate manifest is missing, unsupported or too large')
    try:
        manifest = json.loads(file['bytes'])
        digest = manifest_digest(manifest)
    except (ValueError, TypeError, UnicodeError):
        return _blocked('candidate manifest is not valid JSON')
    if digest != job['manifestDigest']:
        return _blocked('candidate manifest digest does not match the trusted record')
    if not validate_manifest(manifest, {
        'issueId': job['alert']['issueId'], 'identityHash': identity_hash, 'baseSha': job['baseSha'],
    })['valid']:
        return _blocked('candidate manifest is invalid')
    for problem in (
        lambda: _verify_changes(github, pr, manifest, path, job),
        lambda: _verify_checks(github, job['headSha']),
    ):
        result = problem()
        if result:
            return result
    current = github.rest('GET', f"{REPOSITORY_PATH}/pulls/{job['pullNumber']}")
    if not _fixed_repository(current) or current.get('state') != 'open' or current.get('draft') or current.get('merged') or current['base'].get('ref') != target:
        return _blocked('pull request changed target or state before merge')
    if current['head'].get('sha') != job['headSha'] or _hotfix_identity(current, target, bot_login) != identity_hash:
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
