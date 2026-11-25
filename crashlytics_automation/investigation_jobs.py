"""Durable investigation state in an automation-repository metadata ref, not app branches."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import CrashAlert
from .repository import REPOSITORY, STATE_REPOSITORY_PATH, STATE_REFERENCE, TARGET_BRANCHES
from .task_payloads import parse_alert_payload

POLICY_VERSION = 2
MAX_JOB_BYTES = 512 * 1024
LEASE_MINUTES = 50
_STATUSES = {'queued', 'running', 'delivering', 'merging', 'complete', 'manual'}
_SHA = re.compile(r'[0-9a-f]{40}')


class JobConflict(RuntimeError):
    """Another producer/worker changed this investigation; never overwrite it."""


def job_id(alert: CrashAlert) -> str:
    identity = f'{REPOSITORY}/{alert.issue_id}/{alert.app_version}/{POLICY_VERSION}'
    return hashlib.sha256(identity.encode()).hexdigest()


def new_job(alert: CrashAlert, evidence: dict[str, Any], issue_number: int) -> dict[str, Any]:
    return {
        'version': POLICY_VERSION,
        'id': job_id(alert),
        'status': 'queued',
        'alert': alert.to_payload(),
        'issueNumber': issue_number,
        'evidence': evidence,
        'branches': {},
        'analyses': {},
        'branchBases': {},
        'attempts': {},
    }


def validate_job(job: Any) -> None:
    if not isinstance(job, dict) or job.get('version') != POLICY_VERSION:
        raise ValueError('Invalid investigation policy version')
    alert = parse_alert_payload(job.get('alert'))
    if job.get('id') != job_id(alert) or job.get('status') not in _STATUSES:
        raise ValueError('Invalid investigation identity or state')
    if type(job.get('issueNumber')) is not int or job['issueNumber'] < 1:
        raise ValueError('Invalid investigation issue')
    evidence = job.get('evidence')
    if not isinstance(evidence, dict) or evidence.get('status') != 'ready':
        raise ValueError('Investigation requires exported event evidence')
    for name in ('branches', 'analyses', 'attempts'):
        if not isinstance(job.get(name), dict) or not set(job[name]).issubset(TARGET_BRANCHES):
            raise ValueError('Invalid investigation target state')
    for attempts in job['attempts'].values():
        if type(attempts) is not int or not 0 <= attempts <= 3:
            raise ValueError('Invalid investigation attempt count')
    deliveries = job.get('deliveryAttempts', 0)
    if type(deliveries) is not int or not 0 <= deliveries <= 3:
        raise ValueError('Invalid merge delivery attempt count')
    for target, fix in job['branches'].items():
        if not isinstance(fix, dict) or fix.get('baseBranch') != target:
            raise ValueError('Invalid investigation publication')
        if type(fix.get('pullNumber')) is not int or fix['pullNumber'] < 1:
            raise ValueError('Invalid investigation pull request')
        for field, size in (('headSha', 40), ('baseSha', 40), ('manifestDigest', 64)):
            if not isinstance(fix.get(field), str) or re.fullmatch(r'[0-9a-f]{' + str(size) + '}', fix[field]) is None:
                raise ValueError('Invalid investigation publication digest')
    origins = job.get('branchBases', {})
    if not isinstance(origins, dict) or any(
        branch not in TARGET_BRANCHES or not isinstance(sha, str) or _SHA.fullmatch(sha) is None
        for branch, sha in origins.items()
    ):
        raise ValueError('Invalid production branch origin')
    release = job.get('releaseSha')
    if release is not None and (not isinstance(release, str) or _SHA.fullmatch(release) is None):
        raise ValueError('Invalid investigation release SHA')


def _available(job: dict[str, Any], now: datetime) -> bool:
    if job['status'] in ('manual', 'merging', 'complete') and job.get('reportPending') is True:
        return True
    if job['status'] in ('queued', 'delivering'):
        return True
    if job['status'] != 'running':
        return False
    started = job.get('startedAt')
    try:
        moment = datetime.fromisoformat(started.replace('Z', '+00:00'))
        return moment.utcoffset() is not None and moment + timedelta(minutes=LEASE_MINUTES) < now
    except (AttributeError, TypeError, ValueError):
        raise ValueError('Running investigation has no valid lease') from None


class InvestigationQueue:
    def __init__(self, github: Any) -> None:
        self.github = github

    def _head(self) -> str | None:
        try:
            result = self.github.rest('GET', f'{STATE_REPOSITORY_PATH}/git/ref/{STATE_REFERENCE.removeprefix("refs/")}')
        except Exception as error:
            if getattr(error, 'status', None) == 404:
                return None
            raise
        value = (result.get('object') or {}).get('sha') if isinstance(result, dict) else None
        if not isinstance(value, str) or _SHA.fullmatch(value) is None:
            raise ValueError('Invalid investigation metadata reference')
        return value

    def _entries(self, head: str | None) -> dict[str, str]:
        if head is None:
            return {}
        result = self.github.rest('GET', f'{STATE_REPOSITORY_PATH}/git/trees/{head}?recursive=1')
        if not isinstance(result, dict) or result.get('truncated') or not isinstance(result.get('tree'), list):
            raise RuntimeError('Incomplete investigation queue listing')
        return {
            entry['path']: entry['sha']
            for entry in result['tree']
            if isinstance(entry, dict) and entry.get('type') == 'blob'
            and isinstance(entry.get('path'), str)
            and re.fullmatch(r'(?:jobs|pending|active)/[0-9a-f]{64}\.json', entry['path'])
            and isinstance(entry.get('sha'), str) and _SHA.fullmatch(entry['sha'])
        }

    def _read(self, identity: str, blob_sha: str) -> dict[str, Any]:
        result = self.github.rest('GET', f'{STATE_REPOSITORY_PATH}/git/blobs/{blob_sha}')
        if not isinstance(result, dict) or result.get('encoding') != 'base64':
            raise ValueError('Invalid investigation state blob')
        encoded = result.get('content')
        if not isinstance(encoded, str) or len(encoded) > MAX_JOB_BYTES * 2:
            raise ValueError('Investigation state is too large')
        raw = base64.b64decode(encoded.replace('\n', ''), validate=True)
        if len(raw) > MAX_JOB_BYTES:
            raise ValueError('Investigation state is too large')
        job = json.loads(raw)
        validate_job(job)
        if job['id'] != identity:
            raise ValueError('Investigation blob identity mismatch')
        job['_blobSha'] = blob_sha
        return job

    def get(self, alert: CrashAlert) -> dict[str, Any] | None:
        identity = job_id(alert)
        blob = self._entries(self._head()).get(f'jobs/{identity}.json')
        return self._read(identity, blob) if blob is not None else None

    def active(self) -> list[dict[str, Any]]:
        entries = self._entries(self._head())
        return [self._read(path[7:-5], blob) for path, blob in entries.items() if path.startswith('active/')]

    def pending(self) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        entries = self._entries(self._head())
        jobs = (self._read(path[8:-5], blob) for path, blob in entries.items() if path.startswith('pending/'))
        return sorted((job for job in jobs if _available(job, now)),
                      key=lambda job: (job['alert']['time'], job['id']))

    def put(self, job: dict[str, Any]) -> None:
        validate_job(job)
        payload = {key: value for key, value in job.items() if key != '_blobSha'}
        raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > MAX_JOB_BYTES:
            raise ValueError('Investigation state is too large')
        expected = job.get('_blobSha')
        blob = self.github.rest('POST', f'{STATE_REPOSITORY_PATH}/git/blobs', {
            'content': base64.b64encode(raw).decode('ascii'), 'encoding': 'base64',
        })
        blob_sha = blob.get('sha') if isinstance(blob, dict) else None
        if not isinstance(blob_sha, str) or _SHA.fullmatch(blob_sha) is None:
            raise ValueError('Invalid new investigation blob')
        # Fast-forward-only updates and a per-job blob comparison prevent lost updates.
        for _ in range(3):
            head = self._head()
            entries = self._entries(head)
            if entries.get(f'jobs/{job["id"]}.json') != expected:
                raise JobConflict('Investigation changed concurrently')
            changed = [{
                'path': f'jobs/{job["id"]}.json', 'mode': '100644', 'type': 'blob', 'sha': blob_sha,
            }]
            for prefix, present in (
                ('active', job['status'] not in ('manual', 'complete')),
                ('pending', job['status'] in ('queued', 'running', 'delivering') or job.get('reportPending') is True),
            ):
                index_path = f'{prefix}/{job["id"]}.json'
                if present:
                    changed.append({'path': index_path, 'mode': '100644', 'type': 'blob', 'sha': blob_sha})
                elif index_path in entries:
                    changed.append({'path': index_path, 'mode': '100644', 'type': 'blob', 'sha': None})
            tree_body: dict[str, Any] = {'tree': changed}
            if head is not None:
                parent = self.github.rest('GET', f'{STATE_REPOSITORY_PATH}/git/commits/{head}')
                tree_body['base_tree'] = parent['tree']['sha']
            tree = self.github.rest('POST', f'{STATE_REPOSITORY_PATH}/git/trees', tree_body)
            commit = self.github.rest('POST', f'{STATE_REPOSITORY_PATH}/git/commits', {
                'message': f'Investigation {job["id"][:12]}: {job["status"]}',
                'tree': tree['sha'], 'parents': [head] if head else [],
            })
            try:
                if head is None:
                    self.github.rest('POST', f'{STATE_REPOSITORY_PATH}/git/refs', {
                        'ref': STATE_REFERENCE, 'sha': commit['sha'],
                    })
                else:
                    self.github.rest('PATCH', f'{STATE_REPOSITORY_PATH}/git/refs/{STATE_REFERENCE.removeprefix("refs/")}', {
                        'sha': commit['sha'], 'force': False,
                    })
            except Exception as error:
                if getattr(error, 'status', None) in (409, 422):
                    continue
                raise
            job['_blobSha'] = blob_sha
            return
        raise JobConflict('Investigation metadata reference changed concurrently')
