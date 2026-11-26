"""Durable investigation and publication metadata in a non-branch Git ref."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import CrashAlert
from .repository import REPOSITORY, REPOSITORY_PATH, STATE_REFERENCE, TARGET_BRANCHES
from .task_payloads import parse_alert_payload

POLICY_VERSION = 2
PROPOSAL_VERSION = 1
PUBLICATION_VERSION = 1
MAX_PUBLICATION_BYTES = 64 * 1024
DEFAULT_ATTEMPT_LIMIT = 3
APPROVED_ATTEMPT_LIMIT = DEFAULT_ATTEMPT_LIMIT + 1
MAX_JOB_BYTES = 512 * 1024
MAX_PROPOSAL_BYTES = 2 * 1024 * 1024
MAX_VERIFICATION_ATTEMPTS = 3
LEASE_MINUTES = 65
_STATUSES = {'queued', 'running', 'delivering', 'merging', 'complete', 'manual'}
_SHA = re.compile(r'[0-9a-f]{40}')
_SHA64 = re.compile(r'[0-9a-f]{64}')


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
        'attemptLimits': {},
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
    for name in ('branches', 'analyses', 'attempts', 'verificationAttempts'):
        value = job.get(name, {})
        if not isinstance(value, dict) or not set(value).issubset(TARGET_BRANCHES):
            raise ValueError('Invalid investigation target state')
    for attempts in job.get('verificationAttempts', {}).values():
        if type(attempts) is not int or not 0 <= attempts <= MAX_VERIFICATION_ATTEMPTS:
            raise ValueError('Invalid verification attempt count')
    proposal_refs = job.get('proposals', {})
    if not isinstance(proposal_refs, dict) or not set(proposal_refs).issubset(TARGET_BRANCHES):
        raise ValueError('Invalid investigation proposals')
    if any(not isinstance(sha, str) or _SHA.fullmatch(sha) is None for sha in proposal_refs.values()):
        raise ValueError('Invalid investigation proposal pointer')
    if 'verificationOnly' in job and type(job['verificationOnly']) is not bool:
        raise ValueError('Invalid verification-only state')
    if 'verificationResumeRequired' in job and type(job['verificationResumeRequired']) is not bool:
        raise ValueError('Invalid verification resume state')
    limits = job.get('attemptLimits', {})
    if (
        not isinstance(limits, dict) or not set(limits).issubset(TARGET_BRANCHES)
        or any(type(limit) is not int or limit != APPROVED_ATTEMPT_LIMIT for limit in limits.values())
    ):
        raise ValueError('Invalid approved investigation limit')
    for target, attempts in job['attempts'].items():
        if type(attempts) is not int or not 0 <= attempts <= limits.get(target, DEFAULT_ATTEMPT_LIMIT):
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


def proposal_envelope(
    job: dict[str, Any], target: str, decision: dict[str, Any], *,
    release_sha: str, branch_base_sha: str, base_sha: str,
) -> dict[str, Any]:
    """Encode the same host-pinned proposal for durable storage and recovery artifacts."""
    return {
        'version': PROPOSAL_VERSION,
        'identity': {'jobId': job['id'], 'target': target, 'releaseSha': release_sha,
                     'branchBaseSha': branch_base_sha, 'baseSha': base_sha},
        'proposal': {key: decision[key] for key in (
            'decision', 'analysis', 'reason', 'sourcePath', 'sourceLine', 'files',
        )},
    }


class InvestigationQueue:
    def __init__(self, github: Any) -> None:
        self.github = github
        self._written_head: str | None = None

    def _head(self) -> str | None:
        try:
            result = self.github.rest('GET', f'{REPOSITORY_PATH}/git/ref/{STATE_REFERENCE.removeprefix("refs/")}')
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
        result = self.github.rest('GET', f'{REPOSITORY_PATH}/git/trees/{head}?recursive=1')
        if not isinstance(result, dict) or result.get('truncated') or not isinstance(result.get('tree'), list):
            raise RuntimeError('Incomplete investigation queue listing')
        return {
            entry['path']: entry['sha']
            for entry in result['tree']
            if isinstance(entry, dict) and entry.get('type') == 'blob'
            and isinstance(entry.get('path'), str)
            and re.fullmatch(r'(?:(?:jobs|pending|active|proposals)/[0-9a-f]{64}\.json|publications/[0-9a-f]{40}\.json)', entry['path'])
            and isinstance(entry.get('sha'), str) and _SHA.fullmatch(entry['sha'])
        }

    def _read(self, identity: str, blob_sha: str) -> dict[str, Any]:
        result = self.github.rest('GET', f'{REPOSITORY_PATH}/git/blobs/{blob_sha}')
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

    @staticmethod
    def _proposal_path(job: dict[str, Any], target: str) -> str:
        digest = hashlib.sha256(f'{job["id"]}/{target}'.encode()).hexdigest()
        return f'proposals/{digest}.json'

    def save_proposal(
        self, job: dict[str, Any], target: str, decision: dict[str, Any], *,
        release_sha: str, branch_base_sha: str, base_sha: str,
    ) -> dict[str, Any]:
        from .candidate import SHA64, is_allowed_source_path, is_allowed_test_path
        validate_job(job)
        if target not in TARGET_BRANCHES or any(
            not isinstance(value, str) or _SHA.fullmatch(value) is None
            for value in (release_sha, branch_base_sha, base_sha)
        ):
            raise ValueError('Invalid proposal identity')
        if job.get('releaseSha') != release_sha or job.get('branchBases', {}).get(target) != branch_base_sha:
            raise ValueError('Proposal does not match pinned investigation identity')
        if not isinstance(decision, dict) or decision.get('decision') != 'fix':
            raise ValueError('Only fix proposals can be checkpointed')
        files = decision.get('files')
        if not isinstance(files, list) or not files or len(files) > 24:
            raise ValueError('Invalid proposal files')
        identity_hash = hashlib.sha256(
            f'{REPOSITORY}/{parse_alert_payload(job["alert"]).issue_id}/{release_sha}'.encode()
        ).hexdigest()
        normalized, total, seen, kinds = [], 0, set(), set()
        for item in files:
            if not isinstance(item, dict) or set(item) != {
                'path', 'kind', 'beforeSha256', 'afterSha256', 'content',
            }:
                raise ValueError('Invalid normalized proposal file')
            path, content = item['path'], item['content']
            kind = item['kind']
            if not isinstance(path, str) or not isinstance(content, str) or (
                kind == 'source' and not is_allowed_source_path(path)
            ) or (kind == 'test' and not is_allowed_test_path(path, identity_hash)) or kind not in ('source', 'test'):
                raise ValueError('Proposal contains a disallowed file')
            if path in seen:
                raise ValueError('Duplicate proposal path')
            seen.add(path)
            kinds.add(kind)
            data = content.encode('utf-8')
            total += len(data)
            digest = hashlib.sha256(data).hexdigest()
            if len(data) > 256 * 1024 or total > 1024 * 1024 or item['afterSha256'] != digest or (
                kind == 'source' and (not isinstance(item['beforeSha256'], str)
                                      or SHA64.fullmatch(item['beforeSha256']) is None)
            ) or (kind == 'test' and item['beforeSha256'] is not None):
                raise ValueError('Invalid proposal file hash or size')
            normalized.append(dict(item))
        if kinds != {'source', 'test'}:
            raise ValueError('Proposal must include a source change and regression test')
        if not is_allowed_source_path(decision.get('sourcePath')) or (
            type(decision.get('sourceLine')) is not int or decision['sourceLine'] < 1
        ) or not isinstance(decision.get('analysis'), str) or not decision['analysis'].strip() or (
            not isinstance(decision.get('reason'), str) or not decision['reason'].strip()
        ):
            raise ValueError('Proposal has no complete source-anchored analysis')
        envelope = proposal_envelope(
            job, target, {**decision, 'files': normalized}, release_sha=release_sha,
            branch_base_sha=branch_base_sha, base_sha=base_sha,
        )
        raw = json.dumps(envelope, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > MAX_PROPOSAL_BYTES:
            raise ValueError('Proposal is too large')
        blob = self.github.rest('POST', f'{REPOSITORY_PATH}/git/blobs', {
            'content': base64.b64encode(raw).decode('ascii'), 'encoding': 'base64',
        })
        sha = blob.get('sha') if isinstance(blob, dict) else None
        if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
            raise ValueError('Invalid proposal blob')
        previous = job.setdefault('proposals', {}).get(target)
        job['proposals'][target] = sha
        try:
            self.put(job)
        except Exception:
            if previous is None:
                job['proposals'].pop(target, None)
            else:
                job['proposals'][target] = previous
            raise
        return envelope

    def get_proposal(self, job: dict[str, Any], target: str) -> dict[str, Any] | None:
        from .candidate import SHA64, is_allowed_source_path, is_allowed_test_path
        validate_job(job)
        if target not in TARGET_BRANCHES:
            raise ValueError('Invalid proposal target')
        sha = job.get('proposals', {}).get(target)
        if sha is None:
            return None
        if not isinstance(sha, str) or _SHA.fullmatch(sha) is None or (
            self._entries(self._written_head or self._head()).get(self._proposal_path(job, target)) != sha
        ):
            raise ValueError('Proposal pointer is malformed or unreachable')
        result = self.github.rest('GET', f'{REPOSITORY_PATH}/git/blobs/{sha}')
        encoded = result.get('content') if isinstance(result, dict) and result.get('encoding') == 'base64' else None
        if not isinstance(encoded, str) or len(encoded) > MAX_PROPOSAL_BYTES * 2:
            raise ValueError('Invalid proposal blob')
        raw = base64.b64decode(encoded.replace('\n', ''), validate=True)
        if len(raw) > MAX_PROPOSAL_BYTES:
            raise ValueError('Proposal is too large')
        envelope = json.loads(raw)
        identity = envelope.get('identity') if isinstance(envelope, dict) else None
        if not isinstance(envelope, dict) or type(envelope.get('version')) is not int or envelope['version'] != PROPOSAL_VERSION or (
            set(envelope) != {'version', 'identity', 'proposal'} or not isinstance(identity, dict)
        ):
            raise ValueError('Stale or malformed proposal identity')
        expected = {'jobId': job['id'], 'target': target, 'releaseSha': job.get('releaseSha'),
                    'branchBaseSha': job.get('branchBases', {}).get(target)}
        if set(identity) != {'jobId', 'target', 'releaseSha', 'branchBaseSha', 'baseSha'} or (
            any(identity.get(key) != value for key, value in expected.items())
            or not isinstance(identity.get('baseSha'), str) or _SHA.fullmatch(identity['baseSha']) is None
        ):
            raise ValueError('Stale or malformed proposal identity')
        proposal = envelope.get('proposal')
        if not isinstance(proposal, dict) or set(proposal) != {
            'decision', 'analysis', 'reason', 'sourcePath', 'sourceLine', 'files',
        } or proposal.get('decision') != 'fix' or (
            not isinstance(proposal.get('analysis'), str) or not proposal['analysis'].strip()
            or not isinstance(proposal.get('reason'), str) or not proposal['reason'].strip()
            or not is_allowed_source_path(proposal.get('sourcePath'))
            or type(proposal.get('sourceLine')) is not int or proposal['sourceLine'] < 1
        ):
            raise ValueError('Malformed proposal')
        alert = parse_alert_payload(job['alert'])
        identity_hash = hashlib.sha256(
            f'{REPOSITORY}/{alert.issue_id}/{identity["releaseSha"]}'.encode()
        ).hexdigest()
        files, total = proposal.get('files'), 0
        if not isinstance(files, list) or not files or len(files) > 24:
            raise ValueError('Malformed proposal files')
        seen, kinds = set(), set()
        for item in files:
            if not isinstance(item, dict) or set(item) != {
                'path', 'kind', 'beforeSha256', 'afterSha256', 'content',
            } or not isinstance(item.get('content'), str) or not isinstance(item.get('path'), str):
                raise ValueError('Malformed proposal file')
            data = item['content'].encode('utf-8')
            total += len(data)
            kind = item.get('kind')
            allowed = is_allowed_source_path(item.get('path')) if kind == 'source' else (
                is_allowed_test_path(item.get('path'), identity_hash) if kind == 'test' else False
            )
            if item['path'] in seen:
                raise ValueError('Duplicate proposal path')
            seen.add(item['path'])
            kinds.add(kind)
            before = item.get('beforeSha256')
            if not allowed or len(data) > 256 * 1024 or total > 1024 * 1024 or (
                hashlib.sha256(data).hexdigest() != item.get('afterSha256')
            ) or (kind == 'source' and (not isinstance(before, str) or SHA64.fullmatch(before) is None)) or (
                kind == 'test' and before is not None
            ):
                raise ValueError('Malformed proposal file hash or size')
        if kinds != {'source', 'test'}:
            raise ValueError('Proposal must include a source change and regression test')
        return envelope

    def _read_publication(self, head_sha: str, blob_sha: str) -> dict[str, Any]:
        from .candidate import manifest_digest, validate_manifest
        blob = self.github.rest('GET', f'{REPOSITORY_PATH}/git/blobs/{blob_sha}')
        encoded = blob.get('content') if isinstance(blob, dict) and blob.get('encoding') == 'base64' else None
        if not isinstance(encoded, str) or len(encoded) > MAX_PUBLICATION_BYTES * 2:
            raise ValueError('Invalid publication record blob')
        raw = base64.b64decode(encoded.replace('\n', ''), validate=True)
        if len(raw) > MAX_PUBLICATION_BYTES:
            raise ValueError('Publication record is too large')
        record = json.loads(raw.decode('utf-8'))
        if not isinstance(record, dict) or set(record) != {'version', 'headSha', 'manifest', 'manifestDigest'}:
            raise ValueError('Malformed publication record')
        if type(record['version']) is not int or record['version'] != PUBLICATION_VERSION or record['headSha'] != head_sha:
            raise ValueError('Publication record is bound to a different head')
        manifest = record['manifest']
        if not validate_manifest(manifest)['valid'] or record['manifestDigest'] != manifest_digest(manifest):
            raise ValueError('Publication record content or digest is invalid')
        return manifest

    def get_publication(self, head_sha: str) -> dict[str, Any] | None:
        if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None:
            raise ValueError('Invalid publication head')
        blob = self._entries(self._written_head or self._head()).get(f'publications/{head_sha}.json')
        return self._read_publication(head_sha, blob) if blob is not None else None

    def put_publication(self, head_sha: str, manifest: dict[str, Any]) -> None:
        from .candidate import canonical_json, manifest_digest, validate_manifest
        if not isinstance(head_sha, str) or _SHA.fullmatch(head_sha) is None or not validate_manifest(manifest)['valid']:
            raise ValueError('Invalid publication identity or manifest')
        raw = canonical_json({
            'version': PUBLICATION_VERSION, 'headSha': head_sha, 'manifest': manifest,
            'manifestDigest': manifest_digest(manifest),
        }).encode('utf-8')
        if len(raw) > MAX_PUBLICATION_BYTES:
            raise ValueError('Publication record is too large')
        blob = self.github.rest('POST', f'{REPOSITORY_PATH}/git/blobs', {
            'content': base64.b64encode(raw).decode('ascii'), 'encoding': 'base64',
        })
        blob_sha = blob.get('sha') if isinstance(blob, dict) else None
        if not isinstance(blob_sha, str) or _SHA.fullmatch(blob_sha) is None:
            raise ValueError('Invalid publication blob SHA')
        path = f'publications/{head_sha}.json'
        for attempt in range(3):
            head = self._written_head if attempt == 0 and self._written_head is not None else self._head()
            existing = self._entries(head).get(path)
            if existing is not None:
                if self._read_publication(head_sha, existing) != manifest:
                    raise JobConflict('Publication head already has a different verification record')
                return
            try:
                self._written_head = self._advance_head(
                    head, [{'path': path, 'mode': '100644', 'type': 'blob', 'sha': blob_sha}],
                    f'Publication {head_sha[:12]}',
                )
                return
            except Exception as error:
                if getattr(error, 'status', None) in (409, 422):
                    self._written_head = None
                    continue
                raise
        raise JobConflict('Publication metadata reference changed concurrently')

    def _advance_head(self, head: str | None, changes: list[dict[str, Any]], message: str) -> str:
        tree_body: dict[str, Any] = {'tree': changes}
        if head is not None:
            parent = self.github.rest('GET', f'{REPOSITORY_PATH}/git/commits/{head}')
            tree_body['base_tree'] = parent['tree']['sha']
        tree = self.github.rest('POST', f'{REPOSITORY_PATH}/git/trees', tree_body)
        commit = self.github.rest('POST', f'{REPOSITORY_PATH}/git/commits', {
            'message': message, 'tree': tree['sha'], 'parents': [head] if head else [],
        })
        sha = commit.get('sha') if isinstance(commit, dict) else None
        if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
            raise ValueError('Invalid metadata commit SHA')
        if head is None:
            self.github.rest('POST', f'{REPOSITORY_PATH}/git/refs', {'ref': STATE_REFERENCE, 'sha': sha})
        else:
            self.github.rest('PATCH', f'{REPOSITORY_PATH}/git/refs/{STATE_REFERENCE.removeprefix("refs/")}', {
                'sha': sha, 'force': False,
            })
        return sha

    def put(self, job: dict[str, Any]) -> None:
        validate_job(job)
        payload = {key: value for key, value in job.items() if key != '_blobSha'}
        raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > MAX_JOB_BYTES:
            raise ValueError('Investigation state is too large')
        expected = job.get('_blobSha')
        blob = self.github.rest('POST', f'{REPOSITORY_PATH}/git/blobs', {
            'content': base64.b64encode(raw).decode('ascii'), 'encoding': 'base64',
        })
        blob_sha = blob.get('sha') if isinstance(blob, dict) else None
        if not isinstance(blob_sha, str) or _SHA.fullmatch(blob_sha) is None:
            raise ValueError('Invalid new investigation blob')
        # Fast-forward-only updates and a per-job blob comparison prevent lost updates.
        for attempt in range(3):
            head = self._written_head if attempt == 0 and self._written_head is not None else self._head()
            entries = self._entries(head)
            if head is not None and head == self._written_head and entries.get(f'jobs/{job["id"]}.json') != expected:
                self._written_head = None
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
            for proposal_target, proposal_sha in job.get('proposals', {}).items():
                changed.append({
                    'path': self._proposal_path(job, proposal_target), 'mode': '100644',
                    'type': 'blob', 'sha': proposal_sha,
                })
            try:
                new_head = self._advance_head(
                    head, changed, f'Investigation {job["id"][:12]}: {job["status"]}',
                )
            except Exception as error:
                if getattr(error, 'status', None) in (409, 422):
                    self._written_head = None
                    continue
                raise
            job['_blobSha'] = blob_sha
            self._written_head = new_head
            return
        raise JobConflict('Investigation metadata reference changed concurrently')
