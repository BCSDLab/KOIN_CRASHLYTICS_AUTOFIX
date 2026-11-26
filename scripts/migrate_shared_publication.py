"""One-time #1789 publication/metadata cutover; never investigates or merges."""
from __future__ import annotations

import base64
import copy
import json
import os
import re

from crashlytics_automation.candidate import branch_name_for, manifest_digest, sha256, validate_manifest
from crashlytics_automation.github import GitHubError
from crashlytics_automation.investigation_jobs import InvestigationQueue
from crashlytics_automation.models import ManualReview
from crashlytics_automation.pull_requests import branch_head_sha, find_branch_head, read_repository_file, resume_fix_pull_request
from crashlytics_automation.repository import REPOSITORY_PATH, TARGET_BRANCHES
from crashlytics_automation.task_payloads import parse_alert_payload
from crashlytics_automation.worker import runtime_config, worker_github

JOB_ID = '512ac5b6c09e2591aea9344697da891ad80d9736643a70ed9cc6ffece07a2e42'
PRODUCTION = '41071baf8465e0083f156da61a80b30296c63715'
SHARED_HEAD = 'eff91903aa817a0c5f67211c6e34f16a1b07096e'
OLD_HEADS = {'production': SHARED_HEAD, 'develop': '68772e5e1d1465dbb892d5b37aafdde77c73be6f'}
OLD_PULLS = {'production': 1793, 'develop': 1794}


def read_json_blob(github, blob_sha, maximum):
    blob = github.rest('GET', f'{REPOSITORY_PATH}/git/blobs/{blob_sha}')
    if blob.get('encoding') != 'base64' or not isinstance(blob.get('content'), str):
        raise ValueError('Migration source is not a bounded Git blob')
    raw = base64.b64decode(blob['content'].replace('\n', ''), validate=True)
    if len(raw) > maximum:
        raise ValueError('Migration source exceeds its bound')
    return json.loads(raw.decode('utf-8'))


def main():
    config = runtime_config()
    github = worker_github()
    queue = InvestigationQueue(github)
    snapshot = os.environ['SOURCE_METADATA_SHA']
    if re.fullmatch(r'[0-9a-f]{40}', snapshot) is None:
        raise ValueError('Migration requires the immutable pre-cutover metadata commit')
    entries = queue._entries(snapshot)
    source_job = read_json_blob(github, entries[f'jobs/{JOB_ID}.json'], 512 * 1024)
    job = queue.get(parse_alert_payload(source_job['alert']))
    if job is None or job['id'] != JOB_ID or job['issueNumber'] != 1789 or job['status'] != 'manual':
        raise ValueError('Only the existing held #1789 publication may be migrated')
    if job['attempts'] != {'production': 4} or job['attemptLimits'] != {'production': 4} or (
        job.get('verificationAttempts') != {'production': 3, 'develop': 1} or job.get('reportPending') is True
    ):
        raise ValueError('Held incident budget/report state changed')
    before = copy.deepcopy(job)
    if branch_head_sha(github, 'production') != PRODUCTION:
        raise ValueError('Production moved; do not reuse the old verification on another tree')

    legacy = {}
    for path, blob_sha in entries.items():
        match = re.fullmatch(r'publications/([0-9a-f]{40})\.json', path)
        if match is None:
            continue
        record = read_json_blob(github, blob_sha, 64 * 1024)
        head = match[1]
        if set(record) != {'version', 'headSha', 'manifest', 'manifestDigest'} or record['version'] != 1 or record['headSha'] != head:
            raise ValueError('Invalid legacy publication envelope')
        manifest = record['manifest']
        if not validate_manifest(manifest)['valid'] or record['manifestDigest'] != manifest_digest(manifest):
            raise ValueError('Invalid legacy publication digest')
        legacy[head] = (path, blob_sha, manifest)
    if not set(OLD_HEADS.values()).issubset(legacy):
        raise ValueError('Pinned legacy verification records are missing')
    manifests = {target: legacy[head][2] for target, head in OLD_HEADS.items()}
    common = [{key: value for key, value in manifests[target].items() if key != 'baseSha'} for target in TARGET_BRANCHES]
    if common[0] != common[1] or manifests['production']['branchBaseSha'] != PRODUCTION:
        raise ValueError('The two verified old publications do not contain the same source fix')

    mapped = {head: set() for head in legacy}
    for path, blob_sha in entries.items():
        if not re.fullmatch(r'jobs/[0-9a-f]{64}\.json', path):
            continue
        registered = read_json_blob(github, blob_sha, 512 * 1024)
        for target, fix in registered.get('branches', {}).items():
            head = fix.get('headSha')
            if head not in legacy:
                continue
            manifest = legacy[head][2]
            if target not in TARGET_BRANCHES or fix.get('baseSha') != manifest['baseSha'] or (
                fix.get('manifestDigest') != manifest_digest(manifest)
                or registered.get('issueNumber') != manifest.get('issueNumber')
            ):
                raise ValueError('Legacy publication target binding is ambiguous')
            mapped[head].add(target)
    if any(not targets for targets in mapped.values()):
        raise ValueError('An unregistered legacy publication cannot be assigned a target')

    old_pulls = {}
    for target, number in OLD_PULLS.items():
        pull = github.rest('GET', f'{REPOSITORY_PATH}/pulls/{number}')
        if pull.get('merged') or pull['head']['sha'] != OLD_HEADS[target] or pull['base']['ref'] != target or (
            pull.get('user', {}).get('login') != config['botLogin']
        ):
            raise ValueError('Old publication identity changed')
        old_pulls[target] = pull
        manifest = manifests[target]
        if branch_head_sha(github, target) != manifest['baseSha']:
            raise ValueError('Target base moved before publication migration')
        commit = github.rest('GET', f'{REPOSITORY_PATH}/commits/{OLD_HEADS[target]}')
        if [parent['sha'] for parent in commit.get('parents', [])] != [PRODUCTION]:
            raise ValueError('Old source commit is not a direct production child')
        if {file['filename'] for file in commit.get('files', [])} != {file['path'] for file in manifest['files']}:
            raise ValueError('Old source commit contains unexpected files')
        for file in manifest['files']:
            content = read_repository_file(github, OLD_HEADS[target], file['path'])
            baseline = read_repository_file(github, PRODUCTION, file['path'])
            if content is None or sha256(content) != file['afterSha256'] or (
                (sha256(baseline) if baseline is not None else None) != file['beforeSha256']
            ):
                raise ValueError('Native-verified publication bytes changed')

    for head, targets in mapped.items():
        for target in targets:
            queue.put_publication(head, target, legacy[head][2])
    for target in TARGET_BRANCHES:
        queue.put_publication(SHARED_HEAD, target, manifests[target])
    identity = manifests['production']['identityHash']
    branch = branch_name_for(identity, 1789)
    existing = find_branch_head(github, branch)
    if existing is None:
        try:
            github.rest('POST', f'{REPOSITORY_PATH}/git/refs', {'ref': f'refs/heads/{branch}', 'sha': SHARED_HEAD})
        except GitHubError as error:
            if error.status != 422 or find_branch_head(github, branch) != SHARED_HEAD:
                raise
    elif existing != SHARED_HEAD:
        raise ValueError('Shared source branch already has different bytes')

    fixes = {}
    for target in TARGET_BRANCHES:
        manifest = manifests[target]
        result = resume_fix_pull_request(
            github, head_sha=SHARED_HEAD, issue_id=manifest['issueId'], identity_hash=identity,
            source_sha=manifest['sourceSha'], source_path=manifest['sourcePath'], branch_base_sha=PRODUCTION,
            title=old_pulls[target]['title'], issue_number=1789, base_branch=target,
            bot_login=config['botLogin'], publication_store=queue,
        )
        if isinstance(result, ManualReview):
            raise ValueError(result.reason)
        fixes[target] = result
    job['branches'] = {target: fix.to_payload() for target, fix in fixes.items()}
    expected = copy.deepcopy(before)
    expected['branches'] = copy.deepcopy(job['branches'])
    if job != expected:
        raise ValueError('Migration attempted to change investigation/merge policy')
    queue.put(job)
    for target, number in OLD_PULLS.items():
        if number == fixes[target].pull_number:
            continue
        current = github.rest('GET', f'{REPOSITORY_PATH}/pulls/{number}')
        if current.get('merged'):
            raise ValueError('Old PR was merged externally during migration')
        if current['state'] == 'open':
            github.rest('PATCH', f'{REPOSITORY_PATH}/pulls/{number}', {'state': 'closed'})

    head = queue._written_head or queue._head()
    current_entries = queue._entries(head)
    deletions = []
    for path, blob_sha, _manifest in legacy.values():
        current = current_entries.get(path)
        if current is not None and current != blob_sha:
            raise ValueError('Legacy record changed concurrently')
        if current is not None:
            deletions.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': None})
    if deletions:
        queue._written_head = queue._advance_head(head, deletions, 'Migrate legacy publication records to target-scoped schema')
    saved = queue._read(JOB_ID, queue._entries(queue._written_head or queue._head())[f'jobs/{JOB_ID}.json'])
    if saved is None or saved['status'] != 'manual' or saved['attempts'] != before['attempts'] or (
        saved['attemptLimits'] != before['attemptLimits'] or saved['verificationAttempts'] != before['verificationAttempts']
    ):
        raise ValueError('Held incident policy was not preserved')
    for target, fix in fixes.items():
        pull = github.rest('GET', f'{REPOSITORY_PATH}/pulls/{fix.pull_number}')
        if pull.get('merged') or pull.get('draft') or pull['state'] != 'open' or (
            pull['head']['ref'] != branch or pull['head']['sha'] != SHARED_HEAD or pull['base']['ref'] != target
        ):
            raise ValueError('Shared publication postcondition failed')
    from crashlytics_automation.issues import record_fix_progress
    from crashlytics_automation.worker import _context
    record_fix_progress(github, _context(saved), config)
    print(json.dumps({'branch': branch, 'headSha': SHARED_HEAD, 'pulls': {target: fix.pull_number for target, fix in fixes.items()},
                      'status': saved['status'], 'attempts': saved['attempts'], 'verificationAttempts': saved['verificationAttempts']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
