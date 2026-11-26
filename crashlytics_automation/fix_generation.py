"""Publication of fixes produced by the trusted investigation workflow."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .candidate import (
    SHA40, branch_name_for, candidate_manifest, identity_hash_for,
    is_allowed_source_path, is_allowed_test_path,
    require_target_branch, validate_candidate,
)
from .models import CrashAlert, FileChange, FixPlan, ManualReview, PublishedFix
from .ownership import find_ai_fix_for_line
from .privacy import safe_text
from .pull_requests import (
    find_branch_head, find_target_pull_request, publish_fix_pull_request,
    read_repository_file, resume_fix_pull_request,
)
from .release_source import resolve_investigated_source, resolve_release_commit
 

ISSUE_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')


def _is_issue_number(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2 ** 53 - 1


def _fix_title(alert: CrashAlert, base_branch: str) -> str:
    return (f'[Fix] [Crashlytics:{alert.issue_id[:8]}][{base_branch}] '
            f'{safe_text(alert.title, 200)}')[:256]


def _review(reason: Any) -> ManualReview:
    return ManualReview(str(reason)[:1000])


def existing_fix(
    github: Any, *, alert: CrashAlert, issue_number: int,
    base_branch: str, bot_login: str, release_sha: str, branch_base_sha: str,
    publication_store: Any,
) -> PublishedFix | ManualReview | None:
    """Reuse a prior publication only for the exact investigated release and origin."""
    if not _is_issue_number(issue_number):
        raise ValueError('Invalid issue number for autofix')
    if not isinstance(bot_login, str) or not bot_login:
        raise ValueError('Missing autofix bot login')
    if not isinstance(alert, CrashAlert) or not ISSUE_ID.fullmatch(alert.issue_id):
        raise ValueError('Invalid alert for autofix')
    target = require_target_branch(base_branch)
    if not isinstance(release_sha, str) or not SHA40.fullmatch(release_sha):
        raise ValueError('Invalid release SHA for autofix resume')
    if not isinstance(branch_base_sha, str) or not SHA40.fullmatch(branch_base_sha):
        raise ValueError('Invalid production branch base SHA for autofix resume')
    identity_hash = identity_hash_for(alert.issue_id, release_sha)
    pull = find_target_pull_request(github, identity_hash, target, issue_number)
    branch = branch_name_for(identity_hash, issue_number)
    head_sha = (pull.get('head') or {}).get('sha') if pull is not None else None
    if pull is not None and (not isinstance(head_sha, str) or not SHA40.fullmatch(head_sha)):
        return _review('기존 자동 수정 PR의 head SHA를 확인할 수 없습니다.')
    if pull is None:
        head_sha = find_branch_head(github, branch)
    if head_sha is None:
        return None
    try:
        manifest = publication_store.get_publication(head_sha, target)
    except (ValueError, TypeError):
        return _review('기존 자동 수정 브랜치의 외부 검증 기록을 읽을 수 없습니다.')
    if not isinstance(manifest, dict):
        if pull is None:
            return None
        return _review('기존 자동 수정 PR의 외부 검증 기록을 찾을 수 없습니다.')
    source_sha = manifest.get('sourceSha')
    manifest_branch_base_sha = manifest.get('branchBaseSha')
    if manifest.get('version') != 3 or manifest.get('issueNumber') != issue_number \
            or source_sha != release_sha or manifest_branch_base_sha != branch_base_sha \
            or not is_allowed_source_path(manifest.get('sourcePath')):
        return _review('기존 자동 수정 브랜치가 이슈, 릴리스 또는 production 기준과 일치하지 않습니다.')
    return resume_fix_pull_request(
        github, head_sha=head_sha, issue_id=alert.issue_id,
        identity_hash=identity_hash, source_sha=source_sha, source_path=manifest['sourcePath'],
        branch_base_sha=branch_base_sha, title=_fix_title(alert, target),
        issue_number=issue_number, base_branch=target, bot_login=bot_login,
        publication_store=publication_store,
    )


def publish_investigated_fix(
    github: Any, *, alert: CrashAlert, evidence: Mapping[str, Any], decision: Any,
    issue_number: int, base_branch: str, base_sha: str, branch_base_sha: str,
    release_sha: str, bot_login: str, verification: Any, publication_store: Any,
    prior_bot_logins: tuple[str, ...] = (),
) -> PublishedFix | ManualReview:
    """Validate independently verified changes against exact pinned GitHub bytes."""
    if not _is_issue_number(issue_number):
        raise ValueError('Invalid issue number for autofix')
    if not isinstance(bot_login, str) or not bot_login:
        raise ValueError('Missing autofix bot login')
    if not isinstance(alert, CrashAlert) or not ISSUE_ID.fullmatch(alert.issue_id):
        raise ValueError('Invalid alert for autofix')
    if not isinstance(evidence, Mapping) or evidence.get('status') != 'ready':
        return _review('Crashlytics 증거가 준비되지 않았습니다.')
    target = require_target_branch(base_branch)
    if not isinstance(base_sha, str) or not SHA40.fullmatch(base_sha):
        return _review('기준 커밋을 확인할 수 없습니다.')
    if not isinstance(branch_base_sha, str) or not SHA40.fullmatch(branch_base_sha):
        return _review('production 기준 커밋을 확인할 수 없습니다.')
    if not isinstance(verification, Mapping) or verification.get('passed') is not True:
        return _review('수정안에 대한 실제 검증이 완료되지 않았습니다.')
    if not isinstance(release_sha, str) or not SHA40.fullmatch(release_sha):
        return _review('릴리스 커밋을 확인할 수 없습니다.')
    pinned_release = resolve_release_commit(github, evidence)
    if isinstance(pinned_release, ManualReview):
        return pinned_release
    if pinned_release != release_sha:
        return _review('조사 결과의 릴리스 커밋이 증거에서 확인한 릴리스와 다릅니다.')
    if not isinstance(decision, dict) or decision.get('decision') != 'fix':
        reason = decision.get('reason') if isinstance(decision, dict) else None
        return _review(reason if isinstance(reason, str) else '조사 결과가 안전한 수정을 제안하지 않았습니다.')
    path, line = decision.get('sourcePath'), decision.get('sourceLine')
    if not is_allowed_source_path(path) or type(line) is not int or not 0 < line <= 10_000_000:
        return _review('조사된 릴리스 소스 위치가 올바르지 않습니다.')
    source = resolve_investigated_source(github, release_sha=release_sha, path=path, line=line)
    if isinstance(source, ManualReview):
        return source
    if not isinstance(prior_bot_logins, tuple) or any(not isinstance(login, str) for login in prior_bot_logins):
        raise ValueError('Invalid prior bot logins')
    if find_ai_fix_for_line(github, source, bot_logins=tuple(dict.fromkeys((bot_login, *prior_bot_logins)))):
        return _review('해당 릴리스 줄은 이미 이전 자동 수정 봇이 변경했습니다.')

    identity_hash = identity_hash_for(alert.issue_id, release_sha)
    files = decision.get('files')
    if not isinstance(files, list) or not files:
        return _review('조사 결과에 수정 파일이 없습니다.')
    if not any(isinstance(file, dict) and file.get('path') == source.path
               for file in files):
        return _review('검증된 릴리스 소스 앵커 파일이 수정 대상에 포함되지 않았습니다.')
    baseline_map: dict[str, str] = {}
    seen: set[str] = set()
    for file in files:
        file_path = file.get('path') if isinstance(file, dict) else None
        source_file = is_allowed_source_path(file_path)
        test_file = is_allowed_test_path(file_path, identity_hash)
        if not source_file and not test_file:
            return _review(f'조사 결과에 허용되지 않은 파일이 있습니다: {safe_text(file_path, 200)}')
        if file_path in seen:
            return _review('조사 결과에 중복 파일이 있습니다.')
        seen.add(file_path)
        baseline = read_repository_file(github, branch_base_sha, file_path)
        if source_file:
            if baseline is None:
                return _review(f'production 기준에 없는 소스 파일은 수정할 수 없습니다: {safe_text(file_path, 200)}')
            baseline_map[file_path] = baseline
        elif baseline is not None:
            return _review(f'production 기준에서 기존 테스트 파일을 덮어쓸 수 없습니다: {safe_text(file_path, 200)}')

    validated = validate_candidate(files, baseline_map, identity_hash)
    if not validated['valid']:
        return _review(validated['reason'])
    manifest = candidate_manifest(
        issue_id=alert.issue_id, issue_number=issue_number, identity_hash=identity_hash,
        base_sha=base_sha, branch_base_sha=branch_base_sha, source_sha=release_sha,
        source_path=source.path,
        files=[{key: file[key] for key in ('path', 'kind', 'beforeSha256', 'afterSha256')}
               for file in validated['files']],
    )
    plan = FixPlan(
        manifest=manifest,
        changes=tuple(FileChange(file['path'], file['content']) for file in validated['files']),
        title=_fix_title(alert, target), issue_number=issue_number,
        base_branch=target, branch_base_sha=branch_base_sha,
    )
    published = publish_fix_pull_request(
        github, plan=plan, bot_login=bot_login, publication_store=publication_store,
    )
    if not isinstance(published, (PublishedFix, ManualReview)):
        raise ValueError('Unexpected publication result')
    return published
