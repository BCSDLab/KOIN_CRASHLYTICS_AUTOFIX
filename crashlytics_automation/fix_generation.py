"""Bounded model context and candidate generation for one Crashlytics crash.

The provider is a pure text generator: it sees only a bounded snapshot of the
pinned target base branch and the release frame, and returns Kotlin file contents.
Every path, byte, and manifest entry is validated against that exact base here.
Publication itself lives in ``pull_requests`` and is only reached after the
candidate validates.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Sequence

from .candidate import (
    MAX_CANDIDATE_FILES,
    SHA40,
    branch_name_for,
    candidate_manifest,
    identity_hash_for,
    is_allowed_source_path,
    is_allowed_test_path,
    module_for_path,
    path_sort_key,
    regression_test_name,
    require_target_branch,
    validate_candidate,
)
from .models import CrashAlert, FileChange, FixPlan, ManualReview, PublishedFix, SourceLocation
from .privacy import safe_text
from .pull_requests import (
    branch_head_sha,
    find_branch_head,
    find_target_pull_request,
    publish_fix_pull_request,
    read_repository_file,
    resume_fix_pull_request,
)
from .repository import REPOSITORY, REPOSITORY_PATH

MAX_CLOSURE_FILES = 8
MAX_CONTEXT_SOURCE_CHARS = 120_000
MAX_CONTEXT_CLOSURE_CHARS = 40_000
MAX_CONTEXT_FRAME_CHARS = 20_000
FRAME_WINDOW_LINES = 60
MAX_CONTEXT_BREADCRUMBS = 10
MAX_MODULE_FILES = 120

ISSUE_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f'{text[:limit]}\n/* context truncated */'


def _frame_of(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    frame = evidence.get('frame')
    return frame if isinstance(frame, dict) else {}


def _is_safe_line(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2 ** 53 - 1


def _vetted_breadcrumbs(evidence: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Vetted analytics records only: name, ISO timestamp, safe categorical params."""
    records = evidence.get('breadcrumbs')
    if not isinstance(records, list):
        return []
    vetted: list[dict[str, Any]] = []
    for record in records:
        if len(vetted) == MAX_CONTEXT_BREADCRUMBS:
            break
        if not isinstance(record, dict):
            continue
        name = record.get('name')
        timestamp = record.get('timestamp')
        params = record.get('params')
        if not isinstance(name, str) or not isinstance(timestamp, str) or not isinstance(params, dict):
            continue
        vetted.append({
            'name': safe_text(name, 100),
            'timestamp': timestamp[:40],
            'params': {
                key: safe_text(value, 100)
                for key, value in params.items()
                if isinstance(key, str) and isinstance(value, str)
            },
        })
    return vetted


def _frame_snippet(content: str, line: Any, symbol: Any) -> dict[str, Any]:
    lines = content.split('\n')
    if _is_safe_line(line):
        index = min(max(line - 1, 0), max(len(lines) - 1, 0))
    else:
        index = 0
    start = max(0, index - FRAME_WINDOW_LINES // 2)
    end = min(len(lines), start + FRAME_WINDOW_LINES)
    return {
        'sourceShaLine': start + 1,
        'endLine': end,
        'snippet': _truncate('\n'.join(lines[start:end]), MAX_CONTEXT_FRAME_CHARS),
        'symbol': symbol[:1024] if isinstance(symbol, str) else None,
    }


def _release_snippet(
    github: Any, source: SourceLocation, evidence: Mapping[str, Any],
) -> dict[str, Any] | None:
    release_content = read_repository_file(github, source.release_sha, source.path)
    if release_content is None:
        return None
    return _frame_snippet(release_content, source.line, _frame_of(evidence).get('symbol'))


def _base_module_files(github: Any, base_sha: str, source_path: str) -> list[str]:
    """Allowed source files in the crash source's Gradle module, nearest first."""
    module = module_for_path(source_path)
    if module is None:
        return []
    tree = github.rest('GET', f'{REPOSITORY_PATH}/git/trees/{base_sha}?recursive=1')
    # An incomplete tree listing must not be presented to the model as the module's file set.
    entries = tree.get('tree') if isinstance(tree, dict) else None
    if not isinstance(entries, list) or tree.get('truncated'):
        return []
    paths = [
        entry['path']
        for entry in entries
        if isinstance(entry, dict) and entry.get('type') == 'blob'
        and is_allowed_source_path(entry.get('path'))
        and module_for_path(entry.get('path')) == module
    ]
    directory = source_path[:source_path.rfind('/') + 1]
    paths.sort(key=lambda path: (0 if path.startswith(directory) else 1, path_sort_key(path)))
    return paths[:MAX_MODULE_FILES]


def _resolve_closure(
    github: Any, base_sha: str, paths: Sequence[str],
) -> tuple[list[FileChange], str | None]:
    """Read the caller-selected sibling sources within the context budget."""
    resolved: list[FileChange] = []
    remaining = MAX_CONTEXT_CLOSURE_CHARS
    for path in paths:
        if remaining <= 0:
            return [], '소스 클로저 컨텍스트가 상한을 초과했습니다.'
        content = read_repository_file(github, base_sha, path)
        if content is None:
            return [], f'소스 클로저 파일을 기준 브랜치에서 찾을 수 없습니다: {safe_text(path, 200)}'
        if len(content) > remaining:
            continue
        remaining -= len(content)
        resolved.append(FileChange(path, content))
    return resolved, None


def _model_context(
    *,
    alert: CrashAlert,
    evidence: Mapping[str, Any],
    source: SourceLocation,
    base_branch: str,
    base_sha: str,
    base_source: str,
    module_files: Sequence[str],
    closure: Sequence[FileChange],
    release_snippet: dict[str, Any] | None,
    identity_hash: str,
) -> dict[str, Any]:
    frame = _frame_of(evidence)
    return {
        'repository': REPOSITORY,
        'baseBranch': base_branch,
        'baseSha': base_sha,
        'identityHash': identity_hash,
        'issue': {
            'issueId': alert.issue_id,
            'title': safe_text(alert.title, 500),
            'subtitle': safe_text(alert.subtitle, 500),
            'appVersion': safe_text(alert.app_version, 200),
        },
        'crash': {
            'displayVersion': evidence.get('displayVersion'),
            'buildVersion': str(evidence.get('buildVersion')),
            'eventTime': evidence.get('eventTime') if isinstance(evidence.get('eventTime'), str) else None,
            'frame': {
                'file': safe_text(frame.get('file'), 300),
                'line': source.line,
                'symbol': safe_text(frame.get('symbol'), 500),
            },
            'breadcrumbs': _vetted_breadcrumbs(evidence),
        },
        'releaseSource': {
            'sourceSha': source.release_sha,
            'sourcePath': source.path,
            'snippet': release_snippet,
        },
        'baseSources': {
            'sourcePath': source.path,
            'exists': True,
            'content': _truncate(base_source, MAX_CONTEXT_SOURCE_CHARS),
            'moduleFiles': list(module_files),
            'closure': [{'path': change.path, 'content': change.content} for change in closure],
        },
        'policy': {
            'maxFiles': MAX_CANDIDATE_FILES,
            'sourcePaths': 'existing .kt files under domain|data|koin|core[/name]|feature/name/src/main/{java,kotlin}/**',
            'testPaths': (
                'new .kt files under the same module src/test/{java,kotlin}/** named '
                f'{regression_test_name(identity_hash)}'
            ),
            'requirements': [
                'At least one existing source file edit and at least one new regression test.',
                'No Gradle, dependency, resource, manifest, generated, JSON, workflow, or business-module changes.',
                'Regression test must fail on the unfixed base code and pass after the fix.',
                'Complete file contents only; package declaration must match the directory.',
            ],
        },
    }


def _model_credentials(config: Mapping[str, Any]) -> tuple[str, str] | ManualReview:
    model_name = config.get('model')
    if not isinstance(model_name, str) or not model_name:
        return ManualReview('OpenAI 모델이 설정되지 않았습니다.')
    api_key = config.get('apiKey')
    if not isinstance(api_key, str) or not api_key:
        return ManualReview('OpenAI API 키가 설정되지 않았습니다.')
    return model_name, api_key


def _is_issue_number(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2 ** 53 - 1


def _fix_title(alert: CrashAlert, base_branch: str) -> str:
    return (
        f'[Fix] [Crashlytics:{alert.issue_id[:8]}][{base_branch}] '
        f'{safe_text(alert.title, 200)}'
    )[:256]


def _review(reason: Any) -> ManualReview:
    return ManualReview(str(reason)[:1000])


def _validated_plan(
    github: Any,
    *,
    alert: CrashAlert,
    source: SourceLocation,
    identity_hash: str,
    base_branch: str,
    base_sha: str,
    base_source: str,
    closure: Sequence[FileChange],
    decision: Any,
    title: str,
    issue_number: int,
) -> FixPlan | ManualReview:
    """Reuse pinned source bytes; probe test paths only to reject overwrites."""
    if not isinstance(decision, dict) or decision.get('decision') == 'no-fix':
        reason = decision.get('reason') if isinstance(decision, dict) else None
        return _review(reason if isinstance(reason, str) else '모델이 안전한 수정을 제안하지 않았습니다.')
    if decision.get('decision') != 'fix' or not isinstance(decision.get('files'), list):
        raise ValueError('Invalid generation result')

    baseline_map: dict[str, str] = {source.path: base_source}
    baseline_map.update((change.path, change.content) for change in closure)
    for file in decision['files']:
        path = file.get('path') if isinstance(file, dict) else None
        if not is_allowed_source_path(path) and not is_allowed_test_path(path, identity_hash):
            return _review(f'모델이 허용되지 않은 경로를 제안했습니다: {safe_text(path, 200)}')
        if is_allowed_source_path(path):
            if path not in baseline_map:
                return _review('전체 내용을 제공하지 않은 소스 파일은 자동 수정하지 않습니다.')
        else:
            baseline = read_repository_file(github, base_sha, path)
            if baseline is not None:
                baseline_map[path] = baseline

    validated = validate_candidate(decision['files'], baseline_map, identity_hash)
    if not validated['valid']:
        return _review(validated['reason'])

    manifest = candidate_manifest(
        issue_id=alert.issue_id,
        identity_hash=identity_hash,
        base_sha=base_sha,
        source_sha=source.release_sha,
        source_path=source.path,
        files=[
            {key: file[key] for key in ('path', 'kind', 'beforeSha256', 'afterSha256')}
            for file in validated['files']
        ],
    )
    changes = tuple(FileChange(file['path'], file['content']) for file in validated['files'])
    return FixPlan(
        manifest=manifest,
        changes=changes,
        title=title,
        issue_number=issue_number,
        base_branch=base_branch,
    )


def create_fix_pull_request(
    github: Any,
    alert: CrashAlert,
    evidence: dict[str, Any],
    source: SourceLocation,
    config: dict[str, Any],
    *,
    issue_number: int,
    base_branch: str,
    generate: Callable[..., Any],
) -> PublishedFix | ManualReview:
    """Generate and publish one Crashlytics autofix candidate for one target branch.

    ``issue_number`` is the tracker issue created before generation; it is used
    only for the pull request closing link and never reaches the model context.
    ``base_branch`` is the release lane this candidate targets; it is validated
    before any network call. Existing published branches/PRs for that same lane
    are detected first so retries never trigger a billable model call.
    """
    if not callable(generate):
        raise ValueError('Missing generate dependency')
    if not _is_issue_number(issue_number):
        raise ValueError('Invalid issue number for autofix')
    if not isinstance(config, dict):
        raise ValueError('Invalid autofix configuration')
    bot_login = config.get('botLogin')
    if not isinstance(bot_login, str) or not bot_login:
        raise ValueError('Missing autofix bot login')
    if not isinstance(alert, CrashAlert) or not ISSUE_ID.fullmatch(alert.issue_id):
        raise ValueError('Invalid alert for autofix')
    if not isinstance(evidence, dict) or evidence.get('status') != 'ready':
        raise ValueError('Crashlytics evidence is not ready for autofix')
    if not isinstance(source, SourceLocation):
        raise ValueError('Source location is not ready for autofix')
    target = require_target_branch(base_branch)
    if not is_allowed_source_path(source.path):
        return _review('소스 위치가 자동 수정 허용 경로가 아닙니다.')

    identity_hash = identity_hash_for(alert.issue_id)
    title = _fix_title(alert, target)
    branch_name = branch_name_for(identity_hash, target)

    # 1. Resume published work for this target without any model call.
    # A merged pull request is reusable even after its head branch was deleted,
    # so the pull request is consulted before the branch.
    pull = find_target_pull_request(github, identity_hash, target)
    if pull is not None:
        pull_head = (pull.get('head') or {}).get('sha')
        if not isinstance(pull_head, str) or not SHA40.fullmatch(pull_head):
            return _review('기존 자동 수정 PR의 head SHA를 확인할 수 없습니다.')
        resume_head = pull_head
    else:
        resume_head = find_branch_head(github, branch_name)
    if resume_head is not None:
        return resume_fix_pull_request(
            github,
            head_sha=resume_head,
            issue_id=alert.issue_id,
            identity_hash=identity_hash,
            source_sha=source.release_sha,
            source_path=source.path,
            title=title,
            issue_number=issue_number,
            base_branch=target,
            bot_login=bot_login,
        )

    # 2. Build bounded context from the pinned target base and the release frame.
    base_sha = branch_head_sha(github, target)
    base_source = read_repository_file(github, base_sha, source.path)
    if base_source is None:
        return _review(
            f'발생 소스 파일이 현재 {target}에 없어 수정 대상을 확정할 수 없습니다.'
        )
    if len(base_source) > MAX_CONTEXT_SOURCE_CHARS:
        return _review('소스 파일 전체가 모델 컨텍스트 한도를 넘어 안전하게 수정할 수 없습니다.')
    module_files = _base_module_files(github, base_sha, source.path)
    source_directory = source.path[:source.path.rfind('/') + 1]
    closure, closure_failure = _resolve_closure(github, base_sha, [
        path for path in module_files
        if path != source.path and path.startswith(source_directory)
    ][:MAX_CLOSURE_FILES])
    if closure_failure is not None:
        return _review(closure_failure)

    context = _model_context(
        alert=alert,
        evidence=evidence,
        source=source,
        base_branch=target,
        base_sha=base_sha,
        base_source=base_source,
        module_files=module_files,
        closure=closure,
        release_snippet=_release_snippet(github, source, evidence),
        identity_hash=identity_hash,
    )

    # 3. One structured generation call; credentials are not part of the context.
    credentials = _model_credentials(config)
    if isinstance(credentials, ManualReview):
        return credentials
    model_name, api_key = credentials
    decision = generate(model=model_name, api_key=api_key, context=context)

    # 4. Validate the proposal against the pinned base bytes before any write.
    plan = _validated_plan(
        github,
        alert=alert,
        source=source,
        identity_hash=identity_hash,
        base_branch=target,
        base_sha=base_sha,
        base_source=base_source,
        closure=closure,
        decision=decision,
        title=title,
        issue_number=issue_number,
    )
    if isinstance(plan, ManualReview):
        return plan

    # 5. Publish blobs -> tree -> commit -> branch -> PR.
    published = publish_fix_pull_request(github, plan=plan, bot_login=bot_login)
    if not isinstance(published, (PublishedFix, ManualReview)):
        raise ValueError('Unexpected publication result')
    return published
