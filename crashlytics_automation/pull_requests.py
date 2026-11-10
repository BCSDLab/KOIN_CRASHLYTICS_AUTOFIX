"""GitHub publication and resume verification for generated Crashlytics fix branches.

Every write happens here: blobs -> tree -> commit -> branch -> pull request.
The manifest committed with the branch is the exact trusted artifact, and a
resumed branch is trusted only after its manifest and file bytes match it.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import quote

from .candidate import (
    SHA40,
    branch_name_for,
    manifest_bytes,
    manifest_digest,
    manifest_path_for,
    require_target_branch,
    sha256,
    validate_manifest,
)
from .models import FileChange, FixPlan, ManualReview, PublishedFix
from .privacy import safe_text
from .repository import OWNER, REPO, REPOSITORY_PATH

PR_MARKER = '<!-- crashlytics-autofix-pr -->'
URI_COMPONENT_SAFE = "!*'()"
CLOSURE_REFERENCE = re.compile(r'(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s*#(\d+)\b')


def _require_sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA40.fullmatch(value):
        raise ValueError(f'Invalid {name}')
    return value


def _status_of(error: BaseException) -> Any:
    return getattr(error, 'status', None)


def _is_safe_int(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2 ** 53 - 1


def _quote_path(path: str) -> str:
    return '/'.join(quote(segment, safe=URI_COMPONENT_SAFE) for segment in path.split('/'))


def read_repository_file(github: Any, ref: str, path: str) -> str | None:
    """Decoded UTF-8 text of ``path`` at ``ref``; ``None`` only when it does not exist."""
    try:
        data = github.rest(
            'GET',
            f'{REPOSITORY_PATH}/contents/{_quote_path(path)}?ref={quote(ref, safe=URI_COMPONENT_SAFE)}',
        )
        if not isinstance(data, dict) or data.get('type') != 'file' \
                or data.get('encoding') != 'base64' or not isinstance(data.get('content'), str):
            raise ValueError(f'Unexpected contents response for {path}')
        try:
            raw = base64.b64decode(data['content'].replace('\n', ''), validate=False)
        except (binascii.Error, ValueError) as error:
            raise ValueError(f'Invalid base64 contents response for {path}') from error
        text = raw.decode('utf-8', 'replace')
        if '\u0000' in text:
            raise ValueError(f'Binary file cannot be used as context: {path}')
        return text
    except Exception as error:  # noqa: BLE001 - re-raised unless it is a 404
        if _status_of(error) == 404:
            return None
        raise


def _branch_head_sha(github: Any, branch: str) -> str:
    data = github.rest('GET', f'{REPOSITORY_PATH}/git/ref/heads/{branch}')
    obj = data.get('object') if isinstance(data, dict) else None
    return _require_sha(obj.get('sha') if isinstance(obj, dict) else None, 'branch SHA')


def find_branch_head(github: Any, branch: str) -> str | None:
    """Head commit of a published fix branch, or ``None`` when it does not exist."""
    try:
        return _branch_head_sha(github, branch)
    except Exception as error:  # noqa: BLE001 - 404 simply means no branch yet
        if _status_of(error) != 404:
            raise
        return None


def branch_head_sha(github: Any, base_branch: str) -> str:
    """The exact target branch commit that candidates are generated and based on."""
    return _branch_head_sha(github, require_target_branch(base_branch))


def _expected_manifest(
    *, issue_id: str, identity_hash: str, source_sha: str, source_path: str,
) -> dict[str, str]:
    """Manifest fields a published branch is pinned to."""
    return {
        'issueId': issue_id,
        'identityHash': identity_hash,
        'sourceSha': source_sha,
        'sourcePath': source_path,
    }


def _find_pull_request(
    github: Any, branch: str, base_branch: str, head_sha: str | None = None,
) -> dict[str, Any] | None:
    head = quote(f'{OWNER}:{branch}', safe=URI_COMPONENT_SAFE)
    pulls = github.rest(
        'GET', f'{REPOSITORY_PATH}/pulls?head={head}&state=all&per_page=100',
    )
    if not isinstance(pulls, list):
        raise ValueError('Unexpected pull request listing')
    fallback: dict[str, Any] | None = None
    for pull in pulls:
        if not isinstance(pull, dict):
            continue
        if (pull.get('head') or {}).get('ref') != branch \
                or (pull.get('base') or {}).get('ref') != base_branch:
            continue
        if head_sha is None or (pull.get('head') or {}).get('sha') == head_sha:
            return pull
        if fallback is None:
            fallback = pull
    return fallback


def _fixed_repository(pull: Mapping[str, Any]) -> bool:
    return all(
        ((pull.get(side) or {}).get('repo') or {}).get('full_name') == f'{OWNER}/{REPO}'
        for side in ('head', 'base')
    )


def _pull_author(pull: Mapping[str, Any]) -> Any:
    user = pull.get('user')
    return user.get('login') if isinstance(user, dict) else None


def _pinned_pull_matches(
    pull: Mapping[str, Any], *, branch: str, target: str, head_sha: str, bot_login: str | None,
) -> str | None:
    """Reject a pull request that is not this automation's exact pinned publication."""
    if not _fixed_repository(pull):
        return '기존 자동 수정 PR이 설정된 저장소의 PR이 아닙니다.'
    if (pull.get('head') or {}).get('ref') != branch or (pull.get('base') or {}).get('ref') != target:
        return '기존 자동 수정 PR의 브랜치 또는 대상이 다릅니다.'
    if (pull.get('head') or {}).get('sha') != head_sha:
        return '기존 자동 수정 PR의 head가 신뢰 기록과 다릅니다.'
    if bot_login is not None and _pull_author(pull) != bot_login:
        return '기존 자동 수정 PR의 작성자가 설정된 자동화 계정이 아닙니다.'
    return None


def find_target_pull_request(
    github: Any, identity_hash: str, base_branch: str,
) -> dict[str, Any] | None:
    """The pull request published for this identity and target, open or already merged."""
    target = require_target_branch(base_branch)
    return _find_pull_request(github, branch_name_for(identity_hash, target), target)


def _pull_merged(pull: Mapping[str, Any]) -> bool:
    """Merged pull requests stay reusable after their head branch is deleted."""
    merged = pull.get('merged')
    if merged is not None:
        return merged is True
    return isinstance(pull.get('merged_at'), str)


def _verify_published_branch(
    github: Any, head_sha: str, expected: Mapping[str, str],
) -> tuple[dict[str, Any] | None, str | None]:
    """Trust a published branch only if its manifest and content match the record."""
    raw = read_repository_file(github, head_sha, manifest_path_for(expected['identityHash']))
    if raw is None:
        return None, '브랜치에서 manifest를 찾을 수 없습니다.'
    try:
        manifest = json.loads(raw)
    except ValueError:
        return None, '브랜치의 manifest가 올바른 JSON이 아닙니다.'
    validation = validate_manifest(manifest, expected)
    if not validation['valid']:
        return None, validation['reason']
    # The candidate must still be based on the exact target commit recorded in its manifest.
    commit = github.rest('GET', f'{REPOSITORY_PATH}/commits/{head_sha}')
    parents = commit.get('parents') if isinstance(commit, dict) else None
    parent = parents[0].get('sha') if isinstance(parents, list) and parents \
        and isinstance(parents[0], dict) else None
    if parent != manifest['baseSha']:
        return None, '브랜치 커밋의 부모가 manifest 기준 커밋과 다릅니다.'
    for file in manifest['files']:
        content = read_repository_file(github, head_sha, file['path'])
        if content is None:
            return None, f'브랜치에 파일이 없습니다: {file["path"]}'
        if sha256(content) != file['afterSha256']:
            return None, f'브랜치 파일 해시가 manifest와 다릅니다: {file["path"]}'
    return manifest, None


def _create_blob(github: Any, content: str) -> str:
    blob = github.rest(
        'POST',
        f'{REPOSITORY_PATH}/git/blobs',
        {
            'content': base64.b64encode(content.encode('utf-8')).decode('ascii'),
            'encoding': 'base64',
        },
    )
    return _require_sha(blob.get('sha') if isinstance(blob, dict) else None, 'blob SHA')


def _create_tree(github: Any, base_sha: str, changes: Sequence[FileChange]) -> str:
    parent = github.rest('GET', f'{REPOSITORY_PATH}/git/commits/{base_sha}')
    parent_tree = parent.get('tree') if isinstance(parent, dict) else None
    base_tree_sha = _require_sha(
        parent_tree.get('sha') if isinstance(parent_tree, dict) else None, 'base tree SHA',
    )
    entries = [
        {
            'path': change.path,
            'mode': '100644',
            'type': 'blob',
            'sha': _create_blob(github, change.content),
        }
        for change in changes
    ]
    tree = github.rest(
        'POST', f'{REPOSITORY_PATH}/git/trees', {'base_tree': base_tree_sha, 'tree': entries},
    )
    return _require_sha(tree.get('sha') if isinstance(tree, dict) else None, 'tree SHA')


def _commit_message(manifest: Mapping[str, Any], base_sha: str) -> str:
    test_paths = ', '.join(file['path'] for file in manifest['files'] if file['kind'] == 'test')
    return (
        f'fix: Crashlytics {manifest["issueId"]} 자동 수정 후보\n\n'
        f'기준 커밋: {base_sha}\n'
        f'회귀 테스트: {test_paths}\n\n'
        '이 커밋은 자동 생성되었으며 필수 CI를 통과해야 합니다.'
    )


def _create_commit(github: Any, manifest: Mapping[str, Any], base_sha: str, tree_sha: str) -> str:
    commit = github.rest(
        'POST',
        f'{REPOSITORY_PATH}/git/commits',
        {
            'message': _commit_message(manifest, base_sha),
            'tree': tree_sha,
            'parents': [base_sha],
        },
    )
    return _require_sha(commit.get('sha') if isinstance(commit, dict) else None, 'commit SHA')


def _pull_request_body(
    manifest: Mapping[str, Any], issue_number: int, base_branch: str,
) -> str:
    identity_hash = manifest['identityHash']
    return f"""## 자동 수정 후보

* Crashlytics 이슈: `{manifest['issueId']}`
* 대상 브랜치: `{base_branch}` @ `{manifest['baseSha']}`
* 발생 릴리스 소스: `{manifest['sourceSha']}` (`{safe_text(manifest['sourcePath'], 300)}`)
* manifest: `{manifest_path_for(identity_hash)}`
* manifestDigest: `{manifest_digest(manifest)}`

### 검증 필요 사항
* 새 회귀 테스트는 수정된 동작을 일반 JUnit assertion으로 확인합니다.
* 필수 CI(`Lint & Format Check`, `Code Coverage`)가 통과해야 머지합니다.

Closes #{issue_number}

{PR_MARKER} {identity_hash}"""


def _closure_numbers(body: Any) -> set[int]:
    """Issues the pull request body claims to close via GitHub closing keywords."""
    if not isinstance(body, str):
        return set()
    return {int(number) for number in CLOSURE_REFERENCE.findall(body)}


def _body_with_closure_link(body: Any, issue_number: int) -> str:
    text = body if isinstance(body, str) else ''
    if not text.strip():
        return f'Closes #{issue_number}'
    return f'{text.rstrip()}\n\nCloses #{issue_number}'


def _ensure_closure_link(
    github: Any, pull: Mapping[str, Any], issue_number: int,
) -> ManualReview | None:
    """Keep the existing PR linked to exactly ``issue_number``.

    A retry must never inherit a pull request that closes some other issue, and a
    historical body without any closing keyword is linked to the requested one.
    """
    numbers = _closure_numbers(pull.get('body'))
    if numbers == {issue_number}:
        return None
    if numbers:
        listed = ', '.join(f'#{number}' for number in sorted(numbers))
        return ManualReview(
            f'기존 자동 수정 PR이 다른 이슈를 닫도록 연결되어 있습니다: {listed}. '
            f'요청된 이슈: #{issue_number}'[:1000],
        )
    number = pull.get('number')
    if not _is_safe_int(number):
        raise ValueError('Pull request listing returned no number')
    updated = github.rest(
        'PATCH',
        f'{REPOSITORY_PATH}/pulls/{number}',
        {'body': _body_with_closure_link(pull.get('body'), issue_number)},
    )
    if not isinstance(updated, dict):
        raise ValueError('Pull request update returned no record')
    return None


def _create_pull_request(
    github: Any,
    *,
    manifest: Mapping[str, Any],
    head_sha: str,
    title: str,
    issue_number: int,
    base_branch: str,
    bot_login: str | None,
) -> PublishedFix | ManualReview:
    target = require_target_branch(base_branch)
    identity_hash = manifest['identityHash']
    branch = branch_name_for(identity_hash, target)
    try:
        pull: Any = github.rest(
            'POST',
            f'{REPOSITORY_PATH}/pulls',
            {
                'title': title,
                'head': branch,
                'base': target,
                'body': _pull_request_body(manifest, issue_number, target),
                'draft': False,
            },
        )
    except Exception as error:  # noqa: BLE001 - a 422 may mean the PR already exists
        if _status_of(error) != 422:
            raise
        pull = _find_pull_request(github, branch, target)
        if pull is None:
            raise
        mismatch = _pinned_pull_matches(
            pull, branch=branch, target=target, head_sha=head_sha, bot_login=bot_login,
        )
        if mismatch is not None:
            return ManualReview(mismatch[:1000])
        conflict = _ensure_closure_link(github, pull, issue_number)
        if conflict is not None:
            return conflict
    if not isinstance(pull, dict) or not _is_safe_int(pull.get('number')):
        raise ValueError('Pull request creation returned no number')
    return PublishedFix(
        pull_number=pull['number'],
        head_sha=head_sha,
        base_sha=manifest['baseSha'],
        manifest_digest=manifest_digest(manifest),
        base_branch=target,
    )


def resume_fix_pull_request(
    github: Any,
    *,
    head_sha: str,
    issue_id: str,
    identity_hash: str,
    source_sha: str,
    source_path: str,
    title: str,
    issue_number: int,
    base_branch: str,
    bot_login: str | None,
) -> PublishedFix | ManualReview:
    """Resume a branch that already exists instead of generating (and charging) again."""
    target = require_target_branch(base_branch)
    expected = _expected_manifest(
        issue_id=issue_id,
        identity_hash=identity_hash,
        source_sha=source_sha,
        source_path=source_path,
    )
    manifest, failure = _verify_published_branch(github, head_sha, expected)
    if manifest is None:
        return ManualReview(
            f'기존 자동 수정 브랜치의 manifest가 신뢰 기록과 일치하지 않습니다: {failure}'[:1000],
        )
    branch = branch_name_for(identity_hash, target)
    pull = _find_pull_request(github, branch, target, head_sha=head_sha)
    if pull is not None:
        mismatch = _pinned_pull_matches(
            pull, branch=branch, target=target, head_sha=head_sha, bot_login=bot_login,
        )
        if mismatch is not None:
            return ManualReview(mismatch[:1000])
        if pull.get('state') == 'closed' and not _pull_merged(pull):
            return ManualReview('기존 자동 수정 PR이 머지 없이 닫혀 재개하지 않습니다.')
        conflict = _ensure_closure_link(github, pull, issue_number)
        if conflict is not None:
            return conflict
        return PublishedFix(
            pull_number=pull['number'],
            head_sha=head_sha,
            base_sha=manifest['baseSha'],
            manifest_digest=manifest_digest(manifest),
            base_branch=target,
            reused=True,
        )
    return _create_pull_request(
        github,
        manifest=manifest,
        head_sha=head_sha,
        title=title,
        issue_number=issue_number,
        base_branch=target,
        bot_login=bot_login,
    )


def publish_fix_pull_request(
    github: Any, *, plan: FixPlan, bot_login: str | None,
) -> PublishedFix | ManualReview:
    """Commit the validated changes plus manifest, then open the fix pull request."""
    manifest = plan.manifest
    base_branch = require_target_branch(plan.base_branch)
    identity_hash = manifest['identityHash']
    base_sha = manifest['baseSha']
    changes = [
        *plan.changes,
        FileChange(manifest_path_for(identity_hash), manifest_bytes(manifest)),
    ]
    tree_sha = _create_tree(github, base_sha, changes)
    commit_sha = _create_commit(github, manifest, base_sha, tree_sha)

    branch = branch_name_for(identity_hash, base_branch)
    try:
        github.rest(
            'POST', f'{REPOSITORY_PATH}/git/refs', {'ref': f'refs/heads/{branch}', 'sha': commit_sha},
        )
    except Exception as error:  # noqa: BLE001 - a 422 means a concurrent worker won the race
        if _status_of(error) != 422:
            raise
        # A concurrent worker may have created the branch first; resume against it instead of charging again.
        return resume_fix_pull_request(
            github,
            head_sha=_branch_head_sha(github, branch),
            issue_id=manifest['issueId'],
            identity_hash=identity_hash,
            source_sha=manifest['sourceSha'],
            source_path=manifest['sourcePath'],
            title=plan.title,
            issue_number=plan.issue_number,
            base_branch=base_branch,
            bot_login=bot_login,
        )

    return _create_pull_request(
        github,
        manifest=manifest,
        head_sha=commit_sha,
        title=plan.title,
        issue_number=plan.issue_number,
        base_branch=base_branch,
        bot_login=bot_login,
    )
