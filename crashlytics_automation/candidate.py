"""Candidate policy for Crashlytics autofix.

Ties every model-supplied file to exact bytes of the pinned target base branch
and to a deterministic manifest. This module has no network, filesystem, shell,
or credential access; it is pure stdlib.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from .repository import REPOSITORY, TARGET_BRANCHES

MAX_CANDIDATE_FILES = 24
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
MANIFEST_VERSION = 1

SHA40 = re.compile(r'[0-9a-f]{40}')
SHA64 = re.compile(r'[0-9a-f]{64}')
ISSUE_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')
MODULE = r'(?:domain|data|koin|core(?:/[A-Za-z0-9_-]{1,64})?|feature/[A-Za-z0-9_-]{1,64})'
PACKAGE_DIR = r'[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*'
SOURCE_PATH = re.compile(
    rf'^({MODULE})/src/main/(?:java|kotlin)/({PACKAGE_DIR})/([A-Za-z_][A-Za-z0-9_]*)\.kt$'
)
MODULE_PATH = re.compile(rf'^({MODULE})/src/')
DECLARED_PACKAGE = re.compile(r'^[ \t]*package\s+([A-Za-z0-9_.`]+)', re.MULTILINE)
MANIFEST_KEYS = (
    'version', 'issueId', 'identityHash',
    'baseSha', 'sourceSha', 'sourcePath', 'files',
)
FILE_KEYS = ('path', 'kind', 'beforeSha256', 'afterSha256')

# Collation order used by the published JS artifacts: primary weights ignore
# case, and the case level breaks ties so persisted digests stay identical.
_PRIMARY_ORDER = '_-./0123456789abcdefghijklmnopqrstuvwxyz'
_PRIMARY_WEIGHT = {char: weight for weight, char in enumerate(_PRIMARY_ORDER)}


def path_sort_key(path: str) -> tuple[tuple[int, ...], tuple[bool, ...]]:
    """Ordering key for accepted candidate paths."""
    primary = tuple(_PRIMARY_WEIGHT.get(char.lower(), 1000 + ord(char)) for char in path)
    return primary, tuple(char.isupper() for char in path)


def canonical_json(value: Any) -> str:
    """Exact JSON.stringify(value) encoding used for every persisted digest."""
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def sha256(value: str | bytes) -> str:
    data = value.encode('utf-8') if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def identity_hash_for(issue_id: Any) -> str:
    if not isinstance(issue_id, str) or not ISSUE_ID.fullmatch(issue_id):
        raise TypeError('Invalid Crashlytics issue ID')
    return sha256(f'{REPOSITORY}/{issue_id}')


def _require_identity_hash(identity_hash: Any) -> str:
    if not isinstance(identity_hash, str) or not SHA64.fullmatch(identity_hash):
        raise TypeError('Invalid identity hash')
    return identity_hash


def require_target_branch(base_branch: Any) -> str:
    """The target base branch must be one of the repository's fixed release lanes."""
    if not isinstance(base_branch, str) or base_branch not in TARGET_BRANCHES:
        raise TypeError('Invalid target base branch')
    return base_branch


def branch_name_for(identity_hash: Any, base_branch: Any) -> str:
    target = require_target_branch(base_branch)
    return f'hotfix/{target}/crashlytics-{_require_identity_hash(identity_hash)}'


def manifest_path_for(identity_hash: Any) -> str:
    return f'automation/crashlytics/runs/{_require_identity_hash(identity_hash)}.json'


def regression_test_name(identity_hash: Any) -> str:
    return f'CrashlyticsRegression{_require_identity_hash(identity_hash)[:12]}Test.kt'


def _test_path_pattern(identity_hash: str) -> re.Pattern[str]:
    name = re.escape(regression_test_name(identity_hash))
    return re.compile(rf'^({MODULE})/src/test/(?:java|kotlin)/(?:({PACKAGE_DIR})/)?{name}$')


def module_for_path(path: Any) -> str | None:
    if not isinstance(path, str):
        return None
    match = MODULE_PATH.match(path)
    return match.group(1) if match else None


def is_allowed_source_path(path: Any) -> bool:
    return isinstance(path, str) and SOURCE_PATH.fullmatch(path) is not None


def is_allowed_test_path(path: Any, identity_hash: Any) -> bool:
    if not isinstance(path, str):
        return False
    return _test_path_pattern(_require_identity_hash(identity_hash)).fullmatch(path) is not None


def safe_label(value: Any) -> str:
    """Control characters and markup must not travel into comments or PR bodies."""
    return re.sub(r'[\x00-\x1f\x7f`<>]', '?', str(value))[:200]


def _match_path(path: str, identity_hash: str) -> dict[str, str] | None:
    source = SOURCE_PATH.fullmatch(path)
    if source:
        return {'kind': 'source', 'module': source.group(1), 'packageDir': source.group(2)}
    test = _test_path_pattern(identity_hash).fullmatch(path)
    if test:
        return {'kind': 'test', 'module': test.group(1), 'packageDir': test.group(2) or ''}
    return None


def _declared_package(content: str) -> str | None:
    match = DECLARED_PACKAGE.search(content)
    return match.group(1).replace('`', '') if match else None


def _has_exact_keys(value: Any, keys: Sequence[str]) -> bool:
    if not isinstance(value, dict):
        return False
    return len(value) == len(keys) and all(key in value for key in keys)


def validate_candidate(
    files: Any, baseline_map: Mapping[str, Any], identity_hash: Any,
) -> dict[str, Any]:
    """Validate model-supplied files against the exact pinned base bytes.

    ``baseline_map`` maps every existing base path to its decoded UTF-8 content.
    Returns normalized entries carrying content (for publication) plus the
    before/after hashes used in the manifest.
    """
    _require_identity_hash(identity_hash)
    if not isinstance(files, list) or not files:
        return {'valid': False, 'reason': '수정 파일이 없습니다.'}
    if len(files) > MAX_CANDIDATE_FILES:
        return {'valid': False, 'reason': f'수정 파일이 {MAX_CANDIDATE_FILES}개를 초과합니다.'}

    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    source_modules: set[str] = set()
    test_modules: list[str] = []
    total_bytes = 0

    for file in files:
        if not isinstance(file, dict):
            return {'valid': False, 'reason': '수정 파일 항목이 올바르지 않습니다.'}
        path = file.get('path')
        content = file.get('content')
        if not isinstance(path, str) or not 0 < len(path) <= 512:
            return {'valid': False, 'reason': '수정 파일 경로가 올바르지 않습니다.'}
        if not isinstance(content, str) or '\u0000' in content:
            return {'valid': False, 'reason': f'파일 내용이 올바르지 않습니다: {safe_label(path)}'}
        if path in seen:
            return {'valid': False, 'reason': f'중복된 파일 경로입니다: {safe_label(path)}'}
        seen.add(path)

        classification = _match_path(path, identity_hash)
        if classification is None:
            return {'valid': False, 'reason': f'허용되지 않은 경로입니다: {safe_label(path)}'}
        expected_package = classification['packageDir'].replace('/', '.')
        actual_package = _declared_package(content)
        package_mismatch = actual_package is not None if expected_package == '' else actual_package != expected_package
        if package_mismatch:
            return {'valid': False, 'reason': f'파일의 package 선언이 경로와 일치하지 않습니다: {safe_label(path)}'}

        try:
            data = content.encode('utf-8')
        except UnicodeEncodeError:
            return {'valid': False, 'reason': f'파일 내용이 올바르지 않습니다: {safe_label(path)}'}
        if len(data) > MAX_FILE_BYTES:
            return {'valid': False, 'reason': f'파일이 {MAX_FILE_BYTES}바이트를 초과합니다: {safe_label(path)}'}
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_BYTES:
            return {'valid': False, 'reason': f'전체 수정 크기가 {MAX_TOTAL_BYTES}바이트를 초과합니다.'}

        baseline = baseline_map.get(path)
        if classification['kind'] == 'source':
            if not isinstance(baseline, str):
                return {
                    'valid': False,
                    'reason': f'기준 소스에 없는 파일은 수정할 수 없습니다: {safe_label(path)}',
                }
            before_sha256 = sha256(baseline)
            after_sha256 = sha256(data)
            if before_sha256 == after_sha256:
                return {'valid': False, 'reason': f'변경 내용이 없습니다: {safe_label(path)}'}
            source_modules.add(classification['module'])
            normalized.append({
                'path': path, 'kind': 'source',
                'beforeSha256': before_sha256, 'afterSha256': after_sha256,
                'content': content,
            })
        else:
            if path in baseline_map:
                return {'valid': False, 'reason': f'기존 테스트 파일을 덮어쓸 수 없습니다: {safe_label(path)}'}
            test_modules.append(classification['module'])
            normalized.append({
                'path': path, 'kind': 'test',
                'beforeSha256': None, 'afterSha256': sha256(data),
                'content': content,
            })

    if not source_modules:
        return {'valid': False, 'reason': '소스 파일 수정이 없습니다.'}
    if not test_modules:
        return {'valid': False, 'reason': '새 회귀 테스트가 없습니다.'}
    if any(module not in source_modules for module in test_modules):
        return {'valid': False, 'reason': '회귀 테스트가 수정된 소스와 다른 모듈에 있습니다.'}
    return {'valid': True, 'files': normalized}


def candidate_manifest(
    *,
    issue_id: Any,
    identity_hash: Any,
    base_sha: Any,
    source_sha: Any,
    source_path: Any,
    files: Any,
) -> dict[str, Any]:
    _require_identity_hash(identity_hash)
    if not isinstance(issue_id, str) or not ISSUE_ID.fullmatch(issue_id):
        raise TypeError('Invalid issue ID')
    if identity_hash_for(issue_id) != identity_hash:
        raise TypeError('Identity hash does not match issue ID')
    if not isinstance(base_sha, str) or not SHA40.fullmatch(base_sha):
        raise TypeError('Invalid base SHA')
    if not isinstance(source_sha, str) or not SHA40.fullmatch(source_sha):
        raise TypeError('Invalid source SHA')
    if not is_allowed_source_path(source_path):
        raise TypeError('Invalid source path')
    if not isinstance(files, list) or not files or len(files) > MAX_CANDIDATE_FILES:
        raise TypeError('Invalid candidate files')

    entries = []
    for file in files:
        if not isinstance(file, dict):
            raise TypeError('Invalid candidate file entry')
        path = file.get('path')
        kind = file.get('kind')
        before_sha256 = file.get('beforeSha256')
        after_sha256 = file.get('afterSha256')
        if (
            not isinstance(path, str)
            or kind not in ('source', 'test')
            or not isinstance(after_sha256, str) or not SHA64.fullmatch(after_sha256)
            or (kind == 'source' and (not isinstance(before_sha256, str) or not SHA64.fullmatch(before_sha256)))
            or (kind == 'test' and before_sha256 is not None)
        ):
            raise TypeError('Invalid candidate file entry')
        permitted = is_allowed_source_path(path) if kind == 'source' else is_allowed_test_path(path, identity_hash)
        if not permitted:
            raise TypeError('Candidate file path is not allowed')
        entries.append({
            'path': path, 'kind': kind,
            'beforeSha256': before_sha256, 'afterSha256': after_sha256,
        })

    entries.sort(key=lambda entry: path_sort_key(entry['path']))
    return {
        'version': MANIFEST_VERSION,
        'issueId': issue_id,
        'identityHash': identity_hash,
        'baseSha': base_sha,
        'sourceSha': source_sha,
        'sourcePath': source_path,
        'files': entries,
    }


def manifest_digest(manifest: Any) -> str:
    return sha256(canonical_json(manifest))


def manifest_bytes(manifest: Any) -> str:
    """Canonical on-branch encoding.

    The digest is defined over compact JSON.stringify(manifest), so the merge
    gate can recompute it by parsing these bytes and stringifying the object again.
    """
    return f'{json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False)}\n'


def validate_manifest(manifest: Any, expected: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Revalidate a parsed manifest (committed on a branch or read by the merge gate).

    ``expected`` may pin issueId, identityHash, baseSha, sourceSha,
    sourcePath. Byte sizes and on-branch content can only be checked by the caller.
    """
    expected = expected or {}
    if not _has_exact_keys(manifest, MANIFEST_KEYS):
        return {'valid': False, 'reason': 'manifest 형식이 올바르지 않습니다.'}
    if type(manifest['version']) is not int or manifest['version'] != MANIFEST_VERSION:
        return {'valid': False, 'reason': '지원하지 않는 manifest 버전입니다.'}
    issue_id = manifest['issueId']
    if not isinstance(issue_id, str) or not ISSUE_ID.fullmatch(issue_id):
        return {'valid': False, 'reason': 'manifest의 Crashlytics ID가 올바르지 않습니다.'}
    identity_hash = manifest['identityHash']
    if (
        not isinstance(identity_hash, str) or not SHA64.fullmatch(identity_hash)
        or identity_hash_for(issue_id) != identity_hash
    ):
        return {'valid': False, 'reason': 'manifest의 identityHash가 일치하지 않습니다.'}
    base_sha = manifest['baseSha']
    source_sha = manifest['sourceSha']
    if (
        not isinstance(base_sha, str) or not SHA40.fullmatch(base_sha)
        or not isinstance(source_sha, str) or not SHA40.fullmatch(source_sha)
    ):
        return {'valid': False, 'reason': 'manifest의 SHA 값이 올바르지 않습니다.'}
    if not is_allowed_source_path(manifest['sourcePath']):
        return {'valid': False, 'reason': 'manifest의 sourcePath가 허용되지 않습니다.'}
    for key in ('issueId', 'identityHash', 'baseSha', 'sourceSha', 'sourcePath'):
        if key in expected and expected[key] != manifest[key]:
            return {'valid': False, 'reason': f'manifest의 {key} 값이 예상과 다릅니다.'}
    files = manifest['files']
    if not isinstance(files, list) or not files or len(files) > MAX_CANDIDATE_FILES:
        return {'valid': False, 'reason': 'manifest의 파일 목록이 올바르지 않습니다.'}

    seen: set[str] = set()
    source_modules: set[str] = set()
    test_modules: list[str] = []
    for file in files:
        if not _has_exact_keys(file, FILE_KEYS):
            return {'valid': False, 'reason': 'manifest 파일 항목 형식이 올바르지 않습니다.'}
        classification = _match_path(file['path'], identity_hash)
        if classification is None or classification['kind'] != file['kind']:
            return {
                'valid': False,
                'reason': f'manifest의 파일 경로가 허용되지 않습니다: {safe_label(file["path"])}',
            }
        if file['path'] in seen:
            return {'valid': False, 'reason': 'manifest에 중복 파일 경로가 있습니다.'}
        seen.add(file['path'])
        before_sha256 = file['beforeSha256']
        after_sha256 = file['afterSha256']
        if file['kind'] == 'source':
            source_modules.add(classification['module'])
            if (
                not isinstance(before_sha256, str) or not SHA64.fullmatch(before_sha256)
                or not isinstance(after_sha256, str) or not SHA64.fullmatch(after_sha256)
                or before_sha256 == after_sha256
            ):
                return {
                    'valid': False,
                    'reason': f'manifest 소스 해시가 올바르지 않습니다: {safe_label(file["path"])}',
                }
        else:
            test_modules.append(classification['module'])
            if before_sha256 is not None or not isinstance(after_sha256, str) \
                    or not SHA64.fullmatch(after_sha256):
                return {
                    'valid': False,
                    'reason': f'manifest 테스트 해시가 올바르지 않습니다: {safe_label(file["path"])}',
                }
    if not source_modules or not test_modules:
        return {'valid': False, 'reason': 'manifest에 소스와 회귀 테스트가 모두 필요합니다.'}
    if any(module not in source_modules for module in test_modules):
        return {'valid': False, 'reason': 'manifest의 회귀 테스트 모듈이 소스 모듈과 다릅니다.'}
    return {'valid': True, 'manifest': manifest, 'digest': manifest_digest(manifest)}
