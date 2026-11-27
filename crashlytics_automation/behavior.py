"""Strict validation for independent behavior-preservation reviews and proofs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .candidate import (
    MAX_CANDIDATE_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MODULE, PACKAGE_DIR, SHA64,
    _declared_package, _require_identity_hash, canonical_json,
    is_allowed_source_path, is_allowed_test_path, module_for_path, sha256,
)


VERIFICATION_VERSION = 2


def preservation_test_name(identity_hash: str) -> str:
    return f'CrashlyticsPreservation{_require_identity_hash(identity_hash)[:12]}Test.kt'


def _preservation_path_pattern(identity_hash: str) -> re.Pattern[str]:
    module = MODULE
    package = rf'(?:{PACKAGE_DIR}/)?'
    name = re.escape(preservation_test_name(identity_hash).removesuffix('.kt'))
    return re.compile(rf'^{module}/src/(?:test|androidTest)/(?:java|kotlin)/{package}{name}\.kt$')


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and SHA64.fullmatch(value) is not None


def _source_entries(files: Any) -> list[dict[str, str]]:
    if not isinstance(files, list):
        raise ValueError('candidate files must be a list')
    sources: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, Mapping):
            raise ValueError('invalid candidate file entry')
        path = entry.get('path')
        if entry.get('kind') == 'source':
            if not is_allowed_source_path(path):
                raise ValueError('invalid source path')
        elif is_allowed_source_path(path):
            raise ValueError('source path has invalid kind')
        else:
            continue
        if not isinstance(path, str):
            raise ValueError('invalid source path')
        before, after = entry.get('beforeSha256'), entry.get('afterSha256')
        if not _is_hash(before) or not _is_hash(after) or before == after:
            raise ValueError('invalid source hashes')
        if path in seen:
            raise ValueError('duplicate source path')
        seen.add(path)
        sources.append({'path': path, 'beforeSha256': before, 'afterSha256': after})
    if not sources:
        raise ValueError('no changed source files')
    return sorted(sources, key=lambda entry: entry['path'])


def source_digest(files: Any) -> str:
    """Hash canonical JSON for sorted changed-source path and pinned hashes."""
    return sha256(canonical_json(_source_entries(files)))



def candidate_digest(files: Any) -> str:
    """Hash all candidate path/kind/base/result hashes, including test bytes."""
    if not isinstance(files, list):
        raise ValueError('candidate files must be a list')
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in files:
        if not isinstance(item, Mapping):
            raise ValueError('invalid candidate file entry')
        path, kind = item.get('path'), item.get('kind')
        before, after = item.get('beforeSha256'), item.get('afterSha256')
        if not isinstance(path, str) or kind not in ('source', 'test') or path in seen:
            raise ValueError('invalid or duplicate candidate entry')
        if not _is_hash(after) or (kind == 'source' and (not _is_hash(before) or before == after)):
            raise ValueError('invalid candidate hashes')
        if kind == 'test' and before is not None:
            raise ValueError('test file cannot replace a baseline file')
        seen.add(path)
        entries.append({'path': path, 'kind': kind, 'beforeSha256': before, 'afterSha256': after})
    if not any(item['kind'] == 'source' for item in entries) or not any(item['kind'] == 'test' for item in entries):
        raise ValueError('candidate must contain source and test files')
    entries.sort(key=lambda item: item['path'])
    return sha256(canonical_json(entries))

def _valid_content(content: Any, path: str) -> int:
    if not isinstance(content, str) or '\x00' in content:
        raise ValueError(f'invalid file content: {path}')
    try:
        data = content.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError(f'invalid UTF-8 content: {path}') from exc
    if len(data) > MAX_FILE_BYTES:
        raise ValueError(f'file exceeds size limit: {path}')
    match = re.search(r'/src/(?:main|test|androidTest)/(?:java|kotlin)/(?:(?P<pkg>[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)/)?[^/]+$', path)
    expected = match.group('pkg').replace('/', '.') if match and match.group('pkg') else ''
    actual = _declared_package(content)
    if (actual is not None if expected == '' else actual != expected):
        raise ValueError(f'package declaration does not match path: {path}')
    return len(data)


def prepare_behavior_review(
    raw_review: Any, files: Any, baseline_map: Any, identity_hash: str,
) -> dict[str, Any]:
    """Validate and normalize approved reviewer output against pinned base bytes."""
    _require_identity_hash(identity_hash)
    if not isinstance(raw_review, dict) or set(raw_review) != {
        'approved', 'reason', 'unrelatedChanges', 'contracts', 'files',
    }:
        raise ValueError('invalid behavior review schema')
    if raw_review['approved'] is not True:
        raise ValueError('behavior review was not approved')
    reason = raw_review['reason']
    unrelated = raw_review['unrelatedChanges']
    contracts = raw_review['contracts']
    review_files = raw_review['files']
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError('invalid behavior review reason')
    if not isinstance(unrelated, list) or unrelated:
        raise ValueError('behavior review contains unrelated changes')
    if not isinstance(contracts, list) or not contracts:
        raise ValueError('behavior contracts are required')
    if not isinstance(review_files, list) or not isinstance(files, list) or not isinstance(baseline_map, Mapping):
        raise ValueError('invalid review inputs')

    source_entries = _source_entries(files)
    source_paths = {entry['path'] for entry in source_entries}
    all_files: dict[str, str] = {}
    total = 0
    for entry in files:
        if not isinstance(entry, Mapping) or not isinstance(entry.get('path'), str):
            raise ValueError('invalid candidate file entry')
        path, kind, content = entry['path'], entry.get('kind'), entry.get('content')
        if path in all_files:
            raise ValueError('duplicate candidate file')
        module = module_for_path(path)
        if not isinstance(content, str) or '\x00' in content:
            raise ValueError(f'invalid file content: {path}')
        try:
            content.encode('utf-8')
        except UnicodeEncodeError as exc:
            raise ValueError(f'invalid UTF-8 content: {path}') from exc
        if kind not in ('source', 'test') or module is None:
            raise ValueError('invalid candidate path')
        if kind == 'source' and not is_allowed_source_path(path):
            raise ValueError('invalid source path')
        if kind == 'test':
            if not is_allowed_test_path(path, identity_hash):
                raise ValueError('invalid generated test path')
            if path in baseline_map:
                raise ValueError('existing test files cannot be overwritten')
        if kind == 'source':
            before, after = entry.get('beforeSha256'), entry.get('afterSha256')
            baseline = baseline_map.get(path)
            if not _is_hash(before) or not _is_hash(after) or not isinstance(baseline, str):
                raise ValueError('invalid pinned source hashes')
            if sha256(baseline) != before or sha256(content) != after or before == after:
                raise ValueError('source content does not match pinned hashes')
        elif entry.get('beforeSha256') is not None or not _is_hash(entry.get('afterSha256')) or sha256(content) != entry['afterSha256']:
            raise ValueError('test content does not match pinned hash')
        total += _valid_content(content, path)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('candidate exceeds total size limit')
        all_files[path] = content
    if len(all_files) > MAX_CANDIDATE_FILES:
        raise ValueError('too many candidate files')

    preservation_pattern = _preservation_path_pattern(identity_hash)
    preservation_paths: set[str] = set()
    for item in review_files:
        if not isinstance(item, dict) or set(item) != {'path', 'content'}:
            raise ValueError('invalid preservation test file')
        path, content = item['path'], item['content']
        if not isinstance(path, str) or preservation_pattern.fullmatch(path) is None or path in baseline_map:
            raise ValueError('invalid or pre-existing preservation test path')
        if path in preservation_paths:
            raise ValueError('duplicate preservation test path')
        if path not in all_files or all_files[path] != content:
            raise ValueError('reviewed preservation test differs from the candidate')
        preservation_paths.add(path)
    if not preservation_paths:
        raise ValueError('approved review must add preservation tests')
    if len(all_files) > MAX_CANDIDATE_FILES:
        raise ValueError('too many candidate files')
    if preservation_paths != {path for path in all_files if preservation_pattern.fullmatch(path)}:
        raise ValueError('candidate contains preservation tests not owned by the reviewer')

    if not source_paths.issubset(baseline_map):
        raise ValueError('changed source is absent from baseline')
    for source_path in source_paths:
        baseline = baseline_map[source_path]
        if not isinstance(baseline, str):
            raise ValueError('invalid baseline source')
    if any(module_for_path(path) not in {module_for_path(src) for src in source_paths} for path in preservation_paths):
        raise ValueError('preservation tests must be in a changed source module')

    normalized_contracts: list[dict[str, Any]] = []
    contracted_sources: set[str] = set()
    contracted_tests: set[str] = set()
    for contract in contracts:
        keys = {'sourcePath', 'sourceLine', 'behavior', 'testPath', 'testMethod'}
        if not isinstance(contract, dict) or set(contract) != keys:
            raise ValueError('invalid behavior contract')
        source_path, line = contract['sourcePath'], contract['sourceLine']
        test_path, method, behavior = contract['testPath'], contract['testMethod'], contract['behavior']
        if not isinstance(source_path, str) or not isinstance(test_path, str):
            raise ValueError('invalid behavior contract paths')
        if source_path not in source_paths or type(line) is not int or line < 1:
            raise ValueError('contract references an invalid source line')
        if line > len(baseline_map[source_path].splitlines()):
            raise ValueError('contract source line exceeds baseline source')
        if test_path not in preservation_paths or not isinstance(method, str) or not method.strip() or len(method) > 200 or any(ord(char) < 32 for char in method):
            raise ValueError('contract references a missing preservation test or method')
        if not isinstance(behavior, str) or not behavior.strip() or len(behavior) > 1000:
            raise ValueError('invalid behavior contract description')
        if module_for_path(source_path) != module_for_path(test_path):
            raise ValueError('preservation tests must cover source in the same module')
        normalized_contracts.append({
            'sourcePath': source_path, 'sourceLine': line, 'behavior': behavior.strip(),
            'testPath': test_path, 'testMethod': method,
        })
        contracted_sources.add(source_path)
        contracted_tests.add(test_path)
    if contracted_sources != source_paths or contracted_tests != preservation_paths:
        raise ValueError('contracts must cover every changed source and preservation test file')
    normalized_contracts.sort(key=lambda item: (item['sourcePath'], item['sourceLine'], item['testPath'], item['testMethod']))
    return {
        'version': 1, 'approved': True, 'reason': reason.strip(), 'unrelatedChanges': [],
        'contracts': normalized_contracts, 'sourceDigest': source_digest(files),
    }



def validate_review_binding(files: Any, normalized_review: Any) -> None:
    """Validate a normalized review before verification or checkpoint reuse."""
    sources = _source_entries(files)
    if (not isinstance(normalized_review, dict)
            or set(normalized_review) != {'version', 'approved', 'reason', 'unrelatedChanges', 'contracts', 'sourceDigest'}
            or normalized_review.get('version') != 1
            or normalized_review.get('approved') is not True
            or not isinstance(normalized_review.get('reason'), str)
            or not normalized_review['reason'].strip()
            or normalized_review.get('unrelatedChanges') != []
            or normalized_review.get('sourceDigest') != source_digest(files)):
        raise ValueError('missing or mismatched approved behavior review')
    source_paths = {entry['path'] for entry in sources}
    preservation_paths: set[str] = set()
    crash_test_present = False
    for entry in files:
        if not isinstance(entry, Mapping):
            raise ValueError('invalid candidate file')
        path, kind = entry.get('path'), entry.get('kind')
        if kind == 'test':
            if (not isinstance(path, str)
                    or not re.fullmatch(r'.*/Crashlytics(?:Regression[0-9a-f]{12}Test\.(?:kt|java)|Preservation[0-9a-f]{12}Test\.kt)', path)
                    or not _is_hash(entry.get('afterSha256'))
                    or entry.get('beforeSha256') is not None):
                raise ValueError('invalid test proof path or hash')
            content = entry.get('content')
            if content is not None and (not isinstance(content, str) or sha256(content) != entry['afterSha256']):
                raise ValueError('test content does not match pinned hash')
            if 'CrashlyticsPreservation' in path:
                preservation_paths.add(path)
            else:
                crash_test_present = True
        elif kind == 'source':
            if path not in source_paths:
                raise ValueError('invalid source proof path')
            content = entry.get('content')
            if content is not None and (not isinstance(content, str) or sha256(content) != entry['afterSha256']):
                raise ValueError('source content does not match pinned hash')
        else:
            raise ValueError('invalid file kind')
    if not crash_test_present:
        raise ValueError('crash regression test is missing')
    contracts = normalized_review['contracts']
    if not isinstance(contracts, list) or not contracts:
        raise ValueError('behavior contracts are required')
    covered_sources: set[str] = set()
    covered_tests: set[str] = set()
    for contract in contracts:
        if not isinstance(contract, dict) or set(contract) != {'sourcePath', 'sourceLine', 'behavior', 'testPath', 'testMethod'}:
            raise ValueError('invalid normalized behavior contract')
        source_path, test_path = contract['sourcePath'], contract['testPath']
        line, behavior, method = contract['sourceLine'], contract['behavior'], contract['testMethod']
        if not isinstance(source_path, str) or not isinstance(test_path, str):
            raise ValueError('invalid behavior contract paths')
        if (source_path not in source_paths or test_path not in preservation_paths
                or type(line) is not int or line < 1
                or not isinstance(behavior, str) or not behavior.strip()
                or not isinstance(method, str) or not method.strip() or len(method) > 200 or any(ord(char) < 32 for char in method)
                or module_for_path(source_path) != module_for_path(test_path)):
            raise ValueError('invalid or cross-module behavior contract')
        covered_sources.add(source_path)
        covered_tests.add(test_path)
    if covered_sources != source_paths or covered_tests != preservation_paths:
        raise ValueError('behavior contracts do not cover all sources and preservation tests')


def validate_verified_checks(files: Any, verification: Any) -> None:
    """Reject incomplete, legacy, mismatched, or method-incomplete verification proofs."""
    if not isinstance(verification, dict) or verification.get('version') != VERIFICATION_VERSION or verification.get('passed') is not True:
        raise ValueError('verified v2 proof is required')
    if verification.get('candidateDigest') != candidate_digest(files):
        raise ValueError('missing or mismatched candidate digest')
    review = verification.get('behaviorReview')
    validate_review_binding(files, review)
    source_paths = {entry['path'] for entry in _source_entries(files)}
    test_entries: dict[str, str] = {}
    for entry in files:
        if not isinstance(entry, Mapping):
            raise ValueError('invalid candidate file')
        path, kind = entry.get('path'), entry.get('kind')
        if kind == 'test':
            if not isinstance(path, str) or not re.fullmatch(r'.*/Crashlytics(?:Regression|Preservation)[0-9a-f]{12}Test\.(?:kt|java)', path):
                raise ValueError('invalid test proof path')
            if path in test_entries:
                raise ValueError('duplicate test proof path')
            if not _is_hash(entry.get('afterSha256')) or entry.get('beforeSha256') is not None:
                raise ValueError('invalid test hashes')
            test_entries[path] = 'preservation' if 'CrashlyticsPreservation' in path else 'crash'
        elif kind != 'source':
            raise ValueError('invalid file kind')
    if not test_entries or 'crash' not in test_entries.values():
        raise ValueError('crash regression test is missing')
    preservation_paths = {path for path, purpose in test_entries.items() if purpose == 'preservation'}
    contracts = review['contracts']
    covered_sources: set[str] = set()
    covered_tests: set[str] = set()
    methods_by_test: dict[str, set[str]] = {}
    for contract in contracts:
        if not isinstance(contract, dict) or set(contract) != {'sourcePath', 'sourceLine', 'behavior', 'testPath', 'testMethod'}:
            raise ValueError('invalid normalized behavior contract')
        source_path, test_path, method = contract['sourcePath'], contract['testPath'], contract['testMethod']
        if source_path not in source_paths or test_path not in preservation_paths:
            raise ValueError('contract does not cover candidate source and preservation test')
        if type(contract['sourceLine']) is not int or contract['sourceLine'] < 1 or not isinstance(contract['behavior'], str) or not contract['behavior'].strip():
            raise ValueError('invalid normalized behavior contract')
        if not isinstance(method, str) or not method:
            raise ValueError('invalid preservation method name')
        if module_for_path(source_path) != module_for_path(test_path):
            raise ValueError('preservation test is not in source module')
        covered_sources.add(source_path)
        covered_tests.add(test_path)
        methods_by_test.setdefault(test_path, set()).add(method)
    if covered_sources != source_paths or covered_tests != preservation_paths:
        raise ValueError('behavior contracts do not cover all sources and preservation tests')

    checks = verification.get('checks')
    if not isinstance(checks, list):
        raise ValueError('verification checks are missing')
    expected = {(phase, purpose, path) for path, purpose in test_entries.items() for phase in ('baseline', 'candidate')}
    found: dict[tuple[str, str, str], dict[str, Any]] = {}
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError('invalid verification check')
        phase, purpose, path = check.get('phase'), check.get('purpose'), check.get('path')
        if not all(isinstance(value, str) for value in (phase, purpose, path)):
            raise ValueError('invalid verification check identifiers')
        key = (phase, purpose, path)
        if key not in expected or key in found:
            raise ValueError('unexpected or duplicate verification check')
        if not isinstance(check.get('methods'), list) or any(not isinstance(name, str) or not name for name in check['methods']):
            raise ValueError('actual passing JUnit methods are required')
        if len(set(check['methods'])) != len(check['methods']):
            raise ValueError('duplicate JUnit method evidence')
        if type(check.get('timed_out')) is not bool or type(check.get('exit_code')) is not int:
            raise ValueError('invalid verification command result')
        found[key] = check
    if set(found) != expected:
        raise ValueError('missing verification check')

    for path, purpose in test_entries.items():
        baseline = found['baseline', purpose, path]
        candidate = found['candidate', purpose, path]
        for check, phase in ((baseline, 'baseline'), (candidate, 'candidate')):
            result = check.get('test_result')
            evidence = check.get('evidence')
            if check['timed_out'] or not isinstance(evidence, dict):
                raise ValueError('missing or timed-out test evidence')
            if phase == 'candidate' or purpose == 'preservation':
                if (check['exit_code'] != 0 or result != 'passed'
                        or set(evidence) != {'source'} or evidence.get('source') != 'junit-xml'):
                    raise ValueError('candidate and preservation tests must pass in JUnit XML')
            elif phase == 'baseline':
                if check['exit_code'] == 0 or result not in ('failed', 'fatal-oom'):
                    raise ValueError('baseline crash must fail with a nonzero exit')
                if result == 'failed' and (set(evidence) != {'source'} or evidence.get('source') != 'junit-xml'):
                    raise ValueError('baseline failure requires JUnit XML evidence')
                if result == 'fatal-oom':
                    if (set(evidence) != {'source', 'package', 'pid', 'failure', 'testClass'}
                            or evidence.get('source') != 'android-logcat'
                            or evidence.get('failure') != 'fatal OutOfMemoryError'
                            or not isinstance(evidence.get('package'), str) or not evidence['package']
                            or type(evidence.get('pid')) is not int or evidence['pid'] <= 0
                            or not isinstance(evidence.get('testClass'), str) or not evidence['testClass']):
                        raise ValueError('invalid trusted Android fatal OOM evidence')
            if phase == 'candidate' and not check['methods']:
                raise ValueError('candidate must execute actual JUnit test methods')
            if purpose == 'preservation':
                required_methods = methods_by_test[path]
                if not required_methods.issubset(check['methods']):
                    raise ValueError('contract JUnit methods are missing from passing check')
    return None
