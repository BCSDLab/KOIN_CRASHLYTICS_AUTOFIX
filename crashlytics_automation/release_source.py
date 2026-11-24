"""Pins release commits and investigation-selected source anchors to GitHub."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .models import ManualReview, SourceLocation
from .repository import OWNER, REPO, REPOSITORY_PATH

TAG_QUERY = """
query ReleaseTag($owner: String!, $name: String!, $qualifiedName: String!) {
  repository(owner: $owner, name: $name) {
    ref(qualifiedName: $qualifiedName) {
      target {
        __typename
        ... on Commit { oid }
        ... on Tag { target { ... on Commit { oid } } }
      }
    }
  }
}"""

VERSION_QUERY = """
query VersionFile($owner: String!, $name: String!, $expression: String!) {
  repository(owner: $owner, name: $name) {
    object(expression: $expression) {
      ... on Blob { text isBinary }
    }
  }
}"""

BLAME_QUERY = """
query LineBlame($owner: String!, $name: String!, $expression: String!, $path: String!, $sourceExpression: String!) {
  repository(owner: $owner, name: $name) {
    object(expression: $expression) {
      ... on Commit {
        blame(path: $path) {
          ranges {
            startingLine
            endingLine
            commit { oid author { user { login } } }
          }
        }
      }
    }
  }
  sourceFile: repository(owner: $owner, name: $name) {
    object(expression: $sourceExpression) {
      ... on Blob { text isTruncated isBinary }
    }
  }
}"""

_SHA = re.compile(r"[0-9a-f]{40}")
_NUMERIC = re.compile(r"\d+")
_TAG_VERSION = re.compile(r"\d+\.\d+\.\d+")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")
_APP_PATH = re.compile(
    r"(?:koin|core(?:/[^/]+)?|data|domain|feature/[^/]+)/src/main/(?:java|kotlin)/"
    r"(?:[A-Za-z0-9_]+/)*[A-Za-z_][A-Za-z0-9_]*\.(?:kt|java)"
)
_VERSION_NAME = re.compile(r'set\(\s*"versionName"\s*,\s*"([^"]+)"\s*\)')
_VERSION_CODE = re.compile(r'set\(\s*"versionCode"\s*,\s*(\d+)\s*\)')
_MAX_SAFE_INTEGER = 2**53 - 1


class _SourceUnavailable(Exception):
    """A reviewed reason why the release source cannot be pinned."""


def resolve_release_commit(github: Any, evidence: Mapping[str, Any] | None) -> str | ManualReview:
    """Pin and version-check the release tag without requiring a crash frame."""
    try:
        if not isinstance(evidence, Mapping) or evidence.get("status") != "ready":
            raise _SourceUnavailable("Crashlytics 증거가 준비되지 않았습니다.")
        display_version = evidence.get("displayVersion")
        if not isinstance(display_version, str) or _TAG_VERSION.fullmatch(display_version) is None:
            raise _SourceUnavailable("릴리스 버전을 확인할 수 없습니다.")
        build_version = str(evidence.get("buildVersion") or "")
        if _NUMERIC.fullmatch(build_version) is None:
            raise _SourceUnavailable("빌드 번호를 확인할 수 없습니다.")
        payload = github.graphql(
            TAG_QUERY,
            {"owner": OWNER, "name": REPO, "qualifiedName": f"refs/tags/v{display_version}"},
        )
        release_sha = _tag_commit_sha(payload)
        if release_sha is None:
            raise _SourceUnavailable(f"v{display_version} 릴리스 태그를 찾을 수 없습니다.")
        version_payload = github.graphql(
            VERSION_QUERY,
            {"owner": OWNER, "name": REPO, "expression": f"{release_sha}:build.gradle.kts"},
        )
        version_text = _blob_text(version_payload)
        if version_text is None or _unique_setting(version_text, _VERSION_NAME) != display_version \
                or _unique_setting(version_text, _VERSION_CODE) != build_version:
            raise _SourceUnavailable("릴리스 태그의 소스 버전이 발생 빌드와 일치하지 않습니다.")
        return release_sha
    except _SourceUnavailable as unavailable:
        return ManualReview(str(unavailable))


def resolve_investigated_source(
    github: Any, *, release_sha: str, path: str, line: int,
) -> SourceLocation | ManualReview:
    """Validate an investigation-selected source anchor against released bytes and blame."""
    try:
        if not isinstance(release_sha, str) or _SHA.fullmatch(release_sha) is None:
            raise _SourceUnavailable("릴리스 커밋 SHA가 올바르지 않습니다.")
        if not isinstance(path, str) or _APP_PATH.fullmatch(path) is None or ".." in path.split("/"):
            raise _SourceUnavailable("조사된 소스 경로가 앱의 릴리스 소스가 아닙니다.")
        if type(line) is not int or not 0 < line <= _MAX_SAFE_INTEGER:
            raise _SourceUnavailable("조사된 소스 줄 번호가 올바르지 않습니다.")
        payload = github.graphql(
            BLAME_QUERY,
            {
                "owner": OWNER,
                "name": REPO,
                "expression": release_sha,
                "path": path,
                "sourceExpression": f"{release_sha}:{path}",
            },
        )
        source_text = _source_file_text(payload)
        if source_text is None:
            raise _SourceUnavailable("릴리스 소스 파일 내용을 읽을 수 없습니다.")
        if line > _line_count(source_text):
            raise _SourceUnavailable("조사된 줄 번호가 릴리스 소스 파일 범위를 벗어났습니다.")
        commit = _commit_covering_line(_blame_ranges(payload), line)
        sha = commit.get("oid") if isinstance(commit, Mapping) else None
        if not isinstance(sha, str) or _SHA.fullmatch(sha) is None:
            raise _SourceUnavailable("조사된 줄의 변경 이력을 확인할 수 없습니다.")
        author = _mapping_field(commit, "author")
        user = _mapping_field(author, "user")
        login = user.get("login") if user is not None else None
        return SourceLocation(path, line, release_sha, sha,
                              login if isinstance(login, str) and _LOGIN.fullmatch(login) else None)
    except _SourceUnavailable as unavailable:
        return ManualReview(str(unavailable))


def _commit_covering_line(ranges: object, line: int) -> object:
    if not isinstance(ranges, list):
        return None
    for item in ranges:
        if not isinstance(item, Mapping):
            continue
        start, end = item.get("startingLine"), item.get("endingLine")
        if type(start) is int and type(end) is int and start <= line <= end:
            return item.get("commit")
    return None


def _mapping_field(value: object, key: str) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    field = value.get(key)
    return field if isinstance(field, Mapping) else None


def _repository(payload: object) -> Mapping[str, Any] | None:
    return _mapping_field(payload, "repository")


def _repository_object(payload: object) -> Mapping[str, Any] | None:
    return _mapping_field(_repository(payload), "object")


def _blob_text(payload: object) -> str | None:
    blob = _repository_object(payload)
    if blob is None or blob.get("isBinary") or not isinstance(blob.get("text"), str):
        return None
    return blob["text"]


def _source_file_text(payload: object) -> str | None:
    blob = _mapping_field(_mapping_field(payload, "sourceFile"), "object")
    if blob is None or blob.get("isBinary") or blob.get("isTruncated") \
            or not isinstance(blob.get("text"), str):
        return None
    return blob["text"]


def _blame_ranges(payload: object) -> object:
    blame = _mapping_field(_repository_object(payload), "blame")
    return blame.get("ranges") if blame is not None else None


def _tag_commit_sha(payload: object) -> str | None:
    ref = _mapping_field(_repository(payload), "ref")
    target = _mapping_field(ref, "target")
    if target is None:
        return None
    if target.get("__typename") == "Tag":
        target = _mapping_field(target, "target")
    elif target.get("__typename") != "Commit":
        return None
    sha = target.get("oid") if target is not None else None
    return sha if isinstance(sha, str) and _SHA.fullmatch(sha) else None


def _unique_setting(text: str, pattern: re.Pattern[str]) -> str | None:
    values = {match.group(1) for match in pattern.finditer(text)}
    return next(iter(values)) if len(values) == 1 else None


def _line_count(text: str) -> int:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return len(lines)
