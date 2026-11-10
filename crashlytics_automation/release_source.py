"""Pins a released crash line to the tag, file, and blame commit that produced it.

Only the production release tag identifies the source: ``v<versionName>`` must
resolve to a commit whose ``build.gradle.kts`` proves both version values, the
crashed file must exist in the root app modules at that commit, and the blamed
line must be read from that same commit. Every rejection is a ``ManualReview``
with the reason a human needs; transport and API failures propagate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
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
            commit {
              oid
              author { user { login } }
            }
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
_BASENAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\.kt")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_TAG_VERSION = re.compile(r"\d+\.\d+\.\d+")
_APP_PATH = re.compile(
    r"(?:koin|core(?:/[^/]+)?|data|domain|feature/[^/]+)/src/main/(?:java|kotlin)/"
    r"(?:(?P<package>.+)/)?[^/]+\.kt"
)
_DECLARED_PACKAGE = re.compile(r"^\s*package\s+([A-Za-z0-9_.`]+)", re.MULTILINE)
_VERSION_NAME = re.compile(r'set\(\s*"versionName"\s*,\s*"([^"]+)"\s*\)')
_VERSION_CODE = re.compile(r'set\(\s*"versionCode"\s*,\s*(\d+)\s*\)')
_CLASS_TOKEN = re.compile(r"[A-Z]")
MAX_AMBIGUOUS_CANDIDATES = 8
_MAX_SAFE_INTEGER = 2**53 - 1


class _SourceUnavailable(Exception):
    """A reviewed reason why the release source cannot be pinned."""


@dataclass(frozen=True)
class _CrashFrame:
    """The stack frame reduced to what source resolution needs."""

    basename: str
    line: int
    hints: tuple[str, ...]


def resolve_release_source(
    github: Any,
    evidence: Mapping[str, Any] | None,
) -> SourceLocation | ManualReview:
    """Pin the release tag, source file, and blamed change for an alert."""
    try:
        return _pin_release_source(github, evidence)
    except _SourceUnavailable as unavailable:
        return ManualReview(str(unavailable))


def _pin_release_source(github: Any, evidence: Mapping[str, Any] | None) -> SourceLocation:
    evidence = _require_ready_evidence(evidence)
    display_version, build_version = _alert_versions(evidence)
    frame = _crash_frame(evidence)

    release_sha = _release_tag_commit(github, display_version)
    _verify_release_version(github, release_sha, display_version, build_version)
    source_path = _locate_source_file(github, release_sha, frame.basename, frame.hints)
    change_sha, author_login = _blame_release_line(github, release_sha, source_path, frame.line)

    return SourceLocation(source_path, frame.line, release_sha, change_sha, author_login)


# --- Evidence -------------------------------------------------------------


def _require_ready_evidence(evidence: object) -> Mapping[str, Any]:
    if not _is_mapping(evidence) or evidence.get("status") != "ready":
        raise _SourceUnavailable("Crashlytics 증거가 준비되지 않았습니다.")
    return evidence


def _alert_versions(evidence: Mapping[str, Any]) -> tuple[str, str]:
    display_version = evidence.get("displayVersion")
    if not isinstance(display_version, str) or _TAG_VERSION.fullmatch(display_version) is None:
        raise _SourceUnavailable("릴리스 버전을 확인할 수 없습니다.")
    build_version = str(evidence.get("buildVersion") or "")
    if _NUMERIC.fullmatch(build_version) is None:
        raise _SourceUnavailable("빌드 번호를 확인할 수 없습니다.")
    return display_version, build_version


def _crash_frame(evidence: Mapping[str, Any]) -> _CrashFrame:
    """Validate the reported stack frame and derive the file name and package hints."""
    frame = evidence.get("frame")
    frame = frame if _is_mapping(frame) else {}
    raw_file = frame.get("file")
    raw_file = raw_file.strip() if isinstance(raw_file, str) else ""
    basename = _frame_basename(raw_file)
    if _BASENAME.fullmatch(basename) is None or len(raw_file) > 512:
        raise _SourceUnavailable("난독화되었거나 확인할 수 없는 스택 프레임입니다.")

    line = _frame_line(frame.get("line"))

    raw_symbol = frame.get("symbol")
    if isinstance(raw_symbol, str) and len(raw_symbol) > 1024:
        raise _SourceUnavailable("스택 프레임 심볼을 확인할 수 없습니다.")
    symbol = raw_symbol.strip() if isinstance(raw_symbol, str) else ""
    hints = _path_hint_parts(raw_file) or _symbol_package_parts(symbol)
    return _CrashFrame(basename, line, tuple(hints))


def _frame_basename(raw_file: str) -> str:
    """Crashlytics reports a path or a qualified symbol; the last segment is the file."""
    stripped = raw_file[:-3] if raw_file.lower().endswith(".kt") else raw_file
    segments = re.split(r"[\\/.]", re.sub(r"\([^)]*\)", "", stripped))
    last_segment = segments[-1] if segments else ""
    return f"{last_segment.split('$')[0]}.kt"


def _frame_line(value: object) -> int:
    if isinstance(value, str) and re.fullmatch(r"\d{1,7}", value):
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_SAFE_INTEGER:
        raise _SourceUnavailable("스택 프레임의 줄 번호를 확인할 수 없습니다.")
    return value


# --- Release tag and version ---------------------------------------------


def _release_tag_commit(github: Any, display_version: str) -> str:
    """Resolve the release workflow's ``v<versionName>`` tag to its commit."""
    payload = github.graphql(
        TAG_QUERY,
        {"owner": OWNER, "name": REPO, "qualifiedName": f"refs/tags/v{display_version}"},
    )
    source_sha = _tag_commit_sha(payload)
    if source_sha is None:
        raise _SourceUnavailable(f"v{display_version} 릴리스 태그를 찾을 수 없습니다.")
    return source_sha


def _verify_release_version(
    github: Any,
    release_sha: str,
    display_version: str,
    build_version: str,
) -> None:
    """The tag commit must carry the exact version values that produced the crash."""
    payload = github.graphql(
        VERSION_QUERY,
        {"owner": OWNER, "name": REPO, "expression": f"{release_sha}:build.gradle.kts"},
    )
    version_text = _blob_text(payload)
    if version_text is None:
        raise _SourceUnavailable("릴리스 커밋의 버전 정보를 읽을 수 없습니다.")
    version_name = _unique_setting(version_text, _VERSION_NAME)
    version_code = _unique_setting(version_text, _VERSION_CODE)
    if (
        version_name is None
        or version_code is None
        or version_name != display_version
        or version_code != build_version
    ):
        raise _SourceUnavailable("릴리스 태그의 소스 버전이 발생 빌드와 일치하지 않습니다.")


# --- File selection -------------------------------------------------------


def _locate_source_file(
    github: Any,
    release_sha: str,
    basename: str,
    hints: tuple[str, ...],
) -> str:
    """Choose the one released app source file that matches the stack frame."""
    candidates = _release_app_files(github, release_sha, basename)
    selected = _select_candidate(candidates, hints)
    if selected is None and hints and 0 < len(candidates) <= MAX_AMBIGUOUS_CANDIDATES:
        selected = _candidate_with_declared_package(
            github, release_sha, candidates, expected_package=".".join(hints),
        )
    if selected is None:
        if len(candidates) > 1:
            raise _SourceUnavailable("스택 프레임에 해당하는 소스 파일이 여러 개라 특정할 수 없습니다.")
        raise _SourceUnavailable("릴리스 소스에서 스택 프레임 파일을 찾을 수 없습니다.")
    return selected["path"]


def _release_app_files(
    github: Any,
    release_sha: str,
    basename: str,
) -> list[Mapping[str, Any]]:
    tree = github.rest("GET", f"{REPOSITORY_PATH}/git/trees/{release_sha}?recursive=1")
    if _is_mapping(tree) and tree.get("truncated"):
        raise _SourceUnavailable("소스 트리 응답이 잘려 파일을 특정할 수 없습니다.")
    entries = tree.get("tree") if _is_mapping(tree) else None
    if not isinstance(entries, list):
        raise _SourceUnavailable("소스 트리를 읽을 수 없습니다.")
    return [
        entry
        for entry in entries
        if _is_mapping(entry)
        and entry.get("type") == "blob"
        and isinstance(entry.get("path"), str)
        and _is_app_path(entry["path"])
        and entry["path"].split("/")[-1] == basename
    ]


def _candidate_with_declared_package(
    github: Any,
    release_sha: str,
    candidates: Sequence[Mapping[str, Any]],
    *,
    expected_package: str,
) -> Mapping[str, Any] | None:
    """Break a package-hint tie by the ``package`` declaration in the file itself.

    Only a single proven match is accepted; a tie is still undecidable.
    """
    matches: list[Mapping[str, Any]] = []
    for candidate in candidates:
        payload = github.graphql(
            VERSION_QUERY,
            {"owner": OWNER, "name": REPO, "expression": f"{release_sha}:{candidate['path']}"},
        )
        if _declared_package(_blob_text(payload)) == expected_package:
            matches.append(candidate)
    return matches[0] if len(matches) == 1 else None


# --- Blame ----------------------------------------------------------------


def _blame_release_line(
    github: Any,
    release_sha: str,
    source_path: str,
    line: int,
) -> tuple[str, str | None]:
    """Read the release file and the commit that last changed the crashing line."""
    payload = github.graphql(
        BLAME_QUERY,
        {
            "owner": OWNER,
            "name": REPO,
            "expression": release_sha,
            "path": source_path,
            "sourceExpression": f"{release_sha}:{source_path}",
        },
    )
    source_text = _source_file_text(payload)
    if source_text is None:
        raise _SourceUnavailable("소스 파일 내용을 읽을 수 없습니다.")
    if line > _line_count(source_text):
        raise _SourceUnavailable("스택 프레임 줄 번호가 소스 파일 범위를 벗어났습니다.")

    ranges = _blame_ranges(payload)
    if ranges is None:
        raise _SourceUnavailable("소스 줄의 변경 이력을 읽을 수 없습니다.")
    blamed_commit = _commit_covering_line(ranges, line)
    if blamed_commit is None:
        raise _SourceUnavailable("스택 프레임 줄의 변경 이력을 찾을 수 없습니다.")

    change_sha = blamed_commit.get("oid") if _is_mapping(blamed_commit) else None
    if not isinstance(change_sha, str) or _SHA.fullmatch(change_sha) is None:
        raise _SourceUnavailable("변경 커밋을 확인할 수 없습니다.")
    return change_sha, _blame_author_login(blamed_commit)


def _blame_author_login(blamed_commit: object) -> str | None:
    if not _is_mapping(blamed_commit):
        return None
    author = _mapping_field(blamed_commit, "author")
    user = _mapping_field(author, "user")
    login = user.get("login") if user is not None else None
    return login if isinstance(login, str) and _LOGIN.fullmatch(login) else None


def _commit_covering_line(ranges: Sequence[object], line: int) -> object:
    for item in ranges:
        if not _is_mapping(item):
            continue
        start, end = item.get("startingLine"), item.get("endingLine")
        if type(start) is not int or type(end) is not int:
            continue
        if start <= line <= end:
            return item.get("commit")
    return None


# --- Response readers -----------------------------------------------------


def _is_mapping(value: object) -> bool:
    return isinstance(value, Mapping)


def _mapping_field(value: object, key: str) -> Mapping[str, Any] | None:
    if not _is_mapping(value):
        return None
    field = value.get(key)
    return field if _is_mapping(field) else None


def _repository(payload: object) -> Mapping[str, Any] | None:
    return _mapping_field(payload, "repository")


def _repository_object(payload: object) -> Mapping[str, Any] | None:
    """Return the ``repository.object`` payload of a GraphQL response."""
    return _mapping_field(_repository(payload), "object")


def _blob_text(payload: object) -> str | None:
    """Read a ``... on Blob`` text payload, rejecting binary and missing content."""
    blob = _repository_object(payload)
    if blob is None or blob.get("isBinary") or not isinstance(blob.get("text"), str):
        return None
    return blob["text"]


def _source_file_text(payload: object) -> str | None:
    blob = _mapping_field(_mapping_field(payload, "sourceFile"), "object")
    if (
        blob is None
        or blob.get("isBinary")
        or blob.get("isTruncated")
        or not isinstance(blob.get("text"), str)
    ):
        return None
    return blob["text"]


def _blame_ranges(payload: object) -> list[object] | None:
    commit = _repository_object(payload)
    blame = _mapping_field(commit, "blame")
    ranges = blame.get("ranges") if blame is not None else None
    return ranges if isinstance(ranges, list) else None


def _tag_commit_sha(payload: object) -> str | None:
    """Read the commit an annotated or lightweight release tag points at."""
    ref = _mapping_field(_repository(payload), "ref")
    target = _mapping_field(ref, "target")
    if target is None:
        return None
    if target.get("__typename") == "Tag":
        target = _mapping_field(target, "target")
    elif target.get("__typename") != "Commit":
        return None
    sha = target.get("oid") if target is not None else None
    return sha if isinstance(sha, str) and _SHA.fullmatch(sha) is not None else None


# --- Source path policy ---------------------------------------------------


def _is_app_path(path: object) -> bool:
    """Only the root app modules publish release source lines."""
    return isinstance(path, str) and _APP_PATH.fullmatch(path) is not None


def _package_parts_from_path(path: str) -> list[str]:
    match = _APP_PATH.fullmatch(path)
    package = match.group("package") if match else None
    return [part for part in package.split("/") if part] if package else []


def _normalize_package_part(value: str) -> str:
    return value.replace("`", "")


def _path_hint_parts(file: str) -> list[str]:
    cleaned = re.sub(r"\.kt$", "", file.replace("\\", "/").replace("`", ""))
    if "/" in cleaned:
        return [part for part in cleaned.split("/")[:-1] if _IDENTIFIER.fullmatch(part)]
    # A bare "ArticleVM" fragment carries no package information.
    if "." not in cleaned or _CLASS_TOKEN.match(cleaned):
        return []
    return [part for part in cleaned.split(".")[:-1] if _IDENTIFIER.fullmatch(part)]


def _symbol_package_parts(symbol: str) -> list[str]:
    if not symbol:
        return []
    without_location = re.sub(r"\([^)]*\)", " ", symbol).strip()
    if without_location.startswith("at "):
        without_location = without_location[3:]
    tokens = [
        _normalize_package_part(token)
        for token in re.split(r"[\s/.]+", without_location)
        if _IDENTIFIER.fullmatch(token)
    ]
    first_class = next((index for index, token in enumerate(tokens) if _CLASS_TOKEN.match(token)), -1)
    return tokens[:first_class] if first_class > 0 else []


def _common_suffix_length(left: Sequence[str], right: Sequence[str]) -> int:
    score = 0
    while score < len(left) and score < len(right) and left[-1 - score] == right[-1 - score]:
        score += 1
    return score


def _select_candidate(
    candidates: Sequence[Mapping[str, Any]],
    hints: Sequence[str],
) -> Mapping[str, Any] | None:
    """Pick one candidate by the longest shared package suffix; ties stay undecided."""
    if len(candidates) <= 1:
        return candidates[0] if candidates else None
    if not hints:
        return None
    scored = [
        (candidate, _common_suffix_length(_package_parts_from_path(candidate["path"]), hints))
        for candidate in candidates
    ]
    best = max(score for _, score in scored)
    if best == 0:
        return None
    top = [candidate for candidate, score in scored if score == best]
    return top[0] if len(top) == 1 else None


# --- Text helpers ---------------------------------------------------------


def _declared_package(text: object) -> str | None:
    if not isinstance(text, str):
        return None
    match = _DECLARED_PACKAGE.search(text)
    return _normalize_package_part(match.group(1)) if match else None


def _unique_setting(text: str, pattern: re.Pattern[str]) -> str | None:
    values = {match.group(1) for match in pattern.finditer(text)}
    return next(iter(values)) if len(values) == 1 else None


def _line_count(text: str) -> int:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return len(lines)
