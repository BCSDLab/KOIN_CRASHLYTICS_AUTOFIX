"""Proves who owns a released crash line: a merged AI fix, or a real human.

The AI proof requires the blame commit to be a squash merge commit or the
second parent of a merge commit from a configured-bot crashlytics fix PR.
Branches count at either naming generation: the current
``hotfix/<target>/crashlytics-<hash>`` (whose base branch must be that target)
and the historical ``fix/crashlytics-<hash>``. The manifest at the blamed
revision must validate and list the crashed file. The human
fallback never assigns a bot, bot-like, or organization account. API and schema
failures raise; "no AI origin" is only reported after a complete lookup.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Mapping
from urllib.parse import quote

from .candidate import manifest_path_for, validate_manifest
from .models import MergedAiFix, SourceLocation
from .repository import OWNER, REPO, REPOSITORY_PATH, TARGET_BRANCHES

AI_ORIGIN_QUERY = """
query OriginPulls($owner: String!, $name: String!, $oid: GitObjectID!) {
  repository(owner: $owner, name: $name) {
    object(oid: $oid) {
      __typename
      ... on Commit {
        associatedPullRequests(first: 20) {
          nodes {
            number
            merged
            headRefName
            baseRefName
            author { __typename login }
            mergeCommit {
              oid
              parents(first: 2) { totalCount nodes { oid } }
            }
          }
        }
      }
    }
  }
}"""

USER_QUERY = """
query AccountType($login: String!) {
  user(login: $login) { __typename }
}"""

_FIX_BRANCH = re.compile(r"fix/crashlytics-([0-9a-f]{64})")
_HOTFIX_BRANCH = re.compile(
    rf"hotfix/({'|'.join(map(re.escape, TARGET_BRANCHES))})/crashlytics-([0-9a-f]{{64}})"
)
_BOT_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}(?:\[bot\])?")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")
_PAGE_SIZE = 100
_HISTORY_PAGES = 5
_ASSIGNEE_PAGES = 10
_MAX_AUTHOR_CANDIDATES = 20
_MAX_SAFE_INTEGER = 2**53 - 1


def find_ai_fix_for_line(
    github: Any,
    source: SourceLocation,
    *,
    bot_logins: tuple[str, ...],
) -> MergedAiFix | None:
    """Return the merged AI fix that produced the blamed release line, if any.

    A pull request counts only when the blamed commit is its merge commit
    (historical squash) or its merged head (second parent), its head branch is
    ``hotfix/<target>/crashlytics-<identityHash>`` targeting that same base
    branch or the historical ``fix/crashlytics-<identityHash>``, its author is a
    current or explicitly trusted former bot, and the manifest committed at that
    exact revision validates for that identity and lists the crashed file as a
    modified source file. Anything else — unmerged PRs, other bots, human PRs,
    unrelated files or revisions — is not proof.
    """
    if not isinstance(bot_logins, tuple) or not bot_logins:
        raise ValueError("Invalid bot logins")
    app_logins = {_app_login(login) for login in bot_logins}
    for pull in _associated_pulls(github, source.change_sha):
        number, merged, head = pull.get("number"), pull.get("merged"), pull.get("headRefName")
        base = pull.get("baseRefName")
        if (
            type(number) is not int or not 0 < number <= _MAX_SAFE_INTEGER
            or not isinstance(merged, bool) or not isinstance(head, str) or not isinstance(base, str)
        ):
            raise RuntimeError("GitHub origin lookup failed")
        if not merged or not _is_bot_author(pull.get("author"), app_logins):
            continue
        identity_hash = _fix_branch_identity(head, base)
        if identity_hash is None or not _merge_commit_matches(pull.get("mergeCommit"), source.change_sha):
            continue
        if not _manifest_lists_crashed_file(github, source.change_sha, identity_hash, source.path):
            continue
        return MergedAiFix(pull_number=number, commit_sha=source.change_sha)
    return None


# --- AI origin ------------------------------------------------------------


def _app_login(bot_login: str) -> str:
    """Validate the configured bot login and match it the way GraphQL reports it.

    GraphQL ``Bot.login`` omits REST's ``[bot]`` suffix, and a same-named
    ``User`` account is not the GitHub App, so both the login and the account
    type are compared.
    """
    if not isinstance(bot_login, str) or _BOT_LOGIN.fullmatch(bot_login) is None:
        raise ValueError("Invalid bot login")
    return bot_login.removesuffix("[bot]").casefold()


def _is_bot_author(author: object, app_logins: set[str]) -> bool:
    if not isinstance(author, Mapping):
        return False
    account_type = author.get("__typename")
    if not isinstance(account_type, str):
        raise RuntimeError("GitHub origin lookup failed")
    return account_type == "Bot" and str(author.get("login", "")).casefold() in app_logins


def _fix_branch_identity(head_ref: str, base_ref: object) -> str | None:
    """Identity hash of an automation fix branch at either naming generation.

    ``hotfix/<target>/crashlytics-<hash>`` is the current scheme and must target
    the branch it names. ``fix/crashlytics-<hash>`` is historical: old merged
    pull requests still prove AI origin, but nothing new is written to them.
    """
    hotfix = _HOTFIX_BRANCH.fullmatch(head_ref)
    if hotfix is not None:
        return hotfix.group(2) if base_ref == hotfix.group(1) else None
    legacy = _FIX_BRANCH.fullmatch(head_ref)
    return legacy.group(1) if legacy else None


def _merge_commit_matches(merge_commit: object, change_sha: str) -> bool:
    if not isinstance(merge_commit, Mapping):
        return False
    if merge_commit.get("oid") == change_sha:
        return True
    parents = _mapping_field(merge_commit, "parents")
    nodes = parents.get("nodes") if parents is not None else None
    return (
        parents is not None and parents.get("totalCount") == 2
        and isinstance(nodes, list) and len(nodes) == 2
        and isinstance(nodes[1], Mapping) and nodes[1].get("oid") == change_sha
    )


def _manifest_lists_crashed_file(
    github: Any,
    revision: str,
    identity_hash: str,
    source_path: str,
) -> bool:
    """Validate the manifest committed at the blamed AI revision."""
    manifest = _manifest_at(github, revision, identity_hash)
    # A later release still blames the same AI commit, so the manifest
    # release SHA may differ; the branch hash, file, and kind must not.
    if manifest is None or not validate_manifest(manifest, {"identityHash": identity_hash})["valid"]:
        return False
    files = manifest.get("files")
    return isinstance(files, list) and any(
        _is_mapping(file) and file.get("path") == source_path and file.get("kind") == "source"
        for file in files
    )


def _associated_pulls(github: Any, commit_sha: str) -> list[Mapping[str, Any]]:
    payload = github.graphql(
        AI_ORIGIN_QUERY,
        {"owner": OWNER, "name": REPO, "oid": commit_sha},
    )
    commit = _mapping_field(_mapping_field(payload, "repository"), "object")
    connection = _mapping_field(commit, "associatedPullRequests")
    nodes = connection.get("nodes") if connection is not None else None
    if commit is None or commit.get("__typename") != "Commit" \
            or not isinstance(nodes, list) or not all(_is_mapping(node) for node in nodes):
        raise RuntimeError("GitHub origin lookup failed")
    return nodes


# --- Human assignment -----------------------------------------------------


def find_human_assignee(
    github: Any,
    *,
    bot_login: str,
    source: SourceLocation | None = None,
) -> str:
    """Pick a real, assignable human login: blamed author, then history, then repo.

    Bots (the configured automation bot, ``[bot]`` accounts, and API ``Bot``
    accounts) are never assigned. Raises ``RuntimeError`` with a safe reason
    when no eligible person exists, so the caller retries instead of assigning
    a fabricated login.
    """
    if not isinstance(bot_login, str) or _BOT_LOGIN.fullmatch(bot_login) is None:
        raise ValueError("Invalid bot login")

    if source is not None:
        blamed = source.author_login
        if blamed is not None and _is_eligible_human(github, blamed, bot_login):
            return blamed
        prior = _prior_human_author(github, source, bot_login)
        if prior is not None:
            return prior

    login = _repository_human(github, bot_login)
    if login is None:
        raise RuntimeError("이 저장소에서 배정 가능한 사람 담당자를 찾을 수 없습니다.")
    return login


def _is_human_user(github: Any, login: object, bot_login: str) -> bool:
    """Prove an account is a real human user, not a bot or organization."""
    if not isinstance(login, str):
        return False
    lowered = login.casefold()
    if lowered == bot_login.casefold() or lowered.endswith("[bot]"):
        return False
    if _LOGIN.fullmatch(login) is None:
        return False
    payload = github.graphql(USER_QUERY, {"login": login})
    if not _is_mapping(payload):
        raise RuntimeError("GitHub user lookup failed")
    user = payload.get("user")
    if user is None:
        return False
    if not _is_mapping(user) or not isinstance(user.get("__typename"), str):
        raise RuntimeError("GitHub user lookup failed")
    return user["__typename"] == "User"


def _is_assignable(github: Any, login: str) -> bool:
    # Only a user accepted by the assignees endpoint can be assigned.
    try:
        github.rest("GET", f"{REPOSITORY_PATH}/assignees/{quote(login, safe='')}")
    except Exception as error:  # noqa: BLE001 - 404/422 mean "not assignable", others propagate
        if getattr(error, "status", None) in (404, 422):
            return False
        raise
    return True


def _is_eligible_human(github: Any, login: object, bot_login: str) -> bool:
    return _is_human_user(github, login, bot_login) and _is_assignable(github, login)


def _prior_human_author(github: Any, source: SourceLocation, bot_login: str) -> str | None:
    """Latest eligible human author of the released file *before* the blamed change.

    The listing is anchored at the released commit, so entries are newest first:
    anything up to and including the blamed commit is the AI/bot change itself and
    never counts. Only older commits of the same file are considered.
    """
    reached_blamed_change = False
    examined: set[str] = set()
    for page in range(1, _HISTORY_PAGES + 1):
        commits = _file_history(github, source, page)
        for commit in commits:
            sha = commit.get("sha")
            if not isinstance(sha, str):
                raise RuntimeError("GitHub commit listing failed")
            if not reached_blamed_change:
                reached_blamed_change = sha == source.change_sha
                continue
            author = commit.get("author")
            login = author.get("login") if _is_mapping(author) else None
            if not isinstance(login, str) or login in examined:
                continue
            examined.add(login)
            if len(examined) > _MAX_AUTHOR_CANDIDATES:
                return None
            if _is_eligible_human(github, login, bot_login):
                return login
        if len(commits) < _PAGE_SIZE:
            break
    return None


def _file_history(github: Any, source: SourceLocation, page: int) -> list[Mapping[str, Any]]:
    commits = github.rest(
        "GET",
        f"{REPOSITORY_PATH}/commits?path={quote(source.path, safe='')}"
        f"&sha={source.release_sha}&per_page={_PAGE_SIZE}&page={page}",
    )
    if not isinstance(commits, list) or not all(_is_mapping(commit) for commit in commits):
        raise RuntimeError("GitHub commit listing failed")
    return commits


def _repository_human(github: Any, bot_login: str) -> str | None:
    """Choose an assignable human owner or collaborator as the last resort."""
    logins: set[str] = set()
    for page in range(1, _ASSIGNEE_PAGES + 1):
        people = _assignee_page(github, page)
        for person in people:
            login = person.get("login")
            if not isinstance(login, str) or person.get("type") != "User":
                continue
            lowered = login.casefold()
            if lowered == bot_login.casefold() or lowered.endswith("[bot]"):
                continue
            logins.add(login)
        if len(people) < _PAGE_SIZE:
            break
    # Deterministic order: the repository owner first, then by login.
    ordered = sorted(
        logins,
        key=lambda login: (login.casefold() != OWNER.casefold(), login.casefold(), login),
    )
    return next(
        (
            login
            for login in ordered[:_MAX_AUTHOR_CANDIDATES]
            if _is_eligible_human(github, login, bot_login)
        ),
        None,
    )


def _assignee_page(github: Any, page: int) -> list[Mapping[str, Any]]:
    people = github.rest("GET", f"{REPOSITORY_PATH}/assignees?per_page={_PAGE_SIZE}&page={page}")
    if not isinstance(people, list) or not all(_is_mapping(person) for person in people):
        raise RuntimeError("GitHub assignee listing failed")
    return people


# --- GitHub reads ---------------------------------------------------------


def _read_text(github: Any, revision: str, path: str) -> str | None:
    """Read one file blob at an exact revision; a missing file is not a failure."""
    try:
        result = github.rest(
            "GET",
            f"{REPOSITORY_PATH}/contents/{quote(path, safe='/')}?ref={quote(revision, safe='')}",
        )
    except Exception as error:  # noqa: BLE001 - 404 means the file does not exist
        if getattr(error, "status", None) == 404:
            return None
        raise
    if (
        not _is_mapping(result)
        or result.get("type") != "file"
        or result.get("encoding") != "base64"
        or not isinstance(result.get("content"), str)
    ):
        raise RuntimeError("GitHub content lookup failed")
    try:
        return base64.b64decode("".join(result["content"].split()), validate=True).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError) as error:
        raise RuntimeError("GitHub content lookup failed") from error


def _manifest_at(github: Any, revision: str, identity_hash: str) -> Mapping[str, Any] | None:
    """Read the pinned manifest. A malformed artifact is an error, not a non-match."""
    text = _read_text(github, revision, manifest_path_for(identity_hash))
    if text is None:
        return None
    try:
        manifest = json.loads(text)
    except ValueError as error:
        raise RuntimeError("GitHub origin manifest failed") from error
    if not _is_mapping(manifest):
        raise RuntimeError("GitHub origin manifest failed")
    return manifest


def _is_mapping(value: object) -> bool:
    return isinstance(value, Mapping)


def _mapping_field(value: object, key: str) -> Mapping[str, Any] | None:
    if not _is_mapping(value):
        return None
    field = value.get(key)
    return field if _is_mapping(field) else None
