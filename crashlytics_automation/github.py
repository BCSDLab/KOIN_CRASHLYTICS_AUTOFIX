"""Explicitly isolated GitHub App transports for crash automation.

The application scope reaches application-owned endpoints under the fixed
repository. The automation scope can only dispatch its trusted investigation
workflow. Crash report contents never become an API destination, and provider
error bodies are never surfaced because they can echo credentials.

Installation tokens are minted on demand with a short-lived RS256 app JWT. The
transport is a plain ``requests.Session`` (or an injected equivalent exposing
``request()``) with redirects disabled and a hard timeout.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from typing import Any

import jwt

from .repository import (
    AUTOMATION_DISPATCH_PATH,
    AUTOMATION_REPOSITORY,
    OWNER,
    REPO,
    REPOSITORY,
    REPOSITORY_PATH,
    STATE_REFERENCE,
)

API_ROOT = "https://api.github.com"
GRAPHQL_PATH = "/graphql"
REQUEST_TIMEOUT_SECONDS = 30
_API_VERSION = "2022-11-28"


class GitHubError(RuntimeError):
    """A GitHub API response the caller must not treat as data."""

    def __init__(self, status: int) -> None:
        super().__init__(f"GitHub API returned {status}")
        self.status = status


class GitHub:
    """Authenticated, repository-scoped client returned by :func:`create_github`."""

    def __init__(self, token: str, session: Any, repository: str = REPOSITORY) -> None:
        if repository not in (REPOSITORY, AUTOMATION_REPOSITORY):
            raise ValueError("GitHub repository outside the configured scopes")
        self._token = token
        self._session = session
        self._repository = repository

    def rest(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:

        if self._repository == AUTOMATION_REPOSITORY:
            if method != 'POST' or path != AUTOMATION_DISPATCH_PATH or body != {'ref': 'main'}:
                raise ValueError("Automation scope only permits the trusted workflow dispatch")
        else:
            # API destinations are application-owned, never copied from crash reports.
            if path not in (GRAPHQL_PATH, REPOSITORY_PATH) and not path.startswith(
                (f"{REPOSITORY_PATH}/", "/search/issues?")
            ):
                raise ValueError("GitHub endpoint outside the configured repository scope")
            if (
                method == 'PATCH'
                and path == f'{REPOSITORY_PATH}/git/refs/{STATE_REFERENCE.removeprefix("refs/")}'
                and (not isinstance(body, dict) or body.get('force', False) is not False)
            ):
                raise ValueError('Investigation state must advance without force')
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "Content-Type": "application/json",
        }
        response = self._session.request(
            method,
            f"{API_ROOT}{path}",
            headers=headers,
            data=None if body is None else json.dumps(body, ensure_ascii=False),
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        if not 200 <= response.status_code < 300:
            raise GitHubError(response.status_code)
        if response.status_code == 204:
            return None
        return response.json()

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        result = self.rest("POST", GRAPHQL_PATH, {"query": query, "variables": variables})
        if not isinstance(result, dict) or result.get("errors") or not isinstance(result.get("data"), dict):
            raise RuntimeError("GitHub GraphQL lookup failed")
        return result["data"]

    def checkout(self, ref: str, directory: Any) -> None:
        """Fetch an exact commit without persisting installation credentials in Git config."""
        import base64
        import os
        import subprocess
        from pathlib import Path

        if self._repository == AUTOMATION_REPOSITORY:
            raise ValueError("Automation scope cannot check out repositories")
        if not isinstance(ref, str) or re.fullmatch(r'[0-9a-f]{40}', ref) is None:
            raise ValueError('Checkout requires a pinned commit')
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=True)
        if any(destination.iterdir()):
            raise ValueError('Checkout destination must be empty')
        environment = dict(os.environ)
        for key in tuple(environment):
            if key.startswith(('GIT_TRACE', 'GIT_CONFIG_')) or key == 'GIT_CURL_VERBOSE':
                environment.pop(key, None)
        authorization = base64.b64encode(f'x-access-token:{self._token}'.encode()).decode('ascii')
        environment.update({
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
            'GIT_CONFIG_COUNT': '4',
            'GIT_CONFIG_KEY_0': 'http.https://github.com/.extraheader',
            'GIT_CONFIG_VALUE_0': f'AUTHORIZATION: basic {authorization}',
            'GIT_CONFIG_KEY_1': 'credential.helper', 'GIT_CONFIG_VALUE_1': '',
            'GIT_CONFIG_KEY_2': 'core.hooksPath', 'GIT_CONFIG_VALUE_2': os.devnull,
            'GIT_CONFIG_KEY_3': 'http.followRedirects', 'GIT_CONFIG_VALUE_3': 'false',
        })
        commands = [
            ['git', 'init', '--quiet', str(destination)],
            ['git', '-C', str(destination), 'fetch', '--quiet', '--depth=1',
             f'https://github.com/{OWNER}/{REPO}.git', ref],
            ['git', '-C', str(destination), 'checkout', '--quiet', '--detach', 'FETCH_HEAD'],
        ]
        for command in commands:
            try:
                result = subprocess.run(command, env=environment, capture_output=True, timeout=180, check=False)
            except (OSError, subprocess.TimeoutExpired):
                raise RuntimeError('Pinned source checkout could not complete') from None
            if result.returncode:
                raise RuntimeError(f'Pinned source checkout failed (exit {result.returncode})')


def create_github(
    app_id: str,
    installation_id: str,
    private_key: str,
    *,
    repository: str = REPOSITORY,
    permissions: dict[str, str] | None = None,
    session: Any = None,
) -> GitHub:
    """Mint a repository-scoped installation token and return the API client.

    ``session`` must expose ``request(method, url, **kwargs)`` like
    ``requests.Session``; tests inject a deterministic in-memory client.
    The automation repository accepts only the Actions:write permission.
    """
    if repository not in (REPOSITORY, AUTOMATION_REPOSITORY):
        raise ValueError("GitHub repository outside the configured scopes")
    if repository == AUTOMATION_REPOSITORY and permissions != {'actions': 'write'}:
        raise ValueError("Automation scope requires exactly Actions:write")
    app_id_text = str(app_id)
    installation_text = str(installation_id)
    if not app_id_text.isdecimal() or not installation_text.isdecimal():
        raise ValueError("Invalid GitHub App configuration")

    if session is None:
        import requests

        session = requests.Session()

    now = int(time.time())
    app_token = jwt.encode({"iat": now - 60, "exp": now + 600, "iss": app_id_text},
                           private_key, algorithm="RS256")
    token_body: dict[str, Any] = {"repositories": [repository.split('/', 1)[1]]}
    if permissions is not None:
        token_body["permissions"] = permissions
    response = session.request(
        "POST",
        f"{API_ROOT}/app/installations/{installation_text}/access_tokens",
        headers={
            "Authorization": f"Bearer {app_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "Content-Type": "application/json",
        },
        data=json.dumps(token_body, ensure_ascii=False),
        timeout=REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )
    if not 200 <= response.status_code < 300:
        raise GitHubError(response.status_code)
    payload = response.json()
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError("GitHub installation token unavailable")
    return GitHub(token, session, repository=repository)


def _issue_number(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("Invalid GitHub issue number")
    return value


def issue_marker(issue_id: str) -> str:
    if not isinstance(issue_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", issue_id) is None:
        raise ValueError("Invalid Crashlytics issue ID")
    return f"<!-- crashlytics-issue:{issue_id} -->"


def find_issue(github: GitHub, issue_id: str) -> dict[str, Any] | None:
    marker = issue_marker(issue_id)
    query = f'repo:{OWNER}/{REPO} is:issue in:body "{issue_id}"'
    matches: list[dict[str, Any]] = []
    page = 1
    while page <= 10:
        result = github.rest(
            "GET",
            f"/search/issues?q={urllib.parse.quote(query, safe='')}&per_page=100&page={page}",
        )
        if not isinstance(result, dict):
            raise RuntimeError("Incomplete GitHub issue search")
        total = result.get("total_count")
        items = result.get("items")
        if isinstance(total, bool) or not isinstance(total, int) or not isinstance(items, list):
            raise RuntimeError("Incomplete GitHub issue search")
        if result.get("incomplete_results") or total > 1000:
            raise RuntimeError("Incomplete GitHub issue search")
        for issue in items:
            body = issue.get("body") if isinstance(issue, dict) else None
            if isinstance(body, str) and marker in body:
                matches.append(issue)
        if page * 100 >= total:
            break
        page += 1
    if len(matches) > 1:
        raise RuntimeError("Multiple GitHub issues have the same Crashlytics ID")
    return matches[0] if matches else None


def has_comment(github: GitHub, issue_number: int, marker: str) -> bool:
    issue_number = _issue_number(issue_number)
    page = 1
    while True:
        comments = github.rest(
            "GET",
            f"{REPOSITORY_PATH}/issues/{issue_number}/comments?per_page=100&page={page}",
        )
        if not isinstance(comments, list):
            raise RuntimeError("GitHub comment listing failed")
        for comment in comments:
            body = comment.get("body") if isinstance(comment, dict) else None
            if isinstance(body, str) and marker in body:
                return True
        if len(comments) < 100:
            return False
        page += 1


def comment_once(github: GitHub, issue_number: int, marker: str, body: str) -> None:
    issue_number = _issue_number(issue_number)
    if not has_comment(github, issue_number, marker):
        github.rest(
            "POST",
            f"{REPOSITORY_PATH}/issues/{issue_number}/comments",
            {"body": f"{body}\n\n{marker}"},
        )
