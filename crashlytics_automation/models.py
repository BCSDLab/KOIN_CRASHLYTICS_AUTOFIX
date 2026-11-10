"""Named internal state. Camel-case dictionaries are task/API payloads, not domain objects."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CrashAlert:
    issue_id: str
    app_version: str
    event_id: str
    published_at: str
    title: str
    subtitle: str

    def to_payload(self) -> dict[str, Any]:
        return {
            'issueId': self.issue_id,
            'appVersion': self.app_version,
            'eventId': self.event_id,
            'time': self.published_at,
            'title': self.title,
            'subtitle': self.subtitle,
        }


@dataclass(frozen=True)
class SourceLocation:
    """The crash line in a release, and the commit that last changed that line."""

    path: str
    line: int
    release_sha: str
    change_sha: str
    author_login: str | None

    def __post_init__(self) -> None:
        if (not isinstance(self.path, str)
                or re.fullmatch(r'(?:koin|data|domain|core(?:/[^/]+)?|feature/[^/]+)/src/main/(?:java|kotlin)/.+\.kt', self.path) is None
                or '..' in self.path.split('/')
                or type(self.line) is not int or not 0 < self.line <= 10_000_000):
            raise ValueError('Invalid released source location')
        for value in (self.release_sha, self.change_sha):
            if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{40}', value) is None:
                raise ValueError('Invalid released source commit')

    def to_payload(self) -> dict[str, Any]:
        return {
            'status': 'ready',
            'path': self.path,
            'line': self.line,
            'sourceSha': self.release_sha,
            'changeSha': self.change_sha,
            'authorLogin': self.author_login,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any] | None) -> SourceLocation | None:
        if payload is None:
            return None
        if not isinstance(payload, dict) or payload.get('status') != 'ready':
            raise ValueError('Invalid released source payload')
        return cls(payload['path'], payload['line'], payload['sourceSha'],
                   payload['changeSha'], payload.get('authorLogin'))


@dataclass(frozen=True)
class MergedAiFix:
    pull_number: int
    commit_sha: str


@dataclass(frozen=True)
class ManualReview:
    reason: str


@dataclass(frozen=True)
class PublishedFix:
    pull_number: int
    head_sha: str
    base_sha: str
    manifest_digest: str
    base_branch: str
    reused: bool = False

    def to_payload(self) -> dict[str, Any]:
        return {
            'outcome': 'existing' if self.reused else 'created',
            'pullNumber': self.pull_number,
            'headSha': self.head_sha,
            'baseSha': self.base_sha,
            'manifestDigest': self.manifest_digest,
            'baseBranch': self.base_branch,
        }


@dataclass(frozen=True)
class FileChange:
    path: str
    content: str


@dataclass(frozen=True)
class FixPlan:
    """Validated source/test changes plus the exact manifest to commit with them."""

    manifest: dict[str, Any]
    changes: tuple[FileChange, ...]
    title: str
    issue_number: int
    base_branch: str


@dataclass
class CrashContext:
    """Keep partial evidence available when a retry ends in human handoff."""

    alert: CrashAlert
    evidence: dict[str, Any] | None = None
    source: SourceLocation | None = None
    previous_ai_fix: MergedAiFix | None = None
    issue_number: int | None = None
    pull_numbers: tuple[int, ...] = ()
