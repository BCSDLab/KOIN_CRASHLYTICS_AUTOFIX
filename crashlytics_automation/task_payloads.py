"""Validate Firebase/Cloud Tasks input and translate JSON at the runtime boundary."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .models import CrashAlert, CrashContext, PublishedFix, SourceLocation
from .privacy import safe_text
from .repository import TARGET_BRANCHES

MAX_FIX_RETRIES = 2
MAX_MERGE_RETRIES = 168
MAX_SAFE_INTEGER = 2**53 - 1
ISSUE_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')


def _required_text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f'Invalid {name}')
    return value


def _utc_timestamp(value: Any) -> str:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError('Invalid alert time')
    return value.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def parse_alert_payload(payload: Any) -> CrashAlert:
    if not isinstance(payload, dict):
        raise ValueError('Invalid crash alert')
    issue_id = payload.get('issueId')
    if not isinstance(issue_id, str) or ISSUE_ID.fullmatch(issue_id) is None:
        raise ValueError('Invalid Crashlytics issue ID')
    return CrashAlert(
        issue_id=issue_id,
        app_version=_required_text(payload.get('appVersion'), 'app version', 128),
        event_id=_required_text(payload.get('eventId'), 'event ID', 512),
        published_at=_utc_timestamp(payload.get('time')),
        title=safe_text(payload.get('title'), 180),
        subtitle=safe_text(payload.get('subtitle'), 1000),
    )


def parse_firebase_alert(event: Any, config: dict[str, Any]) -> CrashAlert:
    """The Firebase SDK supplies a typed event, not a raw HTTP dictionary."""
    if event.app_id != config['appId']:
        raise ValueError('Unexpected Firebase app')
    issue = event.data.payload.issue
    return parse_alert_payload({
        'issueId': issue.id,
        'appVersion': issue.app_version,
        'eventId': event.id,
        'time': event.time,
        'title': issue.title,
        'subtitle': issue.subtitle,
    })


def parse_fix_task(data: Any) -> CrashAlert:
    if not isinstance(data, dict) or set(data) != {'alert'}:
        raise ValueError('Invalid autofix task')
    return parse_alert_payload(data['alert'])


def validate_merge_task(job: Any) -> None:
    if not isinstance(job, dict):
        raise ValueError('Invalid merge task')
    parse_alert_payload(job.get('alert'))
    if type(job.get('pullNumber')) is not int or not 0 < job['pullNumber'] <= MAX_SAFE_INTEGER:
        raise ValueError('Invalid merge task number')
    for name, length in (('headSha', 40), ('baseSha', 40), ('manifestDigest', 64)):
        value = job.get(name)
        if not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{' + str(length) + '}', value) is None:
            raise ValueError('Invalid merge task digest')
    if type(job.get('issueNumber')) is not int or not 0 < job['issueNumber'] <= MAX_SAFE_INTEGER:
        raise ValueError('Invalid merge task issue number')
    branch = job.get('baseBranch')
    pulls = job.get('pullRequests')
    if branch not in TARGET_BRANCHES or not isinstance(pulls, dict) or set(pulls) != set(TARGET_BRANCHES):
        raise ValueError('Invalid hotfix targets')
    numbers = []
    for target in TARGET_BRANCHES:
        pull = pulls[target]
        if not isinstance(pull, dict) or set(pull) != {'number', 'headSha'}:
            raise ValueError('Invalid hotfix pull request')
        number, head = pull['number'], pull['headSha']
        if type(number) is not int or not 0 < number <= MAX_SAFE_INTEGER \
                or not isinstance(head, str) or re.fullmatch(r'[0-9a-f]{40}', head) is None:
            raise ValueError('Invalid hotfix pull request')
        numbers.append(number)
    if len(set(numbers)) != len(TARGET_BRANCHES) or pulls[branch] != {
        'number': job['pullNumber'], 'headSha': job['headSha'],
    }:
        raise ValueError('Inconsistent hotfix pull requests')


def make_merge_task(context: CrashContext, fix: PublishedFix,
                    fixes: tuple[PublishedFix, ...]) -> dict[str, Any]:
    job = {
        'alert': context.alert.to_payload(),
        'issueNumber': context.issue_number,
        'pullNumber': fix.pull_number,
        'headSha': fix.head_sha,
        'baseSha': fix.base_sha,
        'manifestDigest': fix.manifest_digest,
        'baseBranch': fix.base_branch,
        'pullRequests': {
            peer.base_branch: {'number': peer.pull_number, 'headSha': peer.head_sha}
            for peer in fixes
        },
        'evidence': context.evidence,
        'source': context.source.to_payload() if context.source else None,
    }
    validate_merge_task(job)
    return job


def parse_merge_context(job: Any) -> CrashContext:
    validate_merge_task(job)
    return CrashContext(
        alert=parse_alert_payload(job['alert']),
        evidence=job.get('evidence'),
        source=SourceLocation.from_payload(job.get('source')),
        issue_number=job['issueNumber'],
        pull_numbers=tuple(job['pullRequests'][branch]['number'] for branch in TARGET_BRANCHES),
    )
