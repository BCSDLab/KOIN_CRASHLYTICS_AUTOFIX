"""Issue-first crash reports, progress, human fallback, and merge completion."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping
from urllib.parse import quote

from .github import OWNER, REPO, REPOSITORY_PATH, comment_once, find_issue, has_comment, issue_marker
from .models import CrashAlert, CrashContext
from .ownership import find_human_assignee
from .privacy import safe_text

MANUAL_MARKER = '<!-- crashlytics-human-only -->'
ASSIGNEE_START = '<!-- crashlytics-assignee:start -->'
ASSIGNEE_END = '<!-- crashlytics-assignee:end -->'
REPORT_START = '<!-- crashlytics-report:start -->'
REPORT_END = '<!-- crashlytics-report:end -->'
FIXED_MARKER = '<!-- crashlytics-fixed-pr:{} -->'


def _assignee_section(logins: list[str]) -> str:
    mentions = ', '.join(f'@{login}' for login in logins) or '없음'
    return f'{ASSIGNEE_START}\n### 담당자\n{mentions}\n{ASSIGNEE_END}'


def _with_assignees(body: str, logins: list[str]) -> str:
    section = _assignee_section(logins)
    start = body.find(ASSIGNEE_START)
    end = body.find(ASSIGNEE_END, start + len(ASSIGNEE_START)) if start >= 0 else -1
    if start >= 0 and end >= 0:
        return body[:start] + section + body[end + len(ASSIGNEE_END):]
    return body.rstrip() + '\n\n' + section


def _sync_assignee_body(github: Any, root: str, issue: Mapping[str, Any], bot_login: str) -> None:
    logins = [login for item in issue.get('assignees', [])
              if (login := _human_login(item, bot_login)) is not None]
    body = issue.get('body') or ''
    updated = _with_assignees(body, logins)
    if updated != body:
        github.rest('PATCH', root, {'body': updated})


def event_marker(alert: CrashAlert) -> str:
    digest = hashlib.sha256(alert.event_id.encode('utf-8')).hexdigest()
    return f'<!-- crashlytics-event:{digest} -->'


def find_manual_issue(github: Any, issue_id: str) -> dict[str, Any] | None:
    issue = find_issue(github, issue_id)
    if issue and (MANUAL_MARKER in (issue.get('body') or '') or has_comment(github, issue['number'], MANUAL_MARKER)):
        return issue
    return None


def _crash_url(alert: CrashAlert, config: dict[str, Any]) -> str:
    return (
        'https://console.firebase.google.com/project/' + quote(config['projectId'], safe='')
        + '/crashlytics/app/android:' + quote(config['bundleId'], safe='')
        + '/issues/' + quote(alert.issue_id, safe='')
    )


INPUT_KINDS = {
    'null': '입력값 없음(null)',
    'empty': '빈 입력(empty)',
    'blank': '공백만 있는 입력(blank)',
    'text': '텍스트 입력(text, 실제 입력 내용은 기록에 없음)',
}
SCREEN_KEYS = ('screen_name', 'screen_class')
UNKNOWN = '확인 불가'


def _safe_params(params: Any) -> dict[str, str]:
    """Keep only the categorical parameters the exporter already reduced to."""
    if not isinstance(params, dict):
        return {}
    safe: dict[str, str] = {}
    for key in SCREEN_KEYS:
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            safe[key] = safe_text(value, 160).strip()
    kind = params.get('input_kind')
    if isinstance(kind, str) and kind in INPUT_KINDS:
        safe['input_kind'] = kind
    return safe


def _reproduction_steps(breadcrumbs: Any) -> list[tuple[str, str]]:
    """Rebuild a chronological estimated path from the retained events."""
    if not isinstance(breadcrumbs, (list, tuple)):
        return []
    steps: list[tuple[str, str]] = []
    screen = ''
    for item in breadcrumbs:
        if not isinstance(item, dict):
            continue
        name = safe_text(item.get('name'), 80).strip()
        if not name:
            continue
        timestamp = safe_text(item.get('timestamp'), 64).strip()
        params = _safe_params(item.get('params'))
        observed = ', '.join(f'{key}={value}' for key, value in params.items() if key in SCREEN_KEYS)
        if observed or name == 'screen_view':
            screen = observed
        facts: list[str] = []
        if name == 'screen_view':
            facts.append('화면 전환 기록' + (f': {observed}' if observed else ' (화면 이름 없음)'))
        else:
            if name.endswith('_click'):
                facts.append('클릭 계열 이벤트 기록')
            else:
                facts.append('이벤트 기록')
            facts.append(f'당시 관찰 화면: {screen}' if screen else '관찰된 화면 정보 없음')
        kind = params.get('input_kind')
        if kind is not None:
            facts.append(f'입력 상태: {INPUT_KINDS[kind]}')
        steps.append((timestamp, f'`{name}` — ' + '. '.join(facts) + '.'))
    return steps


def _text(container: Any, key: str, limit: int) -> str:
    """Read one recorded string, sanitized and bounded; anything else is absent."""
    value = container.get(key) if isinstance(container, dict) else None
    return safe_text(value, limit).strip() if isinstance(value, str) else ''


def _environment_text(evidence: dict[str, Any]) -> tuple[str, str]:
    environment = evidence.get('environment')
    device = ' '.join(
        item for item in (_text(environment, 'manufacturer', 64), _text(environment, 'model', 64)) if item
    )
    architecture = _text(environment, 'architecture', 48)
    if architecture:
        device = f'{device} ({architecture})' if device else f'아키텍처 {architecture}'
    os_text = ' '.join(
        item for item in (_text(environment, 'osName', 48), _text(environment, 'osVersion', 48)) if item
    )
    return device, os_text


def _koin_version(alert: CrashAlert, evidence: dict[str, Any]) -> str:
    display, build = (_text(evidence, 'displayVersion', 40), _text(evidence, 'buildVersion', 40))
    if display:
        return f'{display} ({build})' if build else display
    return f'{safe_text(alert.app_version, 128)} (알림에 기록된 버전)'


def _crash_report_body(context: CrashContext, reason: str, config: dict[str, Any]) -> str:
    alert, source = context.alert, context.source
    evidence = context.evidence if isinstance(context.evidence, dict) else {}
    title, subtitle = safe_text(alert.title), safe_text(alert.subtitle)
    lines = [
        '### 어떤 오류인가요?',
        f'* {title}',
        f'* {subtitle}',
        f'* 사유: {safe_text(reason)}',
        f'* 발생 버전: {safe_text(alert.app_version)}',
        f'* 알림 시각: {safe_text(alert.published_at)}',
        f'* [Crashlytics에서 확인]({_crash_url(alert, config)})',
    ]
    if source is not None:
        path, line = source.path, source.line
        lines.append(f'* 소스: [{safe_text(path)}:{line}](https://github.com/{OWNER}/{REPO}/blob/'
                     f"{source.release_sha}/{quote(path, safe='/')}#L{line})")
    if context.previous_ai_fix is not None:
        lines.append(f'* 이전 AI 수정 PR: https://github.com/{OWNER}/{REPO}/pull/{context.previous_ai_fix.pull_number}')
        lines.append('* AI가 수정한 라인에서 재발하여 AI 재수정을 금지합니다.')
    if context.pull_numbers:
        lines.append('* hotfix PR: ' + ', '.join(
            f'https://github.com/{OWNER}/{REPO}/pull/{number}' for number in context.pull_numbers
        ))

    lines.extend(['', '### 재현 방법은 무엇인가요?'])
    steps = _reproduction_steps(evidence.get('breadcrumbs'))
    if not steps:
        lines.append('* 재현 경로를 재구성할 이벤트 기록(breadcrumb)이 없습니다. 확인 불가.')
    else:
        lines.append('아래는 Crashlytics에 남은 이벤트 기록만으로 재구성한 추정 경로이며, '
                     '실제로 실행해 확인한 재현 절차가 아닙니다. '
                     '이 자동화는 오류 이전의 최근 10개 이벤트만 추리므로 시작·중간 단계가 빠져 있을 수 있습니다.')
        lines.extend(f'{index}. ' + (f'`{timestamp}` — ' if timestamp else '')
                     + step for index, (timestamp, step) in enumerate(steps, 1))
        last_timestamp = steps[-1][0]
        observed_at = safe_text(evidence.get('eventTime') or alert.published_at, 64)
        lines.extend([
            '',
            f'* 마지막으로 기록된 이벤트 시각: {last_timestamp or UNKNOWN}',
            f'* 오류 관측 시각: {observed_at}',
            '* 마지막 이벤트는 오류 직전에 기록된 행동일 뿐, 오류의 원인이라는 근거는 없습니다.',
            '* 이 보고서에는 실제 입력값을 포함하지 않고 범주형 입력 상태만 기록했습니다.',
        ])

    lines.extend(['', '### 정상적인 동작은 무엇인가요?',
                  f'* {UNKNOWN} — 이벤트 로그에는 기대 동작이 기록되어 있지 않습니다.'])
    lines.extend(['', '### 예상되는 원인은 무엇인가요?', f'* 관찰된 예외: {subtitle or UNKNOWN}'])
    location = f'{safe_text(source.path)}:{source.line}' if source is not None else UNKNOWN
    lines.append(f'* 관찰된 소스 위치: {location}')
    lines.append(f'* 근본 원인: {UNKNOWN} — 로그와 이벤트만으로 원인을 확정할 수 없습니다.')

    lines.extend(['', '### 오류 사진을 올려주세요',
                  f'* {UNKNOWN} — 이 자동화는 스크린샷을 내보내거나 첨부하지 않습니다.'])

    device, os_text = _environment_text(evidence)
    lines.extend(['', '### 오류가 발생한 환경을 알려주세요',
                  f'* 기기: {device or UNKNOWN}',
                  f'* OS: {os_text or UNKNOWN}',
                  f'* KOIN 버전: {_koin_version(alert, evidence)}'])

    return '\n'.join(lines)


def _progress_section(context: CrashContext, config: dict[str, Any]) -> str:
    """Keep the full factual crash report in the issue, not only an event count."""
    lines = [REPORT_START, _crash_report_body(context, '자동 수정 처리 중입니다.', config),
             '', '### 자동 수정 진행 상황']
    lines.append('* production → develop 순서로 머지하며, 두 PR 완료 후 이슈를 종료합니다.'
                 if context.pull_numbers else '* AI 수정 PR: 아직 없음')
    lines.append(REPORT_END)
    return '\n'.join(lines)


def _with_report_section(body: str, section: str) -> str:
    start = body.find(REPORT_START)
    if start >= 0:
        end = body.find(REPORT_END, start + len(REPORT_START))
        if end >= 0:
            return body[:start] + section + body[end + len(REPORT_END):]
    anchor = body.find(ASSIGNEE_START)
    if anchor >= 0:
        return body[:anchor] + section + '\n\n' + body[anchor:]
    return body.rstrip() + '\n\n' + section


def _context_issue_number(context: CrashContext) -> int:
    number = getattr(context, 'issue_number', None)
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise ValueError('Invalid issue number for crash tracker')
    return number


def _tracker(github: Any, context: CrashContext) -> dict[str, Any]:
    """Fetch the associated tracker and prove it is this crash's genuine issue."""
    number = _context_issue_number(context)
    issue = github.rest('GET', f'{REPOSITORY_PATH}/issues/{number}')
    if not isinstance(issue, dict) or issue.get('number') != number:
        raise RuntimeError('Associated GitHub record is not the expected issue')
    if issue.get('pull_request') is not None:
        raise RuntimeError('Associated GitHub record is a pull request, not an issue')
    body = issue.get('body')
    if not isinstance(body, str) or issue_marker(context.alert.issue_id) not in body:
        raise RuntimeError('Associated GitHub issue does not match the Crashlytics ID')
    return issue


def ensure_crash_issue(github: Any, context: CrashContext, config: dict[str, Any]) -> int:
    """Create the normal tracker before evidence/model work, or reuse it."""
    alert = context.alert
    issue = find_issue(github, alert.issue_id)
    if issue is not None:
        number = issue['number']
        if MANUAL_MARKER in (issue.get('body') or '') or has_comment(github, number, MANUAL_MARKER):
            return number
        if issue.get('state') != 'open':
            github.rest('PATCH', f'{REPOSITORY_PATH}/issues/{number}', {'state': 'open'})
        return number
    body = '\n\n'.join([
        _progress_section(context, config),
        issue_marker(alert.issue_id),
        event_marker(alert),
        _assignee_section([]),
    ])
    created = github.rest('POST', f'{REPOSITORY_PATH}/issues', {
        'title': f'[Fix] [Crashlytics:{alert.issue_id[:8]}] {safe_text(alert.title, 180)}'[:256],
        'body': body,
        'labels': ['bug'],
    })
    if not isinstance(created, dict) or not isinstance(created.get('number'), int):
        raise RuntimeError('GitHub issue creation did not return an issue')
    return created['number']


def record_fix_progress(github: Any, context: CrashContext, config: dict[str, Any]) -> None:
    """Enrich the managed report while leaving human-edited text untouched."""
    issue = _tracker(github, context)
    body = issue.get('body') or ''
    updated = _with_report_section(body, _progress_section(context, config))
    for marker in (issue_marker(context.alert.issue_id), event_marker(context.alert)):
        if marker not in updated:
            updated += '\n\n' + marker
    logins = [login for item in issue.get('assignees', [])
              if (login := _human_login(item, config['botLogin'])) is not None]
    updated = _with_assignees(updated, logins)
    if updated != body:
        github.rest('PATCH', f"{REPOSITORY_PATH}/issues/{issue['number']}", {'body': updated})


def verify_crash_issue(github: Any, context: CrashContext) -> None:
    """Reject forged task associations before merge or closure."""
    _tracker(github, context)


def close_fixed_issue(github: Any, context: CrashContext) -> None:
    """Close the verified normal tracker only after both hotfix merges."""
    if len(context.pull_numbers) != 2 or len(set(context.pull_numbers)) != 2 \
            or any(type(number) is not int or number < 1 for number in context.pull_numbers):
        raise ValueError('Invalid hotfix pull request numbers')
    issue = _tracker(github, context)
    body = issue.get('body') or ''
    if MANUAL_MARKER in body or has_comment(github, issue['number'], MANUAL_MARKER):
        return
    root = f"{REPOSITORY_PATH}/issues/{issue['number']}"
    if issue.get('state') == 'closed':
        return
    marker = FIXED_MARKER.format(','.join(str(number) for number in context.pull_numbers))
    links = ', '.join(f'PR #{number}' for number in context.pull_numbers)
    comment_once(github, issue['number'], marker,
                 f'{links} 모두 merge commit으로 머지되어 이 이슈를 닫습니다.')
    github.rest('PATCH', root, {'state': 'closed'})


def _human_login(assignee: Any, bot_login: str) -> str | None:
    if not isinstance(assignee, dict) or assignee.get('type') != 'User':
        return None
    login = assignee.get('login')
    if (not isinstance(login, str) or re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', login) is None
            or login == bot_login or login.endswith('[bot]')):
        return None
    return login


def _first_human(issue: Mapping[str, Any], bot_login: str) -> str | None:
    assignees = issue.get('assignees')
    if not isinstance(assignees, list):
        return None
    return next(
        (login for login in (_human_login(item, bot_login) for item in assignees) if login), None,
    )


def _reuse_tracker(github: Any, context: CrashContext) -> dict[str, Any] | None:
    if getattr(context, 'issue_number', None) is not None:
        issue = _tracker(github, context)
        context.issue_number = issue['number']
        return issue
    issue = find_issue(github, context.alert.issue_id)
    if issue is not None:
        context.issue_number = issue['number']
    return issue


def report_for_human(github: Any, context: CrashContext, reason: str,
                     config: dict[str, Any], *, failed_pr: int | None = None) -> dict[str, Any]:
    """Create/comment once, then assign a human without overwriting concurrent work."""
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
        raise ValueError('Invalid manual handoff reason')
    alert = context.alert
    body = _crash_report_body(context, reason, config)
    if failed_pr is not None:
        body += f'\n\n* 자동 수정 PR: https://github.com/{OWNER}/{REPO}/pull/{failed_pr}'
    report = '\n'.join([REPORT_START, body, REPORT_END])
    issue = _reuse_tracker(github, context)
    if issue is None:
        issue = github.rest('POST', f'{REPOSITORY_PATH}/issues', {
            'title': f'[Fix] [Crashlytics:{alert.issue_id[:8]}] {safe_text(alert.title, 180)}'[:256],
            'body': '\n\n'.join([report, issue_marker(alert.issue_id), MANUAL_MARKER,
                                 event_marker(alert), _assignee_section([])]),
            'labels': ['bug'],
        })
        context.issue_number = issue['number']
    else:
        if issue.get('state') != 'open':
            github.rest('PATCH', f"{REPOSITORY_PATH}/issues/{issue['number']}", {'state': 'open'})
        existing, event = issue.get('body') or '', event_marker(alert)
        if MANUAL_MARKER not in existing or event not in existing:
            comment_once(github, issue['number'], MANUAL_MARKER + '\n' + event, body)
        updated = _with_report_section(existing, report)
        for marker in (issue_marker(alert.issue_id), MANUAL_MARKER, event):
            if marker not in updated:
                updated += '\n\n' + marker
        if updated != existing:
            github.rest('PATCH', f"{REPOSITORY_PATH}/issues/{issue['number']}", {'body': updated})
    root = f"{REPOSITORY_PATH}/issues/{issue['number']}"
    bot_login = config['botLogin']
    current = github.rest('GET', root)
    login = _first_human(current, bot_login)
    if login is None:
        assignment_error = None
        try:
            candidate = find_human_assignee(github, bot_login=bot_login, source=context.source)
        except RuntimeError as error:
            candidate, assignment_error = None, error
        # Eligibility lookup may race a human assignment or issue closure.
        current = github.rest('GET', root)
        if current.get('state') != 'open':
            return {'outcome': 'closed', 'issueNumber': issue['number']}
        login = _first_human(current, bot_login)
        if login is None:
            if assignment_error is not None:
                _sync_assignee_body(github, root, current, bot_login)
                raise assignment_error
            if not isinstance(candidate, str) or candidate == bot_login or candidate.endswith('[bot]'):
                raise ValueError('Manual handoff requires a human assignee')
            login = candidate
            current = github.rest('POST', root + '/assignees', {'assignees': [login]})
    bots = [item['login'] for item in current.get('assignees', [])
            if isinstance(item.get('login'), str) and
            (item.get('type') == 'Bot' or item['login'] == bot_login or item['login'].endswith('[bot]'))]
    if bots:
        current = github.rest('DELETE', root + '/assignees', {'assignees': bots})
    _sync_assignee_body(github, root, current, bot_login)
    return {'outcome': 'manual', 'issueNumber': issue['number'], 'login': login}
