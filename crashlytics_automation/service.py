"""Issue first, then AI repair, ordinary CI, merge, and issue completion."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .evidence import find_evidence
from .fix_generation import create_fix_pull_request
from .issues import (
    close_fixed_issue,
    ensure_crash_issue,
    find_manual_issue,
    record_fix_progress,
    report_for_human,
    verify_crash_issue,
)
from .merge import attempt_merge
from .models import CrashContext, ManualReview, PublishedFix
from .openai_client import request_fix_proposal
from .ownership import find_ai_fix_for_line
from .release_source import resolve_release_source
from .repository import TARGET_BRANCHES
from .task_payloads import (
    MAX_FIX_RETRIES,
    MAX_MERGE_RETRIES,
    make_merge_task,
    parse_fix_task,
    parse_merge_context,
)


class CrashAutomation:
    def __init__(self, github: Any, config: dict[str, Any], *,
                 bigquery_client: Any = None,
                 enqueue_merge: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.github = github
        self.config = config
        self.bigquery_client = bigquery_client
        self.enqueue_merge = enqueue_merge

    def process_fix_task(self, data: dict[str, Any], *, retry_count: int = 0) -> dict[str, Any]:
        context = CrashContext(parse_fix_task(data))
        if self.bigquery_client is None or self.enqueue_merge is None:
            raise ValueError('Fix tasks require BigQuery and merge task delivery')
        try:
            context.issue_number = ensure_crash_issue(self.github, context, self.config)
            decision = self._prepare_fix(context, retry_count)
        except Exception:
            if retry_count < MAX_FIX_RETRIES:
                raise
            decision = ManualReview('자동 수정 처리 오류가 반복되어 사람의 확인이 필요합니다.')

        # Reporting failures must retry reporting, not re-enter the generation error handler.
        if isinstance(decision, ManualReview):
            return report_for_human(self.github, context, decision.reason, self.config)

        record_fix_progress(self.github, context, self.config)
        # Both PRs exist before either merge is queued; retries reuse each published branch.
        for fix in decision:
            self.enqueue_merge(make_merge_task(context, fix, decision))
        return {
            'outcome': 'existing' if all(fix.reused for fix in decision) else 'created',
            'pullRequests': [fix.to_payload() for fix in decision],
        }

    def _prepare_fix(self, context: CrashContext, retry_count: int) -> tuple[PublishedFix, ...] | ManualReview:
        manual_issue = find_manual_issue(self.github, context.alert.issue_id)
        context.evidence = find_evidence(self.bigquery_client, self.config, context.alert.to_payload())
        if manual_issue is not None:
            return ManualReview('이미 사람 담당자에게 전환된 오류의 추가 알림입니다.')
        if context.evidence is None:
            if retry_count < MAX_FIX_RETRIES:
                raise RuntimeError('Crashlytics export pending; retry autofix later')
            return ManualReview('BigQuery 데이터 대기 기한이 지났습니다.')
        if context.evidence['status'] != 'ready':
            return ManualReview(context.evidence.get('reason', '자동 수정에 필요한 오류 소스 정보를 확인할 수 없습니다.'))

        source = resolve_release_source(self.github, context.evidence)
        if isinstance(source, ManualReview):
            return source
        context.source = source
        record_fix_progress(self.github, context, self.config)

        trusted_authors = (self.config['botLogin'], *self.config.get('priorBotLogins', ()))
        context.previous_ai_fix = find_ai_fix_for_line(self.github, source, bot_logins=trusted_authors)
        if context.previous_ai_fix is not None:
            return ManualReview('이전에 AI가 수정한 출시 코드의 동일 라인에서 오류가 재발했습니다.')

        fixes: list[PublishedFix] = []
        for branch in TARGET_BRANCHES:
            fix = create_fix_pull_request(
                self.github, context.alert, context.evidence, source, self.config,
                issue_number=context.issue_number, base_branch=branch,
                generate=request_fix_proposal,
            )
            if isinstance(fix, ManualReview):
                return ManualReview(f'{branch}: {fix.reason}')
            fixes.append(fix)
            context.pull_numbers = tuple(published.pull_number for published in fixes)
            record_fix_progress(self.github, context, self.config)
        return tuple(fixes)

    def process_merge_task(self, job: dict[str, Any], *, retry_count: int = 0) -> dict[str, Any]:
        context = parse_merge_context(job)
        verify_crash_issue(self.github, context)
        if find_manual_issue(self.github, context.alert.issue_id) is not None:
            return report_for_human(
                self.github, context, '이미 사람 담당자에게 전환되어 자동 머지를 중단합니다.', self.config,
            )
        result = attempt_merge(self.github, job, bot_login=self.config['botLogin'])
        if result['outcome'] == 'pending' and retry_count < MAX_MERGE_RETRIES:
            raise RuntimeError('Required checks pending; retry merge later')
        if result['outcome'] == 'merged':
            if result['complete']:
                close_fixed_issue(self.github, context)
            return result
        reason = (f"자동 수정 PR #{job['pullNumber']}을 머지할 수 없습니다: "
                  + result.get('reason', '필수 CI 대기 기한이 지났습니다.'))
        return report_for_human(self.github, context, reason, self.config, failed_pr=job['pullNumber'])
