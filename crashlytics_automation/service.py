"""Snapshot crashes for isolated investigation; retain verified CI/merge delivery."""

from __future__ import annotations

from typing import Any

from .evidence import find_evidence
from .investigation_jobs import InvestigationQueue, JobConflict, new_job
from .issues import (
    close_fixed_issue,
    ensure_crash_issue,
    record_fix_progress,
    report_for_human,
    verify_crash_issue,
)
from .merge import attempt_merge
from .models import CrashContext, ManualReview
from .repository import TARGET_BRANCHES
from .task_payloads import (
    MAX_FIX_RETRIES,
    MAX_MERGE_RETRIES,
    parse_fix_task,
    parse_merge_context,
)


class CrashAutomation:
    def __init__(self, github: Any, config: dict[str, Any], *,
                 bigquery_client: Any = None) -> None:
        self.github = github
        self.config = config
        self.bigquery_client = bigquery_client

    def process_fix_task(self, data: dict[str, Any], *, retry_count: int = 0) -> dict[str, Any]:
        context = CrashContext(parse_fix_task(data))
        if self.bigquery_client is None:
            raise ValueError('Investigation preparation requires BigQuery')
        try:
            context.issue_number = ensure_crash_issue(self.github, context, self.config)
            decision = self._prepare_fix(context, retry_count)
        except Exception:
            if retry_count < MAX_FIX_RETRIES:
                raise
            decision = ManualReview('자동 조사 준비 중 오류가 반복되어 사람의 확인이 필요합니다.')
        if isinstance(decision, ManualReview):
            return report_for_human(self.github, context, decision.reason, self.config)
        return decision

    def _prepare_fix(self, context: CrashContext, retry_count: int) -> dict[str, Any] | ManualReview:
        queue = InvestigationQueue(self.github)
        job = queue.get(context.alert)
        if job is None:
            context.evidence = find_evidence(self.bigquery_client, self.config, context.alert.to_payload())
            if context.evidence is None:
                if retry_count < MAX_FIX_RETRIES:
                    raise RuntimeError('Crashlytics export pending; retry preparation later')
                return ManualReview('BigQuery 데이터 대기 기한이 지났습니다.')
            if context.evidence['status'] != 'ready':
                return ManualReview(context.evidence.get('reason', '발생 이벤트를 확인할 수 없습니다.'))
            job = new_job(context.alert, context.evidence, context.issue_number)
            try:
                queue.put(job)
            except JobConflict:
                job = queue.get(context.alert)
                if job is None:
                    raise
        context.evidence = dict(job['evidence'])
        context.evidence['investigation'] = {
            'status': job['status'],
            'reason': job.get('reason', ''),
            'analyses': job['analyses'],
            'runUrl': job.get('runUrl'),
        }
        context.pull_numbers = tuple(job['branches'][branch]['pullNumber']
                                     for branch in TARGET_BRANCHES if branch in job['branches'])
        record_fix_progress(self.github, context, self.config)
        return {'outcome': job['status'], 'issueNumber': context.issue_number, 'investigationId': job['id']}

    def process_merge_task(self, job: dict[str, Any], *, retry_count: int = 0) -> dict[str, Any]:
        context = parse_merge_context(job)
        verify_crash_issue(self.github, context)
        queue = InvestigationQueue(self.github)
        investigation = queue.get(context.alert)
        if investigation is not None:
            expected = {branch: {'number': fix['pullNumber'], 'headSha': fix['headSha']}
                        for branch, fix in investigation['branches'].items()}
            if investigation['status'] not in ('delivering', 'merging', 'complete') or expected != job['pullRequests']:
                return {'outcome': 'superseded', 'issueNumber': context.issue_number}
        result = attempt_merge(self.github, job, bot_login=self.config['botLogin'])
        if result['outcome'] == 'pending' and retry_count < MAX_MERGE_RETRIES:
            raise RuntimeError('Required checks pending; retry merge later')
        if result['outcome'] == 'merged':
            if result['complete']:
                if investigation is not None:
                    investigation['status'] = 'complete'
                    queue.put(investigation)
                    if any(active['alert']['issueId'] == context.alert.issue_id
                           for active in queue.active()):
                        return {**result, 'complete': False}
                    context.evidence = dict(context.evidence or {})
                    context.evidence['investigation'] = {
                        'status': 'complete', 'analyses': investigation['analyses'],
                        'runUrl': investigation.get('runUrl'),
                    }
                    record_fix_progress(self.github, context, self.config)
                close_fixed_issue(self.github, context)
            return result
        reason = (f"자동 수정 PR #{job['pullNumber']}을 머지할 수 없습니다: "
                  + result.get('reason', '필수 CI 대기 기한이 지났습니다.'))
        if investigation is not None:
            investigation['status'], investigation['reason'] = 'manual', reason
            queue.put(investigation)
        return report_for_human(self.github, context, reason, self.config, failed_pr=job['pullNumber'])
