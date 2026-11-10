"""Firebase entrypoints for issue-first repair, CI merge, and human fallback."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from firebase_admin import functions, initialize_app
from firebase_admin.exceptions import AlreadyExistsError
from firebase_functions import options, tasks_fn
from firebase_functions.alerts import crashlytics_fn
from firebase_functions.params import SecretParam
from google.cloud import bigquery

from crashlytics_automation.github import create_github
from crashlytics_automation.service import CrashAutomation
from crashlytics_automation.openai_client import DEFAULT_MODEL
from crashlytics_automation.task_payloads import MAX_FIX_RETRIES, MAX_MERGE_RETRIES, parse_firebase_alert
from crashlytics_automation.repository import ANDROID_APPLICATION_ID


def _required_env(name: str) -> str:
    value = os.environ.get(name, '')
    if not value.strip():
        raise ValueError(f'Missing configuration: {name}')
    return value


PROJECT_ID = _required_env('CRASHLYTICS_PROJECT_ID')
REGION = 'us-central1'
SERVICE_ACCOUNT = _required_env('AUTOMATION_SERVICE_ACCOUNT')
BOT_LOGIN = _required_env('CRASHLYTICS_AUTOFIX_BOT_LOGIN')
CONFIG = {
    'projectId': PROJECT_ID,
    'appId': _required_env('CRASHLYTICS_APP_ID'),
    'botLogin': BOT_LOGIN,
    'priorBotLogins': tuple(login.strip() for login in
                            os.environ.get('CRASHLYTICS_PRIOR_BOT_LOGINS', '').split(',') if login.strip()),
    'bundleId': ANDROID_APPLICATION_ID,
    'dataset': 'firebase_crashlytics',
    'table': os.environ.get('BIGQUERY_TABLE', 'in_koreatech_koin_ANDROID'),
    'location': _required_env('BIGQUERY_LOCATION'),
    'maximumBytesBilled': '1000000000',
}
PRIVATE_KEY = SecretParam('CRASHLYTICS_GITHUB_APP_PRIVATE_KEY')
OPENAI_KEY = SecretParam('CRASHLYTICS_OPENAI_API_KEY')
# CrashlyticsOptions in firebase-functions 0.6.0 drops per-trigger runtime options.
options.set_global_options(
    service_account=SERVICE_ACCOUNT,
    memory=options.MemoryOption.MB_512,
    timeout_sec=300,
    max_instances=1,
    concurrency=1,
)
initialize_app(options={'projectId': PROJECT_ID})


def _github(permissions: dict[str, str]) -> Any:
    return create_github(
        _required_env('CRASHLYTICS_GITHUB_APP_ID'),
        _required_env('CRASHLYTICS_GITHUB_INSTALLATION_ID'),
        PRIVATE_KEY.value,
        permissions=permissions,
    )


def _enqueue_task(name: str, identity: str, data: dict[str, Any]) -> None:
    task_id = hashlib.sha256(f'{name}/{identity}'.encode('utf-8')).hexdigest()
    queue = functions.task_queue(f'locations/{REGION}/functions/{name}')
    try:
        queue.enqueue({'data': data}, functions.TaskOptions(task_id=task_id, dispatch_deadline_seconds=600))
    except AlreadyExistsError:
        pass


def _receive(event: Any) -> None:
    alert = parse_firebase_alert(event, CONFIG)
    _enqueue_task('generateCrashlyticsFix', alert.event_id, {'alert': alert.to_payload()})


def _retry_count(request: Any) -> int:
    # Python's CallableRequest does not expose Node's retryCount property.
    value = request.raw_request.headers.get('X-CloudTasks-TaskRetryCount', '0')
    if not isinstance(value, str) or not value.isascii() or not value.isdigit() or len(value) > 10:
        raise ValueError('Invalid Cloud Tasks retry count')
    return int(value)


ALERT_OPTIONS = {'app_id': CONFIG['appId'], 'retry': True}
TASK_OPTIONS = {
    'region': REGION,
    'invoker': [SERVICE_ACCOUNT],
    'retry_config': options.RetryConfig(max_attempts=MAX_FIX_RETRIES + 1,
                                       min_backoff_seconds=21600, max_backoff_seconds=21600, max_doublings=0),
    'rate_limits': options.RateLimits(max_concurrent_dispatches=1, max_dispatches_per_second=1),
}


@crashlytics_fn.on_new_fatal_issue_published(**ALERT_OPTIONS)
def crashlyticsNewFatal(event: crashlytics_fn.CrashlyticsNewFatalIssueEvent) -> None:
    _receive(event)


@crashlytics_fn.on_new_nonfatal_issue_published(**ALERT_OPTIONS)
def crashlyticsNewNonfatal(event: crashlytics_fn.CrashlyticsNewNonfatalIssueEvent) -> None:
    _receive(event)


@crashlytics_fn.on_new_anr_issue_published(**ALERT_OPTIONS)
def crashlyticsNewAnr(event: crashlytics_fn.CrashlyticsNewAnrIssueEvent) -> None:
    _receive(event)


@crashlytics_fn.on_regression_alert_published(**ALERT_OPTIONS)
def crashlyticsRegression(event: crashlytics_fn.CrashlyticsRegressionAlertEvent) -> None:
    _receive(event)


@crashlytics_fn.on_velocity_alert_published(**ALERT_OPTIONS)
def crashlyticsVelocity(event: crashlytics_fn.CrashlyticsVelocityAlertEvent) -> None:
    _receive(event)


def _enqueue_merge(job: dict[str, Any]) -> None:
    _enqueue_task('mergeCrashlyticsFix', f"{job['pullNumber']}/{job['headSha']}", job)


@tasks_fn.on_task_dispatched(**{**TASK_OPTIONS, 'secrets': [PRIVATE_KEY, OPENAI_KEY], 'timeout_sec': 600})
def generateCrashlyticsFix(request: tasks_fn.CallableRequest) -> dict[str, Any]:
    automation = CrashAutomation(
        _github({'contents': 'write', 'issues': 'write', 'pull_requests': 'write'}),
        {**CONFIG, 'model': os.environ.get('OPENAI_MODEL', DEFAULT_MODEL), 'apiKey': OPENAI_KEY.value},
        bigquery_client=bigquery.Client(project=PROJECT_ID),
        enqueue_merge=_enqueue_merge,
    )
    return automation.process_fix_task(request.data, retry_count=_retry_count(request))


@tasks_fn.on_task_dispatched(**{
    **TASK_OPTIONS,
    'secrets': [PRIVATE_KEY],
    'retry_config': options.RetryConfig(max_attempts=MAX_MERGE_RETRIES + 1,
                                       min_backoff_seconds=3600, max_backoff_seconds=3600, max_doublings=0),
})
def mergeCrashlyticsFix(request: tasks_fn.CallableRequest) -> dict[str, Any]:
    automation = CrashAutomation(
        _github({'contents': 'write', 'issues': 'write', 'pull_requests': 'write', 'checks': 'read', 'statuses': 'read'}),
        CONFIG,
    )
    return automation.process_merge_task(request.data, retry_count=_retry_count(request))
