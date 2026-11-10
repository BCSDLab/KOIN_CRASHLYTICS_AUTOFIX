"""Crashlytics export lookup for the crashed release.

Uses the real ``google-cloud-bigquery`` client API: ``get_table`` for export-table
discovery and a parameterised ``query`` whose job result is consumed directly.
Only the smallest amount of source evidence is returned; exporter rows can hold
logs and user payloads and those are never propagated.

``find_evidence`` returns:

* ``None`` while the export tables/data are still pending (retry later),
* ``{"status": "unavailable", "reason": ...}`` when the crash cannot be
  attributed to Kotlin source,
* ``{"status": "ready", "displayVersion", "buildVersion", "frame", "eventTime",
  "breadcrumbs", "environment"}`` when a developer frame from the matching
  release is proven,
* ``{"status": "unavailable", "reason", "displayVersion", "buildVersion",
  "eventTime", "breadcrumbs", "environment"}`` when the event matches the alert
  but no developer frame can be proven, so the manual handoff keeps its context.

``environment`` is projected from the five safe
``device.{manufacturer,model,architecture}`` and
``operating_system.{name,display_version}`` columns. Values that are missing,
blank, non-textual, or not a short plain device/OS token are omitted instead of
guessed; identifiers, locale, user data and logs are never selected.

Breadcrumbs are the last ten Analytics events at or before the crash, reduced to
``{"name", "timestamp", "params"}``. Only developer-controlled categorical
parameters (``screen_name``, ``screen_class``, and the ``input_kind`` enum) are
kept; logs, user fields, arbitrary parameters, and raw input are never returned.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from google.api_core.exceptions import NotFound
from google.cloud import bigquery as bq

_DAY = timedelta(days=1)
_WINDOW_BEFORE = 30 * _DAY
_WINDOW_AFTER = timedelta(minutes=5)

_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,61}[a-z0-9]")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ANDROID_TABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*_ANDROID")
_BUNDLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
_ISSUE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_DISPLAY_VERSION = re.compile(r"\d+(?:\.\d+){1,3}")
_NUMERIC = re.compile(r"\d+")
_VERSION_TEXT = re.compile(r"(\d+(?:\.\d+){1,3})\s*\((\d+)\)")
_DEVELOPER_SYMBOL = re.compile(r"in\.koreatech\.koin\.")
_KT_FILE = re.compile(r"(?:[A-Za-z0-9_.$-]+/)*[A-Za-z_][A-Za-z0-9_]*\.kt")
_EVENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
_SCREEN_VALUE = re.compile(r"[A-Za-z][A-Za-z0-9_.:/-]{0,127}")
_INPUT_KINDS = frozenset({"null", "empty", "blank", "text"})
_SCREEN_KEYS = frozenset({"screen_name", "screen_class"})
_ENVIRONMENT_FIELDS = ("manufacturer", "model", "architecture", "osName", "osVersion")
_ENVIRONMENT_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+()-]{0,63}")
_MAX_BREADCRUMBS = 10
_MAX_BREADCRUMB_ROWS = 100


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _version_parts(value: object) -> tuple[str | None, str | None] | None:
    if not isinstance(value, str):
        return None
    full = _VERSION_TEXT.fullmatch(value.strip())
    if full:
        return full.group(1), full.group(2)
    if _DISPLAY_VERSION.fullmatch(value):
        return value, None
    if _NUMERIC.fullmatch(value):
        return None, value
    return None


def _field(value: object, name: str) -> Any:
    """Read a column from a BigQuery ``Row`` or a plain mapping."""
    getter = getattr(value, "get", None)
    if callable(getter):
        return getter(name)
    return None


def _valid_frame(frame: object) -> dict[str, Any] | None:
    if frame is None:
        return None
    raw_file = _field(frame, "file")
    file = raw_file.strip() if isinstance(raw_file, str) else ""
    raw_symbol = _field(frame, "symbol")
    symbol = raw_symbol.replace("`", "").strip() if isinstance(raw_symbol, str) else ""
    line = _field(frame, "line")
    if (
        _field(frame, "owner") != "DEVELOPER"
        or _DEVELOPER_SYMBOL.match(symbol) is None
        or len(symbol) > 1024
        or _KT_FILE.fullmatch(file) is None
        or ".." in file.split("/")
        or len(file) > 512
        or isinstance(line, bool)
        or not isinstance(line, int)
        or line < 1
        or line > 10_000_000
    ):
        return None
    return {"file": file, "line": line, "symbol": symbol}


def _select_columns(table: str) -> str:
    return f"""SELECT
    application.display_version AS displayVersion,
    application.build_version AS buildVersion,
    event_timestamp AS eventTime,
    STRUCT(blame_frame.file AS file, blame_frame.line AS line,
      blame_frame.symbol AS symbol, blame_frame.owner AS owner) AS blameFrame,
    ARRAY(SELECT AS STRUCT f.file, f.line, f.symbol, f.owner
      FROM UNNEST(exceptions) AS ex WITH OFFSET ex_index,
        UNNEST(ex.frames) AS f WITH OFFSET frame_index
      ORDER BY ex.blamed DESC, ex_index DESC, frame_index LIMIT 100) AS exceptionFrames,
    ARRAY(SELECT AS STRUCT f.file, f.line, f.symbol, f.owner
      FROM UNNEST(threads) AS thread WITH OFFSET thread_index,
        UNNEST(thread.frames) AS f WITH OFFSET frame_index
      WHERE thread.crashed OR thread.blamed
      ORDER BY thread.blamed DESC, thread_index, frame_index LIMIT 100) AS threadFrames,
    ARRAY(SELECT AS STRUCT b.name AS name, b.timestamp AS breadcrumbTime,
        ARRAY(SELECT AS STRUCT p.key AS key, p.value AS value
          FROM UNNEST(b.params) AS p
          WHERE p.key IN ('screen_name', 'screen_class', 'input_kind')) AS breadcrumbParams
      FROM UNNEST(breadcrumbs) AS b
      WHERE b.timestamp <= event_timestamp
      ORDER BY b.timestamp DESC LIMIT {_MAX_BREADCRUMB_ROWS}) AS breadcrumbs,
    device.manufacturer AS manufacturer,
    device.model AS model,
    device.architecture AS architecture,
    'Android' AS osName, -- platform filter fixes the OS family; operating_system.name may be a version.
    operating_system.display_version AS osVersion
    FROM `{table}`
    WHERE issue_id = @issueId AND bundle_identifier = @bundleId AND platform = 'ANDROID'
      AND event_timestamp BETWEEN TIMESTAMP(@startTime) AND TIMESTAMP(@endTime)
      AND (@displayVersion IS NULL OR application.display_version = @displayVersion)
      AND (@buildVersion IS NULL OR application.build_version = @buildVersion)"""


def _validate_config(config: object) -> None:
    if not isinstance(config, Mapping):
        raise ValueError("Invalid BigQuery configuration")
    project = config.get("projectId")
    dataset = config.get("dataset")
    table = config.get("table")
    bundle = config.get("bundleId")
    location = config.get("location")
    maximum = config.get("maximumBytesBilled")
    if (
        not isinstance(project, str)
        or _PROJECT.fullmatch(project) is None
        or not isinstance(dataset, str)
        or _IDENTIFIER.fullmatch(dataset) is None
        or not isinstance(table, str)
        or _ANDROID_TABLE.fullmatch(table) is None
        or not isinstance(bundle, str)
        or _BUNDLE.fullmatch(bundle) is None
        or not isinstance(location, str)
        or not location
        or not _NUMERIC.fullmatch(str(maximum))
    ):
        raise ValueError("Invalid BigQuery configuration")


def _timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_params(params: object) -> dict[str, str]:
    if not isinstance(params, (list, tuple)):
        return {}
    safe: dict[str, str] = {}
    for param in params:
        key, value = _field(param, "key"), _field(param, "value")
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if ((key in _SCREEN_KEYS and _SCREEN_VALUE.fullmatch(value))
                or (key == "input_kind" and value in _INPUT_KINDS)):
            safe.setdefault(key, value)
    return safe


def _breadcrumbs(value: object, crash_time: datetime) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    records = []
    for item in value:
        name, moment = _field(item, "name"), _timestamp(_field(item, "breadcrumbTime"))
        if isinstance(name, str) and _EVENT_NAME.fullmatch(name) and moment is not None and moment <= crash_time:
            records.append({"name": name, "timestamp": _iso(moment),
                            "params": _safe_params(_field(item, "breadcrumbParams"))})
    records.sort(key=lambda record: record["timestamp"])
    return records[-_MAX_BREADCRUMBS:]


def _environment_value(value: object) -> str | None:
    """Return a short plain device/OS token, or ``None`` when it is unusable."""
    if not isinstance(value, str):
        return None
    collapsed = " ".join(value.split())
    if _ENVIRONMENT_VALUE.fullmatch(collapsed) is None:
        return None
    return collapsed


def _environment(value: object) -> dict[str, str]:
    """Project the five safe device/OS columns, omitting anything unusable."""
    environment: dict[str, str] = {}
    for name in _ENVIRONMENT_FIELDS:
        safe = _environment_value(_field(value, name))
        if safe is not None:
            environment[name] = safe
    return environment


def _event_context(row: object, event_time: datetime, display: str, build: str) -> dict[str, Any]:
    return {
        "displayVersion": display,
        "buildVersion": build,
        "eventTime": _iso(event_time),
        "breadcrumbs": _breadcrumbs(_field(row, "breadcrumbs"), event_time),
        "environment": _environment(row),
    }


def find_evidence(
    bigquery: bq.Client,
    config: Mapping[str, Any],
    alert: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return source evidence for an alert, ``None`` while data is pending."""
    _validate_config(config)
    alert = alert if isinstance(alert, Mapping) else {}
    issue_id = alert.get("issueId")
    if not isinstance(issue_id, str) or _ISSUE_ID.fullmatch(issue_id) is None:
        raise ValueError("Invalid Crashlytics issue ID")

    version = _version_parts(alert.get("appVersion"))
    occurred = _timestamp(alert.get("time"))
    if version is None or occurred is None:
        return _unavailable("알림의 앱 버전 또는 발생 시각을 해석할 수 없습니다.")
    display_version, build_version = version

    start_time = occurred - _WINDOW_BEFORE
    end_time = occurred + _WINDOW_AFTER
    project = config["projectId"]
    dataset = config["dataset"]

    tables: list[str] = []
    for name in (config["table"], f"{config['table']}_REALTIME"):
        try:
            bigquery.get_table(f"{project}.{dataset}.{name}")
        except NotFound:
            continue
        tables.append(f"{project}.{dataset}.{name}")
    if not tables:
        return None

    sql = (
        "SELECT * FROM ("
        + "\nUNION ALL\n".join(_select_columns(table) for table in tables)
        + ") ORDER BY eventTime DESC LIMIT 1"
    )
    params = [
        bq.ScalarQueryParameter("issueId", "STRING", issue_id),
        bq.ScalarQueryParameter("bundleId", "STRING", config["bundleId"]),
        bq.ScalarQueryParameter("displayVersion", "STRING", display_version),
        bq.ScalarQueryParameter("buildVersion", "STRING", build_version),
        bq.ScalarQueryParameter("startTime", "STRING", _iso(start_time)),
        bq.ScalarQueryParameter("endTime", "STRING", _iso(end_time)),
    ]
    job_config = bq.QueryJobConfig(
        use_legacy_sql=False,
        query_parameters=params,
        maximum_bytes_billed=int(str(config["maximumBytesBilled"])),
    )
    try:
        row = next(iter(bigquery.query(sql, job_config=job_config, location=config["location"]).result()), None)
    except NotFound:
        return None
    if row is None:
        return None
    found_display = str(_field(row, "displayVersion") or "")
    found_build = str(_field(row, "buildVersion") or "")
    event_time = _timestamp(_field(row, "eventTime"))
    if (
        _DISPLAY_VERSION.fullmatch(found_display) is None
        or _NUMERIC.fullmatch(found_build) is None
        or (display_version is not None and display_version != found_display)
        or (build_version is not None and build_version != found_build)
        or event_time is None
        or event_time < start_time
        or event_time > end_time
    ):
        return _unavailable("조회한 발생 데이터의 버전 또는 시각이 알림과 일치하지 않습니다.")

    frames: list[object] = [_field(row, "blameFrame")]
    for name in ("exceptionFrames", "threadFrames"):
        extra = _field(row, name)
        if isinstance(extra, (list, tuple)):
            frames.extend(extra)
    frame = next((valid for valid in map(_valid_frame, frames) if valid is not None), None)
    context = _event_context(row, event_time, found_display, found_build)
    if frame is None:
        return {
            "status": "unavailable",
            "reason": "난독화가 해제된 앱 Kotlin 소스 프레임을 확인할 수 없습니다.",
            **context,
        }

    return {"status": "ready", "frame": frame, **context}
