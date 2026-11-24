from datetime import datetime, timezone

from crashlytics_automation.evidence import _stack_trace, find_evidence


CONFIG = {
    "projectId": "valid-project1",
    "dataset": "crashlytics",
    "table": "com_koin_ANDROID",
    "bundleId": "com.koreatech.koin",
    "location": "US",
    "maximumBytesBilled": "1000000",
}


class QueryResult:
    def __init__(self, row):
        self.row = row

    def result(self):
        return [self.row]


class BigQuery:
    def __init__(self, row):
        self.row = row

    def get_table(self, _name):
        return object()

    def query(self, *_args, **_kwargs):
        return QueryResult(self.row)


def test_matching_library_only_oom_is_ready_without_app_frame():
    timestamp = datetime(2026, 1, 2, tzinfo=timezone.utc)
    row = {
        "displayVersion": "1.2.3",
        "buildVersion": "42",
        "eventTime": timestamp,
        "blameFrame": None,
        "exceptions": [{
            "type": "java.lang.OutOfMemoryError",
            "frames": [{
                "file": None,
                "line": None,
                "symbol": "failed to allocate 123456 bytes with 987654 bytes free",
                "owner": "RUNTIME",
                "library": "Android Runtime",
            }],
        }],
        "threads": [],
        "breadcrumbs": [],
    }
    evidence = find_evidence(
        BigQuery(row), CONFIG,
        {"issueId": "issue-1", "appVersion": "1.2.3 (42)", "time": timestamp.isoformat()},
    )

    assert evidence["status"] == "ready"
    assert evidence["frame"] is None
    stack = evidence["stackTrace"]
    assert stack["exceptions"][0]["type"] == "java.lang.OutOfMemoryError"
    assert stack["exceptions"][0]["frames"][0]["symbol"].endswith("987654 bytes free")
    assert stack["truncated"] is False


def test_stack_preserves_order_types_and_redacts_sensitive_strings():
    frames = [
        {"symbol": "first allocation 8192 bytes token=abc123", "owner": "RUNTIME"},
        {"symbol": "second frame", "owner": "VENDOR"},
    ]
    stack = _stack_trace({
        "exceptions": [{"type": "java.lang.OutOfMemoryError", "frames": frames}],
        "threads": [{"threadName": "main", "crashed": True,
                     "frames": [{"symbol": "nativeFrame", "library": "libart.so", "owner": "SYSTEM"}]}],
    })

    exception = stack["exceptions"][0]
    assert exception["type"] == "java.lang.OutOfMemoryError"
    assert [frame["symbol"].split(" token=")[0] if frame["symbol"] else None
            for frame in exception["frames"]] == ["first allocation 8192 bytes", "second frame"]
    assert exception["frames"][0]["symbol"].endswith("token=[REDACTED]")
    assert stack["threads"][0]["frames"][0]["library"] == "libart.so"
    assert stack["threads"][0]["crashed"] is True


def test_stack_truncation_is_explicit_and_keeps_leading_frames():
    frames = [{"symbol": f"frame{i}"} for i in range(1000)]
    stack = _stack_trace({
        "exceptions": [{"type": "Example", "frameCount": len(frames), "frames": frames}],
        "threads": [],
    })

    assert stack["truncated"] is True
    assert stack["exceptions"][0]["frameCount"] == len(frames)
    assert 0 < len(stack["exceptions"][0]["frames"]) < len(frames)
    assert stack["exceptions"][0]["frames"][0]["symbol"] == "frame0"


def test_library_only_oom_keeps_deep_pager_and_allocation_details():
    timestamp = datetime(2026, 1, 2, tzinfo=timezone.utc)
    frames = [{"symbol": f"androidx.compose.runtime.frame{i}", "owner": "VENDOR"} for i in range(75)]
    pager = "androidx.compose.foundation.pager.PagerMeasureKt.measurePager"
    frames[60] = {"file": "PagerMeasure.kt", "line": 221, "symbol": pager, "owner": "VENDOR"}
    message = ("Failed to allocate a 52616 byte allocation; growth limit 268435456; "
               "giving up on allocation because <1% of heap free after GC. token=sensitive")
    row = {
        "displayVersion": "1.2.3", "buildVersion": "42", "eventTime": timestamp,
        "exceptions": [{"type": "java.lang.OutOfMemoryError", "message": message,
                        "nested": False, "frames": frames}],
        "memory": {"free": 1024, "used": 268434432}, "processState": "FOREGROUND",
    }
    evidence = find_evidence(BigQuery(row), CONFIG, {
        "issueId": "oom", "appVersion": "1.2.3 (42)", "time": timestamp.isoformat(),
    })
    exception = evidence["stackTrace"]["exceptions"][0]
    assert evidence["status"] == "ready" and evidence["frame"] is None
    assert any(frame["symbol"] == pager for frame in exception["frames"])
    assert "52616" in exception["message"] and "268435456" in exception["message"]
    assert "1%" in exception["message"] and "sensitive" not in exception["message"]
    assert exception["nested"] is False
    assert evidence["memory"] == {"free": 1024, "used": 268434432}
