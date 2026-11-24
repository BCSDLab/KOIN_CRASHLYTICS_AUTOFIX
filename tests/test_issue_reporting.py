import copy

from crashlytics_automation.github import issue_marker
from crashlytics_automation.issues import (
    ASSIGNEE_END,
    ASSIGNEE_START,
    MANUAL_MARKER,
    REPORT_END,
    REPORT_START,
    report_for_human,
)
from crashlytics_automation.models import CrashAlert, CrashContext
from crashlytics_automation.repository import REPOSITORY_PATH


CONFIG = {
    "botLogin": "koin-automation[bot]",
    "projectId": "koin-project",
    "bundleId": "in.koreatech.koin",
}
ALERT = CrashAlert(
    issue_id="issue-report-1",
    app_version="1.2.3 (42)",
    event_id="event-report-1",
    published_at="2026-01-02T03:04:05Z",
    title="Out of memory",
    subtitle="java.lang.OutOfMemoryError",
)


class IssueGitHub:
    def __init__(self, issue):
        self.issue = copy.deepcopy(issue)
        self.comments = []
        self.body_updates = []
        self.comment_calls = 0

    def rest(self, method, path, body=None):
        body = body or {}
        if path == f"{REPOSITORY_PATH}/issues/{self.issue['number']}":
            if method == "GET":
                return copy.deepcopy(self.issue)
            if method == "PATCH":
                if "body" in body:
                    self.body_updates.append(body["body"])
                self.issue.update(copy.deepcopy(body))
                return copy.deepcopy(self.issue)
        if path.endswith("/comments"):
            self.comment_calls += 1
            if method == "GET":
                return copy.deepcopy(self.comments)
            if method == "POST":
                self.comments.append(copy.deepcopy(body))
                return copy.deepcopy(body)
        raise AssertionError(f"Unexpected API call: {method} {path}")


def test_first_and_repeated_handoff_update_one_managed_report_without_comments():
    human_notes = "Please keep this diagnostic note and the attached device details."
    assignee_section = (
        f"{ASSIGNEE_START}\n### 담당자\n@human-reviewer\n{ASSIGNEE_END}"
    )
    fixture = {
        "number": 29,
        "state": "open",
        "body": "\n\n".join([
            human_notes,
            issue_marker(ALERT.issue_id),
            MANUAL_MARKER,
            assignee_section,
        ]),
        "assignees": [{"login": "human-reviewer", "type": "User"}],
    }
    github = IssueGitHub(fixture)
    context = CrashContext(ALERT, issue_number=29, evidence={
        "status": "ready",
        "displayVersion": "1.2.3",
        "buildVersion": "42",
        "stackTrace": {"exceptions": [], "threads": [], "truncated": False},
    })

    first = report_for_human(github, context, "No app source frame was found.", CONFIG)
    first_body = github.issue["body"]
    second = report_for_human(github, context, "No app source frame was found.", CONFIG)

    assert first == second == {"outcome": "manual", "issueNumber": 29, "login": "human-reviewer"}
    assert human_notes in github.issue["body"]
    assert "No app source frame was found." in github.issue["body"]
    assert github.issue["body"].count(REPORT_START) == 1
    assert github.issue["body"].count(REPORT_END) == 1
    assert github.issue["body"].count(issue_marker(ALERT.issue_id)) == 1
    assert github.issue["body"].count(ASSIGNEE_START) == 1
    assert github.issue["body"].count(ASSIGNEE_END) == 1
    assert github.issue["body"] == first_body
    assert len(github.body_updates) == 1
    assert github.comment_calls == 0
    assert github.comments == []
