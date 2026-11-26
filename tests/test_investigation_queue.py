import base64
import copy
import hashlib
from datetime import datetime, timezone
from urllib.parse import parse_qs

import pytest

from crashlytics_automation.investigation_jobs import (
    InvestigationQueue,
    JobConflict,
    new_job,
)
from crashlytics_automation.repository import REPOSITORY_PATH, STATE_REFERENCE
from crashlytics_automation.service import CrashAutomation


CONFIG = {
    "projectId": "koin-project",
    "bundleId": "in.koreatech.koin",
    "botLogin": "koin-automation[bot]",
    "table": "in_koreatech_koin_ANDROID",
    "dataset": "firebase_crashlytics",
    "location": "US",
    "maximumBytesBilled": "1000000",
}
EVENT_TIME = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
ALERT = {
    "issueId": "issue-oom-1",
    "appVersion": "1.2.3 (42)",
    "eventId": "event-oom-1",
    "time": EVENT_TIME.isoformat(),
    "title": "Out of memory",
    "subtitle": "java.lang.OutOfMemoryError",
}


class ApiError(RuntimeError):
    def __init__(self, status):
        super().__init__(str(status))
        self.status = status


class MemoryGitHub:
    """Small Git-data and issue API model with real blob/reference CAS semantics."""

    def __init__(self, issues=None):
        self.issues = {item["number"]: copy.deepcopy(item) for item in (issues or [])}
        self.blobs = {}
        self.trees = {}
        self.commits = {}
        self.refs = {}
        self.comments = {number: [] for number in self.issues}
        self.next_issue = max(self.issues, default=0) + 1
        self.patch_count = 0

    @staticmethod
    def _sha(value):
        return hashlib.sha1(value if isinstance(value, bytes) else value.encode()).hexdigest()

    def rest(self, method, path, body=None):
        body = body or {}
        if path.startswith("/search/issues?") and method == "GET":
            query = parse_qs(path.split("?", 1)[1]).get("q", [""])[0]
            quoted = query.split('"')
            crash_id = quoted[1] if len(quoted) > 1 else ""
            marker = f"crashlytics-issue:{crash_id} -->"
            matches = [copy.deepcopy(issue) for issue in self.issues.values()
                       if marker in (issue.get("body") or "")]
            return {"total_count": len(matches), "items": matches, "incomplete_results": False}

        if path == f"{REPOSITORY_PATH}/issues" and method == "POST":
            issue = {
                "number": self.next_issue,
                "title": body["title"],
                "body": body["body"],
                "state": "open",
                "assignees": [],
            }
            self.issues[self.next_issue] = issue
            self.comments[self.next_issue] = []
            self.next_issue += 1
            return copy.deepcopy(issue)
        issue_prefix = f"{REPOSITORY_PATH}/issues/"
        if path.startswith(issue_prefix):
            suffix = path[len(issue_prefix):]
            if suffix.endswith("/assignees"):
                number = int(suffix.split("/", 1)[0])
                if method == "POST":
                    issue = self.issues[number]
                    issue["assignees"] = [{"login": login, "type": "User"}
                                          for login in body.get("assignees", [])]
                    return copy.deepcopy(issue)
                if method == "DELETE":
                    self.issues[number]["assignees"] = []
                    return copy.deepcopy(self.issues[number])
            if suffix.endswith("/comments"):
                number = int(suffix.split("/", 1)[0])
                if method == "GET":
                    return copy.deepcopy(self.comments[number])
                if method == "POST":
                    self.comments[number].append(copy.deepcopy(body))
                    return copy.deepcopy(body)
            number = int(suffix)
            if method == "GET":
                return copy.deepcopy(self.issues[number])
            if method == "PATCH":
                self.patch_count += 1
                self.issues[number].update(copy.deepcopy(body))
                return copy.deepcopy(self.issues[number])

        ref_path = f"{REPOSITORY_PATH}/git/ref/{STATE_REFERENCE.removeprefix('refs/')}"
        if path == ref_path and method == "GET":
            if STATE_REFERENCE not in self.refs:
                raise ApiError(404)
            return {"object": {"sha": self.refs[STATE_REFERENCE]}}
        if path == f"{REPOSITORY_PATH}/git/refs" and method == "POST":
            ref = body["ref"]
            if ref in self.refs:
                raise ApiError(422)
            self.refs[ref] = body["sha"]
            return {"ref": body["ref"]}
        if path == f"{REPOSITORY_PATH}/git/refs/{STATE_REFERENCE.removeprefix('refs/')}" and method == "PATCH":
            commit = self.commits[body["sha"]]
            if commit["parents"] != [self.refs.get(STATE_REFERENCE)]:
                raise ApiError(409)
            self.refs[STATE_REFERENCE] = body["sha"]
            return {"object": {"sha": body["sha"]}}
        if path == f"{REPOSITORY_PATH}/git/blobs" and method == "POST":
            raw = base64.b64decode(body["content"])
            sha = self._sha(raw)
            self.blobs[sha] = raw
            return {"sha": sha}
        if path.startswith(f"{REPOSITORY_PATH}/git/blobs/") and method == "GET":
            sha = path.rsplit("/", 1)[1]
            return {"encoding": "base64", "content": base64.b64encode(self.blobs[sha]).decode()}
        if path.startswith(f"{REPOSITORY_PATH}/git/trees/") and method == "GET":
            sha = path.split("/git/trees/", 1)[1].split("?", 1)[0]
            commit = self.commits.get(sha)
            tree_sha = commit["tree"] if commit else sha
            tree = self.trees[tree_sha]
            return {"truncated": False, "tree": [
                {"path": name, "type": "blob", "sha": blob}
                for name, blob in sorted(tree.items())
            ]}
        if path == f"{REPOSITORY_PATH}/git/trees" and method == "POST":
            tree = copy.deepcopy(self.trees.get(body.get("base_tree"), {}))
            for item in body["tree"]:
                if item["sha"] is None:
                    tree.pop(item["path"], None)
                else:
                    tree[item["path"]] = item["sha"]
            sha = self._sha(repr(sorted(tree.items())))
            self.trees[sha] = tree
            return {"sha": sha}
        if path.startswith(f"{REPOSITORY_PATH}/git/commits/") and method == "GET":
            return {"tree": {"sha": self.commits[path.rsplit("/", 1)[1]]["tree"]}}
        if path == f"{REPOSITORY_PATH}/git/commits" and method == "POST":
            parents = body["parents"]
            raw = repr((body["tree"], parents, body["message"]))
            sha = self._sha(raw)
            self.commits[sha] = {"tree": body["tree"], "parents": parents}
            return {"sha": sha}
        raise AssertionError(f"Unhandled GitHub API call: {method} {path}")


class MemoryBigQuery:
    def __init__(self):
        self.query_count = 0
        self.row = {
            "displayVersion": "1.2.3",
            "buildVersion": "42",
            "eventTime": EVENT_TIME,
            "blameFrame": None,
            "exceptions": [{
                "type": "java.lang.OutOfMemoryError",
                "frames": [{
                    "file": None,
                    "line": None,
                    "symbol": "failed to allocate 98304 bytes with 1024 bytes free",
                    "owner": "RUNTIME",
                    "library": "Android Runtime",
                }],
            }],
            "threads": [],
            "breadcrumbs": [],
        }

    def get_table(self, _name):
        return object()

    def query(self, *_args, **_kwargs):
        self.query_count += 1
        return type("Job", (), {"result": lambda _self: [self.row]})()


def test_library_only_evidence_is_enqueued_once_and_reused_without_bigquery():
    github = MemoryGitHub()
    bigquery = MemoryBigQuery()
    dispatches = []
    service = CrashAutomation(
        github, CONFIG, bigquery_client=bigquery,
        worker_dispatch=lambda: dispatches.append(None),
    )
    task = {"alert": ALERT}

    first = service.process_fix_task(task)
    second = service.process_fix_task(task)

    assert first["outcome"] == second["outcome"] == "queued"
    assert first["investigationId"] == second["investigationId"]
    assert bigquery.query_count == 1
    assert len(dispatches) == 2
    job = InvestigationQueue(github).get(service_context_alert())
    assert job["status"] == "queued"
    assert job["evidence"]["frame"] is None
    assert job["evidence"]["stackTrace"]["exceptions"][0]["type"] == "java.lang.OutOfMemoryError"
    assert github.refs and not any(ref.startswith("refs/heads/") for ref in github.refs)


def test_dispatch_failure_after_persistence_retries_without_requerying_evidence():
    github = MemoryGitHub()
    bigquery = MemoryBigQuery()
    dispatches = []

    def dispatch():
        dispatches.append(None)
        if len(dispatches) == 1:
            raise RuntimeError("GitHub dispatch unavailable")

    service = CrashAutomation(
        github, CONFIG, bigquery_client=bigquery, worker_dispatch=dispatch,
    )
    task = {"alert": ALERT}

    with pytest.raises(RuntimeError, match="GitHub dispatch unavailable"):
        service.process_fix_task(task)
    result = service.process_fix_task(task)

    assert result["outcome"] == "queued"
    assert bigquery.query_count == 1
    assert len(dispatches) == 2
    assert InvestigationQueue(github).get(service_context_alert())["status"] == "queued"


def test_manual_hold_redelivery_does_not_dispatch_or_change_job_counters():
    github = MemoryGitHub()
    alert = service_context_alert()
    job = new_job(alert, {"status": "ready"}, 17)
    job["status"] = "manual"
    job["reason"] = "Human review required"
    job["attempts"] = {"production": 2}
    job["deliveryAttempts"] = 3
    queue = InvestigationQueue(github)
    queue.put(job)
    before = queue.get(alert)
    dispatches = []
    service = CrashAutomation(
        github, CONFIG, bigquery_client=MemoryBigQuery(),
        worker_dispatch=lambda: dispatches.append(None),
    )

    result = service.process_fix_task({"alert": ALERT})
    after = queue.get(alert)

    assert result["outcome"] == "manual"
    assert dispatches == []
    assert after["status"] == before["status"] == "manual"
    assert after["attempts"] == before["attempts"]
    assert after["deliveryAttempts"] == before["deliveryAttempts"]

def service_context_alert():
    from crashlytics_automation.task_payloads import parse_alert_payload

    return parse_alert_payload(ALERT)


def test_legacy_human_only_marker_does_not_block_investigation():
    from crashlytics_automation.github import issue_marker
    from crashlytics_automation.issues import MANUAL_MARKER

    fixture = {
        "number": 17,
        "title": "Existing crash",
        "body": f"human-authored details\n\n{issue_marker(ALERT['issueId'])}\n{MANUAL_MARKER}",
        "state": "open",
        "assignees": [{"login": "human-reviewer", "type": "User"}],
    }
    github = MemoryGitHub([fixture])
    bigquery = MemoryBigQuery()
    result = CrashAutomation(
        github, CONFIG, bigquery_client=bigquery,
        worker_dispatch=lambda: None,
    ).process_fix_task({"alert": ALERT})

    assert result["outcome"] == "queued"
    assert bigquery.query_count == 1
    assert MANUAL_MARKER not in github.issues[17]["body"]
    assert "human-authored details" in github.issues[17]["body"]
    assert InvestigationQueue(github).get(service_context_alert())["status"] == "queued"


def test_stale_job_write_is_rejected_without_losing_concurrent_winner():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    alert = service_context_alert()
    evidence = {
        "status": "ready",
        "frame": None,
        "stackTrace": {"exceptions": [], "threads": [], "truncated": False},
    }
    from crashlytics_automation.investigation_jobs import new_job

    queue.put(new_job(alert, evidence, 17))
    stale = queue.get(alert)
    winner = queue.get(alert)
    winner["status"] = "complete"
    queue.put(winner)
    stale["status"] = "manual"

    with pytest.raises(JobConflict):
        queue.put(stale)

    saved = queue.get(alert)
    assert saved["status"] == "complete"
    assert saved["_blobSha"] == winner["_blobSha"]


def test_completed_job_leaves_active_queue_but_remains_retrievable():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    alert = service_context_alert()
    from crashlytics_automation.investigation_jobs import new_job

    job = new_job(alert, {"status": "ready", "frame": None}, 17)
    queue.put(job)
    saved = queue.get(alert)
    saved["status"] = "complete"
    queue.put(saved)

    assert queue.active() == []
    assert queue.get(alert)["status"] == "complete"


@pytest.mark.parametrize("status", ["manual", "merging", "complete"])
def test_pending_reports_remain_deliverable_without_reopening_analysis(status):
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    alert = service_context_alert()
    job = new_job(alert, {"status": "ready"}, 17)
    job["status"] = status
    job["reason"] = "Investigation finished"
    queue.put(job)
    assert queue.pending() == []

    job["reportPending"] = True
    queue.put(job)
    pending = queue.pending()
    assert len(pending) == 1 and pending[0]["status"] == status
    assert pending[0]["id"] == job["id"]

    job.pop("reportPending")
    queue.put(job)
    assert queue.pending() == []
    assert queue.get(alert)["status"] == status


def test_fourth_attempt_requires_explicit_scoped_limit_and_round_trips():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    alert = service_context_alert()
    job = new_job(alert, {'status': 'ready'}, 17)
    job['status'] = 'manual'
    job['attempts']['production'] = 4
    with pytest.raises(ValueError):
        queue.put(job)

    job['attemptLimits'] = {'production': 4}
    queue.put(job)
    stored = queue.get(alert)
    assert stored['attempts'] == {'production': 4}
    assert stored['attemptLimits'] == {'production': 4}


@pytest.mark.parametrize('limits', [
    {'production': True}, {'production': 5}, {'unknown': 4},
])
def test_unbounded_or_malformed_attempt_grants_cannot_be_saved(limits):
    queue = InvestigationQueue(MemoryGitHub())
    job = new_job(service_context_alert(), {'status': 'ready'}, 17)
    job['attemptLimits'] = limits
    with pytest.raises(ValueError):
        queue.put(job)


def _proposal_fixture(queue, job=None):
    from crashlytics_automation.candidate import identity_hash_for, regression_test_name
    from crashlytics_automation.investigation_jobs import new_job

    alert = service_context_alert()
    job = job or new_job(alert, {'status': 'ready'}, 17)
    job['releaseSha'] = 'a' * 40
    job.setdefault('branchBases', {})['production'] = 'b' * 40
    identity = identity_hash_for(alert.issue_id, job['releaseSha'])
    source_path = 'domain/src/main/kotlin/org/koin/Thing.kt'
    source_content = 'package org.koin\nclass Thing { fun value() = 2 }\n'
    test_path = f'domain/src/test/kotlin/org/koin/{regression_test_name(identity)}'
    test_content = 'package org.koin\nclass RegressionTest\n'
    import hashlib
    files = [
        {'path': source_path, 'kind': 'source', 'beforeSha256': 'c' * 64,
         'afterSha256': hashlib.sha256(source_content.encode()).hexdigest(), 'content': source_content},
        {'path': test_path, 'kind': 'test', 'beforeSha256': None,
         'afterSha256': hashlib.sha256(test_content.encode()).hexdigest(), 'content': test_content},
    ]
    decision = {
        'decision': 'fix', 'analysis': 'Root cause found in Thing.value.',
        'reason': 'The source change addresses the crash.', 'sourcePath': source_path,
        'sourceLine': 2, 'files': files,
    }
    return job, decision


def test_proposal_checkpoint_is_versioned_reachable_and_excludes_tool_results():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    job, decision = _proposal_fixture(queue)
    queue.put(job)
    envelope = queue.save_proposal(
        job, 'production', {**decision, 'toolResults': [{'stdout': 'must not persist'}]},
        release_sha=job['releaseSha'], branch_base_sha='b' * 40, base_sha='d' * 40,
    )
    restored = queue.get_proposal(queue.get(service_context_alert()), 'production')
    assert envelope['version'] == 1
    assert envelope['identity'] == {
        'jobId': job['id'], 'target': 'production', 'releaseSha': 'a' * 40,
        'branchBaseSha': 'b' * 40, 'baseSha': 'd' * 40,
    }
    assert restored == envelope
    assert 'toolResults' not in restored['proposal']
    assert queue._proposal_path(job, 'production') in queue._entries(queue._head())


def test_proposal_checkpoint_rejects_unreachable_or_malformed_pointer():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    job, _ = _proposal_fixture(queue)
    queue.put(job)
    job['proposals'] = {'production': 'f' * 40}
    with pytest.raises(ValueError, match='unreachable'):
        queue.get_proposal(job, 'production')


def test_proposal_checkpoint_cas_conflict_does_not_overwrite_winner():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    job, decision = _proposal_fixture(queue)
    queue.put(job)
    stale = queue.get(service_context_alert())
    winner = queue.get(service_context_alert())
    winner['status'] = 'manual'
    queue.put(winner)
    with pytest.raises(JobConflict):
        queue.save_proposal(
            stale, 'production', decision, release_sha='a' * 40,
            branch_base_sha='b' * 40, base_sha='d' * 40,
        )
    saved = queue.get(service_context_alert())
    assert saved['status'] == 'manual'
    assert saved.get('proposals', {}) == {}


def test_reachable_malformed_proposal_envelope_is_rejected():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    job, _ = _proposal_fixture(queue)
    queue.put(job)
    malformed = github.rest('POST', f'{REPOSITORY_PATH}/git/blobs', {
        'content': base64.b64encode(b'{"version":true}').decode(), 'encoding': 'base64',
    })['sha']
    job['proposals'] = {'production': malformed}
    queue.put(job)
    with pytest.raises(ValueError, match='identity'):
        queue.get_proposal(queue.get(service_context_alert()), 'production')


def test_serial_state_writes_survive_stale_ref_reads_without_losing_updates():
    from crashlytics_automation.task_payloads import parse_alert_payload

    class LaggingReference(MemoryGitHub):
        visible_head = None

        def rest(self, method, path, body=None):
            if self.visible_head is not None and method == 'GET' and path == (
                f'{REPOSITORY_PATH}/git/ref/{STATE_REFERENCE.removeprefix("refs/")}'
            ):
                return {'object': {'sha': self.visible_head}}
            return super().rest(method, path, body)

    github = LaggingReference()
    queue = InvestigationQueue(github)
    alert = parse_alert_payload(ALERT)
    job = new_job(alert, {'status': 'ready'}, 17)
    queue.put(job)
    github.visible_head = github.refs[STATE_REFERENCE]
    job['attempts']['production'] = 1
    queue.put(job)
    job['analyses']['production'] = {'analysis': 'Completed investigation'}
    queue.put(job)
    github.visible_head = None
    saved = InvestigationQueue(github).get(alert)
    assert saved['attempts'] == {'production': 1}
    assert saved['analyses']['production']['analysis'] == 'Completed investigation'


def _publication_fixture():
    from crashlytics_automation.candidate import candidate_manifest, identity_hash_for
    job, decision = _proposal_fixture(None)
    return candidate_manifest(
        issue_id=service_context_alert().issue_id, issue_number=job['issueNumber'],
        identity_hash=identity_hash_for(service_context_alert().issue_id, job['releaseSha']),
        base_sha='d' * 40, branch_base_sha='b' * 40, source_sha=job['releaseSha'],
        source_path=decision['sourcePath'],
        files=[{key: item[key] for key in ('path', 'kind', 'beforeSha256', 'afterSha256')}
               for item in decision['files']],
    )


def test_publication_record_survives_interleaved_job_writes_without_app_branch_files():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    job, _ = _proposal_fixture(queue)
    queue.put(job)
    manifest = _publication_fixture()
    head = 'e' * 40
    queue.put_publication(head, manifest)
    job['attempts']['production'] = 1
    queue.put(job)

    fresh = InvestigationQueue(github)
    assert fresh.get_publication(head) == manifest
    assert fresh.get(service_context_alert())['attempts'] == {'production': 1}
    assert set(github.refs) == {STATE_REFERENCE}
    assert f'publications/{head}.json' in fresh._entries(fresh._head())


def test_publication_record_cannot_be_rebound_to_different_verification():
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    manifest = _publication_fixture()
    head = 'e' * 40
    queue.put_publication(head, manifest)
    altered = {**manifest, 'baseSha': 'f' * 40}
    with pytest.raises(JobConflict, match='different verification'):
        queue.put_publication(head, altered)
    assert InvestigationQueue(github).get_publication(head) == manifest


@pytest.mark.parametrize('field,value', [('headSha', 'f' * 40), ('manifestDigest', 'f' * 64)])
def test_external_publication_rejects_tampered_binding_and_digest(field, value):
    import json
    github = MemoryGitHub()
    queue = InvestigationQueue(github)
    head = 'e' * 40
    queue.put_publication(head, _publication_fixture())
    path = f'publications/{head}.json'
    parent = github.refs[STATE_REFERENCE]
    record_sha = queue._entries(parent)[path]
    record = json.loads(github.blobs[record_sha])
    record[field] = value
    replacement = github.rest('POST', f'{REPOSITORY_PATH}/git/blobs', {
        'content': base64.b64encode(json.dumps(record).encode()).decode(), 'encoding': 'base64',
    })['sha']
    tree = github.rest('POST', f'{REPOSITORY_PATH}/git/trees', {
        'base_tree': github.commits[parent]['tree'],
        'tree': [{'path': path, 'mode': '100644', 'type': 'blob', 'sha': replacement}],
    })['sha']
    commit = github.rest('POST', f'{REPOSITORY_PATH}/git/commits', {
        'tree': tree, 'parents': [parent], 'message': 'Malformed external update',
    })['sha']
    github.rest('PATCH', f'{REPOSITORY_PATH}/git/refs/{STATE_REFERENCE.removeprefix("refs/")}',
                {'sha': commit, 'force': False})
    with pytest.raises(ValueError):
        InvestigationQueue(github).get_publication(head)
