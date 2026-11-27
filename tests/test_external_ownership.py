import pytest

from crashlytics_automation import ownership
from crashlytics_automation.candidate import candidate_manifest, identity_hash_for, regression_test_name
from crashlytics_automation.models import SourceLocation

SOURCE_PATH = 'domain/src/main/kotlin/org/koin/Thing.kt'
RELEASE = 'a' * 40
HEAD = 'b' * 40
MERGE = 'c' * 40
IDENTITY = identity_hash_for('ownership-issue', RELEASE)


def _manifest():
    from crashlytics_automation.behavior import candidate_digest, source_digest

    regression = f'domain/src/test/kotlin/org/koin/{regression_test_name(IDENTITY)}'
    preservation = (
        f'domain/src/test/kotlin/org/koin/CrashlyticsPreservation{IDENTITY[:12]}Test.kt'
    )
    files = [
        {'path': SOURCE_PATH, 'kind': 'source', 'beforeSha256': 'd' * 64, 'afterSha256': 'e' * 64},
        {'path': regression, 'kind': 'test', 'beforeSha256': None, 'afterSha256': 'f' * 64},
        {'path': preservation, 'kind': 'test', 'beforeSha256': None, 'afterSha256': '1' * 64},
    ]
    proof = {
        'version': 2, 'passed': True, 'reason': 'Both regression and preservation checks passed.',
        'candidateDigest': candidate_digest(files),
        'behaviorReview': {
            'version': 1, 'approved': True, 'reason': 'No unrelated behavior changes.',
            'unrelatedChanges': [],
            'contracts': [{
                'sourcePath': SOURCE_PATH, 'sourceLine': 1,
                'behavior': 'Existing behavior remains unchanged.',
                'testPath': preservation, 'testMethod': 'existingBehaviorRemainsUnchanged',
            }],
            'sourceDigest': source_digest(files),
        },
        'checks': [
            {'phase': 'baseline', 'purpose': 'crash', 'path': regression,
             'exit_code': 1, 'timed_out': False, 'test_result': 'failed',
             'evidence': {'source': 'junit-xml'}, 'methods': []},
            {'phase': 'candidate', 'purpose': 'crash', 'path': regression,
             'exit_code': 0, 'timed_out': False, 'test_result': 'passed',
             'evidence': {'source': 'junit-xml'}, 'methods': ['regressionReproduced']},
            *[
                {'phase': phase, 'purpose': 'preservation', 'path': preservation,
                 'exit_code': 0, 'timed_out': False, 'test_result': 'passed',
                 'evidence': {'source': 'junit-xml'}, 'methods': ['existingBehaviorRemainsUnchanged']}
                for phase in ('baseline', 'candidate')
            ],
        ],
    }
    return candidate_manifest(
        issue_id='ownership-issue', issue_number=17, identity_hash=IDENTITY,
        base_sha=RELEASE, branch_base_sha=RELEASE, source_sha=RELEASE,
        source_path=SOURCE_PATH, files=files, verification=proof,
    )

def _pull(base='production'):
    from crashlytics_automation.candidate import branch_name_for
    return {
        'number': 17, 'merged': True,
        'headRefName': branch_name_for(IDENTITY, 17),
        'headRefOid': HEAD, 'baseRefName': base,
        'author': {'__typename': 'Bot', 'login': 'autofix'},
        'mergeCommit': {'oid': MERGE, 'parents': {
            'totalCount': 2, 'nodes': [{'oid': RELEASE}, {'oid': HEAD}],
        }},
    }

@pytest.mark.parametrize('blamed', [HEAD, MERGE])
def test_ai_ownership_uses_merged_pr_head_record_even_when_blame_is_merge_commit(monkeypatch, blamed):
    calls = []
    class Store:
        def get_publication(self, head, base):
            calls.append((head, base))
            return _manifest() if head == HEAD and base == 'production' else None

    monkeypatch.setattr(ownership, '_associated_pulls', lambda *_args: [_pull()])
    monkeypatch.setattr('crashlytics_automation.investigation_jobs.InvestigationQueue', lambda _github: Store())
    source = SourceLocation(SOURCE_PATH, 1, RELEASE, blamed, 'autofix[bot]')
    found = ownership.find_ai_fix_for_line(object(), source, bot_logins=('autofix[bot]',))
    assert found is not None
    assert found.pull_number == 17
    assert found.commit_sha == blamed
    assert calls == [(HEAD, 'production')]


def test_ai_ownership_uses_associated_pull_target_for_shared_branch(monkeypatch):
    calls = []
    class Store:
        def get_publication(self, head, base):
            calls.append((head, base))
            return _manifest() if head == HEAD and base == 'develop' else None

    monkeypatch.setattr(ownership, '_associated_pulls', lambda *_args: [_pull('develop')])
    monkeypatch.setattr('crashlytics_automation.investigation_jobs.InvestigationQueue', lambda _github: Store())
    source = SourceLocation(SOURCE_PATH, 1, RELEASE, HEAD, 'autofix[bot]')
    found = ownership.find_ai_fix_for_line(object(), source, bot_logins=('autofix[bot]',))
    assert found is not None
    assert calls == [(HEAD, 'develop')]

def test_missing_external_record_never_claims_ai_ownership(monkeypatch):
    class Store:
        def get_publication(self, _head, _base):
            return None

    monkeypatch.setattr(ownership, '_associated_pulls', lambda *_args: [_pull()])
    monkeypatch.setattr('crashlytics_automation.investigation_jobs.InvestigationQueue', lambda _github: Store())
    source = SourceLocation(SOURCE_PATH, 1, RELEASE, HEAD, 'autofix[bot]')
    assert ownership.find_ai_fix_for_line(object(), source, bot_logins=('autofix[bot]',)) is None


def test_malformed_merged_head_is_not_silently_treated_as_human_origin(monkeypatch):
    pull = {**_pull(), 'headRefOid': 'unbound'}
    monkeypatch.setattr(ownership, '_associated_pulls', lambda *_args: [pull])
    source = SourceLocation(SOURCE_PATH, 1, RELEASE, HEAD, 'autofix[bot]')
    with pytest.raises(RuntimeError, match='publication head'):
        ownership.find_ai_fix_for_line(object(), source, bot_logins=('autofix[bot]',))
