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
    return candidate_manifest(
        issue_id='ownership-issue', issue_number=17, identity_hash=IDENTITY,
        base_sha=RELEASE, branch_base_sha=RELEASE, source_sha=RELEASE,
        source_path=SOURCE_PATH,
        files=[
            {'path': SOURCE_PATH, 'kind': 'source', 'beforeSha256': 'd' * 64, 'afterSha256': 'e' * 64},
            {'path': f'domain/src/test/kotlin/org/koin/{regression_test_name(IDENTITY)}',
             'kind': 'test', 'beforeSha256': None, 'afterSha256': 'f' * 64},
        ],
    )


def _pull():
    return {
        'number': 17, 'merged': True,
        'headRefName': f'fix/17-crashlytics-production-{IDENTITY}',
        'headRefOid': HEAD, 'baseRefName': 'production',
        'author': {'__typename': 'Bot', 'login': 'autofix'},
        'mergeCommit': {'oid': MERGE, 'parents': {
            'totalCount': 2, 'nodes': [{'oid': RELEASE}, {'oid': HEAD}],
        }},
    }


@pytest.mark.parametrize('blamed', [HEAD, MERGE])
def test_ai_ownership_uses_merged_pr_head_record_even_when_blame_is_merge_commit(monkeypatch, blamed):
    class Store:
        def get_publication(self, head):
            return _manifest() if head == HEAD else None

    monkeypatch.setattr(ownership, '_associated_pulls', lambda *_args: [_pull()])
    monkeypatch.setattr('crashlytics_automation.investigation_jobs.InvestigationQueue', lambda _github: Store())
    source = SourceLocation(SOURCE_PATH, 1, RELEASE, blamed, 'autofix[bot]')
    found = ownership.find_ai_fix_for_line(object(), source, bot_logins=('autofix[bot]',))
    assert found is not None
    assert found.pull_number == 17
    assert found.commit_sha == blamed


def test_missing_external_record_never_claims_ai_ownership(monkeypatch):
    class Store:
        def get_publication(self, _head):
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
