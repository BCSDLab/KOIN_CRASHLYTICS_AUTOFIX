import json

import pytest

from crashlytics_automation import github
from crashlytics_automation.repository import (
    AUTOMATION_DISPATCH_PATH,
    AUTOMATION_REPOSITORY,
    REPOSITORY,
    REPOSITORY_PATH,
    STATE_REFERENCE,
)


class Response:
    def __init__(self, status, body=None):
        self.status_code = status
        self.body = body or {}

    def json(self):
        return self.body


class Session:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [Response(200, {'object': {'sha': 'a' * 40}})])

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_automation_installation_dispatches_only_main_workflow_and_returns_204(monkeypatch):
    monkeypatch.setattr(github.jwt, 'encode', lambda *_a, **_k: 'test-jwt')
    session = Session([
        Response(200, {'token': 'automation-token'}),
        Response(204),
    ])
    client = github.create_github(
        '123', '456', 'test-key', repository=AUTOMATION_REPOSITORY,
        permissions={'actions': 'write'}, session=session,
    )

    assert client.rest('POST', AUTOMATION_DISPATCH_PATH, {'ref': 'main'}) is None
    token_request = session.calls[0]
    assert json.loads(token_request[2]['data']) == {
        'repositories': [AUTOMATION_REPOSITORY.split('/', 1)[1]],
        'permissions': {'actions': 'write'},
    }
    dispatch = session.calls[1]
    assert dispatch[0] == 'POST'
    assert dispatch[1] == 'https://api.github.com' + AUTOMATION_DISPATCH_PATH
    assert json.loads(dispatch[2]['data']) == {'ref': 'main'}
    assert dispatch[2]['headers']['Authorization'] == 'Bearer automation-token'


@pytest.mark.parametrize('method,path,body', [
    ('GET', AUTOMATION_DISPATCH_PATH, {'ref': 'main'}),
    ('POST', AUTOMATION_DISPATCH_PATH, {'ref': 'develop'}),
    ('POST', AUTOMATION_DISPATCH_PATH, {'ref': 'main', 'inputs': {'x': 'y'}}),
    ('POST', AUTOMATION_DISPATCH_PATH + '?ref=main', {'ref': 'main'}),
    ('PATCH', AUTOMATION_DISPATCH_PATH, {'ref': 'main'}),
    ('POST', REPOSITORY_PATH + '/issues', {'title': 'privilege escalation'}),
    ('POST', '/graphql', {'query': 'mutation { ... }'}),
    ('PUT', AUTOMATION_DISPATCH_PATH, {'ref': 'main'}),
])
def test_automation_client_rejects_non_dispatch_requests(method, path, body):
    session = Session()
    client = github.GitHub('automation-token', session, repository=AUTOMATION_REPOSITORY)

    with pytest.raises(ValueError):
        client.rest(method, path, body)

    assert session.calls == []


def test_automation_client_cannot_checkout(tmp_path):
    client = github.GitHub('automation-token', Session(), repository=AUTOMATION_REPOSITORY)

    with pytest.raises(ValueError):
        client.checkout('a' * 40, tmp_path)


@pytest.mark.parametrize('repository,permissions', [
    ('BCSDLab/OTHER', {'actions': 'write'}),
    (AUTOMATION_REPOSITORY, None),
    (AUTOMATION_REPOSITORY, {'contents': 'write'}),
    (AUTOMATION_REPOSITORY, {'actions': 'write', 'contents': 'read'}),
    (AUTOMATION_REPOSITORY, {'actions': 'read'}),
])
def test_invalid_repository_or_automation_permissions_are_rejected_before_request(
    repository, permissions, monkeypatch
):
    session = Session()
    monkeypatch.setattr(github.jwt, 'encode', lambda *_a, **_k: 'test-jwt')

    with pytest.raises(ValueError):
        github.create_github(
            '123', '456', 'test-key', repository=repository,
            permissions=permissions, session=session,
        )

    assert session.calls == []


def test_direct_client_constructor_rejects_arbitrary_repository():
    session = Session()

    with pytest.raises(ValueError):
        github.GitHub('token', session, repository='BCSDLab/OTHER')

    assert session.calls == []


@pytest.mark.parametrize('method,path,body', [
    ('PATCH', '/git/refs/heads/main', {'sha': 'a' * 40}),
    ('POST', '/git/refs', {'ref': 'refs/heads/new-code', 'sha': 'a' * 40}),
    ('PUT', '/contents/main.py', {'content': 'dW53YW50ZWQ='}),
])
def test_application_installation_cannot_send_state_or_code_to_another_repository(method, path, body):
    session = Session()
    client = github.GitHub('test-token', session)

    with pytest.raises(ValueError):
        client.rest(method, '/repos/BCSDLab/KOIN_CRASHLYTICS_AUTOFIX' + path, body)

    assert session.calls == []


def test_state_reference_can_advance_but_cannot_force_overwrite_a_concurrent_writer():
    session = Session()
    client = github.GitHub('test-token', session)
    path = REPOSITORY_PATH + '/git/refs/' + STATE_REFERENCE.removeprefix('refs/')
    client.rest('PATCH', path, {'sha': 'a' * 40, 'force': False})

    with pytest.raises(ValueError):
        client.rest('PATCH', path, {'sha': 'b' * 40, 'force': True})

    assert len(session.calls) == 1


def test_rejected_installation_cannot_silently_fall_back(monkeypatch):
    session = Session([Response(422)])
    monkeypatch.setattr(github.jwt, 'encode', lambda *_a, **_k: 'test-jwt')

    with pytest.raises(github.GitHubError) as error:
        github.create_github(
            '123', '456', 'test-key', repository=AUTOMATION_REPOSITORY,
            permissions={'actions': 'write'}, session=session,
        )

    assert error.value.status == 422
    assert len(session.calls) == 1
    assert json.loads(session.calls[0][2]['data']) == {
        'repositories': [AUTOMATION_REPOSITORY.split('/', 1)[1]],
        'permissions': {'actions': 'write'},
    }


def test_application_create_github_defaults_to_unchanged_app_scope(monkeypatch):
    session = Session([Response(200, {'token': 'app-token'})])
    monkeypatch.setattr(github.jwt, 'encode', lambda *_a, **_k: 'test-jwt')

    client = github.create_github(
        '123', '456', 'test-key', permissions={'contents': 'write'}, session=session,
    )

    assert json.loads(session.calls[0][2]['data']) == {
        'repositories': [REPOSITORY.split('/', 1)[1]],
        'permissions': {'contents': 'write'},
    }
