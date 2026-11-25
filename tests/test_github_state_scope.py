import json

import pytest

from crashlytics_automation import github
from crashlytics_automation.repository import REPO, STATE_REPO, STATE_REPOSITORY_PATH, STATE_REFERENCE


class Response:
    def __init__(self, status, body=None):
        self.status_code = status
        self.body = body or {}

    def json(self):
        return self.body


class Session:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return Response(200, {'object': {'sha': 'a' * 40}})


@pytest.mark.parametrize('method,path,body', [
    ('PATCH', '/git/refs/heads/main', {'sha': 'a' * 40}),
    ('POST', '/git/refs', {'ref': 'refs/heads/new-code', 'sha': 'a' * 40}),
    ('PUT', '/contents/main.py', {'content': 'dW53YW50ZWQ='}),
])
def test_state_access_cannot_mutate_automation_code(method, path, body):
    session = Session()
    client = github.GitHub('test-token', session, include_state=True)

    with pytest.raises(ValueError):
        client.rest(method, STATE_REPOSITORY_PATH + path, body)

    assert session.calls == []


def test_application_only_credentials_cannot_write_the_state_reference():
    session = Session()
    client = github.GitHub('test-token', session)

    with pytest.raises(ValueError):
        client.rest('PATCH', STATE_REPOSITORY_PATH + '/git/refs/' + STATE_REFERENCE.removeprefix('refs/'),
                    {'sha': 'a' * 40, 'force': False})

    assert session.calls == []


def test_state_reference_can_advance_but_cannot_force_overwrite_a_concurrent_writer():
    session = Session()
    client = github.GitHub('test-token', session, include_state=True)
    path = STATE_REPOSITORY_PATH + '/git/refs/' + STATE_REFERENCE.removeprefix('refs/')
    client.rest('PATCH', path, {'sha': 'a' * 40, 'force': False})

    with pytest.raises(ValueError):
        client.rest('PATCH', path, {'sha': 'b' * 40, 'force': True})

    assert len(session.calls) == 1


def test_missing_repository_authorization_cannot_silently_fall_back(monkeypatch):
    class TargetOnlyInstallation(Session):
        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            request = json.loads(kwargs['data'])
            if STATE_REPO in request['repositories']:
                return Response(422)
            if request['repositories'] == [REPO]:
                return Response(201, {'token': 'target-only-token'})
            raise AssertionError('Unexpected installation scope')

    session = TargetOnlyInstallation()
    monkeypatch.setattr(github.jwt, 'encode', lambda *_a, **_k: 'test-jwt')

    with pytest.raises(github.GitHubError) as error:
        github.create_github('123', '456', 'test-key', session=session,
                             permissions={'contents': 'write'}, include_state=True)

    assert error.value.status == 422
    assert len(session.calls) == 1
