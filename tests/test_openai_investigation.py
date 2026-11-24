import json

import pytest

from crashlytics_automation.openai_client import (
    FixProposalResponseError,
    request_fix_proposal,
)


class FakeResponse:
    status_code = 200

    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class FakeSession:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.payloads = []

    def post(self, _url, *, data, **_kwargs):
        self.payloads.append(json.loads(data))
        return FakeResponse(self.responses.pop(0))


def final(decision='no-fix'):
    return {
        'status': 'completed',
        'output_text': json.dumps({
            'decision': decision,
            'reason': '조사 결과 수정이 필요하지 않습니다.',
            'analysis': '관찰: 명령 출력 확인. 가설: 재현되지 않음. 불확실성: 없음.',
            'sourcePath': None,
            'sourceLine': None,
            'files': [],
        }),
    }


def tool_call(
    arguments='{"command":"find /workspace/target -type f","timeout_seconds":30}',
    call_id='call_1',
    item_id='fc_1',
    reasoning_id='rs_1',
):
    return {
        'status': 'completed',
        'output': [
            {'type': 'reasoning', 'id': reasoning_id, 'summary': []},
            {
                'type': 'function_call',
                'id': item_id,
                'call_id': call_id,
                'name': 'run_command',
                'arguments': arguments,
            },
        ],
    }


def test_investigation_executes_commands_and_retains_context_across_turns():
    session = FakeSession(
        tool_call(),
        tool_call(
            '{"command":"./gradlew :app:testDebugUnitTest","timeout_seconds":300}',
            call_id='call_2',
            item_id='fc_2',
            reasoning_id='rs_2',
        ),
        final(),
    )
    executed = []

    def execute(*, command, timeout_seconds):
        executed.append((command, timeout_seconds))
        stdout = (
            '/workspace/target/app/src/Main.kt\n'
            if len(executed) == 1
            else 'BUILD SUCCESSFUL\n'
        )
        return {'exit_code': 0, 'stdout': stdout, 'stderr': '', 'timed_out': False}

    result = request_fix_proposal(
        api_key='secret-key',
        context={
            'paths': {'target': '/workspace/target'},
            'crash': {'frame': None, 'stackTrace': {'exceptions': []}},
            'regressionTestName': 'CrashRegressionTest',
        },
        execute=execute,
        session=session,
    )

    assert executed == [
        ('find /workspace/target -type f', 30),
        ('./gradlew :app:testDebugUnitTest', 300),
    ]
    assert result['decision'] == 'no-fix'
    assert [item['stdout'] for item in result['toolResults']] == [
        '/workspace/target/app/src/Main.kt\n',
        'BUILD SUCCESSFUL\n',
    ]
    first_followup = session.payloads[1]['input']
    assert first_followup[0]['role'] == 'system'
    assert json.loads(first_followup[1]['content'])['crash']['frame'] is None
    assert first_followup[2]['type'] == 'reasoning'
    assert first_followup[4]['type'] == 'function_call_output'
    assert first_followup[4]['call_id'] == 'call_1'
    second_followup = session.payloads[2]['input']
    assert second_followup[:2] == first_followup[:2]
    assert [item.get('id') for item in second_followup if item.get('type') == 'reasoning'] == ['rs_1', 'rs_2']
    assert [item['call_id'] for item in second_followup if item.get('type') == 'function_call_output'] == [
        'call_1', 'call_2'
    ]
    assert json.loads(second_followup[4]['output'])['stdout'] == '/workspace/target/app/src/Main.kt\n'
    assert json.loads(second_followup[-1]['output'])['stdout'] == 'BUILD SUCCESSFUL\n'
    assert session.payloads[0]['tools'][0]['name'] == 'run_command'
    assert session.payloads[0]['text']['format']['schema']['required'] == [
        'decision', 'reason', 'analysis', 'sourcePath', 'sourceLine', 'files'
    ]


def test_refusal_or_answer_without_tool_use_is_not_a_completed_investigation():
    refusal = {
        'status': 'completed',
        'output': [{'type': 'message', 'role': 'assistant', 'content': [{'type': 'refusal', 'refusal': 'no'}]}],
    }
    with pytest.raises(FixProposalResponseError) as error:
        request_fix_proposal(
            api_key='secret-key', context={'crash': {'frame': None}}, execute=lambda **_: None,
            session=FakeSession(refusal),
        )
    assert error.value.code == 'investigation_refused'

    with pytest.raises(FixProposalResponseError) as error:
        request_fix_proposal(
            api_key='secret-key', context={'crash': {'frame': None}}, execute=lambda **_: None,
            session=FakeSession(final()),
        )
    assert error.value.code == 'investigation_not_performed'


def test_failed_or_timed_out_commands_cannot_support_a_final_decision():
    for command_result in (
        {'exit_code': 1, 'stdout': 'compiler failed', 'stderr': '', 'timed_out': False},
        {'exit_code': 0, 'stdout': '', 'stderr': '', 'timed_out': True},
    ):
        with pytest.raises(FixProposalResponseError) as error:
            request_fix_proposal(
                api_key='secret-key',
                context={},
                execute=lambda **_: command_result,
                session=FakeSession(tool_call(), final()),
            )
        assert error.value.code == 'investigation_execution_failed'


def test_invalid_tool_arguments_are_rejected_without_running_callback():
    ran = False

    def execute(**_kwargs):
        nonlocal ran
        ran = True

    with pytest.raises(FixProposalResponseError) as error:
        request_fix_proposal(
            api_key='secret-key', context={}, execute=execute,
            session=FakeSession(tool_call('{"command":"ls","timeout_seconds":999999}')),
        )
    assert error.value.code == 'invalid_model_response'
    assert not ran


def test_provider_errors_do_not_echo_credentials_or_provider_body():
    class ErrorSession:
        def post(self, *_args, **_kwargs):
            return type('Response', (), {'status_code': 401, 'text': 'secret-key provider details'})()

    with pytest.raises(FixProposalResponseError) as error:
        request_fix_proposal(
            api_key='secret-key', context={}, execute=lambda **_: None, session=ErrorSession(),
        )
    assert error.value.status == 401
    assert 'secret-key' not in str(error.value)
    assert 'provider details' not in str(error.value)


def test_provider_timeout_and_token_limit_are_reported_without_secret_echo():
    import requests

    class TimeoutSession:
        def post(self, *_args, **_kwargs):
            raise requests.Timeout('secret-key in provider exception')

    with pytest.raises(FixProposalResponseError) as error:
        request_fix_proposal(
            api_key='secret-key', context={}, execute=lambda **_: None, session=TimeoutSession(),
        )
    assert error.value.code == 'provider_timeout'
    assert 'secret-key' not in str(error.value)

    token_limit = {
        'status': 'incomplete',
        'incomplete_details': {'reason': 'max_output_tokens'},
        'error': {'message': 'secret-key provider body'},
    }
    with pytest.raises(FixProposalResponseError) as error:
        request_fix_proposal(
            api_key='secret-key', context={}, execute=lambda **_: None, session=FakeSession(token_limit),
        )
    assert error.value.code == 'incomplete_model_response'
    assert 'secret-key' not in str(error.value)
