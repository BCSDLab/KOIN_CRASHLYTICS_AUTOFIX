import json
import shlex
import subprocess
import tempfile
from pathlib import Path

import pytest

from crashlytics_automation import openai_client
from crashlytics_automation.openai_client import (
    FixProposalResponseError,
    _run_experiment,
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
    text = json.dumps({
        'decision': decision,
        'reason': '조사 결과 수정이 필요하지 않습니다.',
        'analysis': '관찰: 명령 출력 확인. 가설: 재현되지 않음. 불확실성: 없음.',
        'sourcePath': None,
        'sourceLine': None,
        'files': [],
    })
    return {
        'status': 'completed',
        'output_text': text,
        'output': [
            {'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': text}]},
        ],
    }


def tool_call(
    arguments='{"command":"find /workspace/target -type f","timeout_seconds":30}',
    call_id='call_1',
    item_id='fc_1',
    reasoning_id='rs_1',
    name='run_command',
):
    return {
        'status': 'completed',
        'output': [
            {'type': 'reasoning', 'id': reasoning_id, 'summary': []},
            {
                'type': 'function_call',
                'id': item_id,
                'call_id': call_id,
                'name': name,
                'arguments': arguments,
            },
        ],
    }


def test_investigation_executes_real_tools_and_retains_context_across_turns(monkeypatch):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        scratch = root / 'scratch'
        target = root / 'target'
        scratch.mkdir()
        target.mkdir()
        monkeypatch.setattr(openai_client, 'EXPERIMENT_SCRATCH_ROOT', str(scratch))
        monkeypatch.setattr(openai_client, 'EXPERIMENT_TARGET_ROOT', str(target))
        session = FakeSession(
            tool_call('{"command":"pwd","timeout_seconds":30}'),
            tool_call(
                '{"script":"print(1 + 1)","timeout_seconds":300}',
                call_id='call_2',
                item_id='fc_2',
                reasoning_id='rs_2',
                name='run_experiment',
            ),
            final(),
        )
        executed = []

        def execute(*, command, timeout_seconds):
            executed.append((command, timeout_seconds))
            completed = subprocess.run(
                shlex.split(command),
                cwd=target,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                'exit_code': completed.returncode,
                'stdout': completed.stdout.decode('utf-8'),
                'stderr': completed.stderr.decode('utf-8'),
                'timed_out': False,
            }

        result = request_fix_proposal(
            api_key='secret-key',
            context={
                'paths': {'target': str(target)},
                'crash': {'frame': None, 'stackTrace': {'exceptions': []}},
                'regressionTestName': 'CrashRegressionTest',
            },
            execute=execute,
            session=session,
        )

        assert executed[0] == ('pwd', 30)
        assert executed[1][0].startswith('python3 -c ')
        assert result['decision'] == 'no-fix'
        assert [item['tool'] for item in result['toolResults']] == ['run_command', 'run_experiment']
        assert [item['stdout'] for item in result['toolResults']] == [f'{target}\n', '2\n']
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
        assert json.loads(second_followup[-1]['output'])['stdout'] == '2\n'
        assert (scratch / 'experiments' / '2' / 'stdout.txt').read_text() == '2\n'
        assert session.payloads[0]['tools'][0]['name'] == 'run_command'
        assert session.payloads[0]['tools'][1]['name'] == 'run_experiment'




def test_static_only_no_fix_is_continued_with_a_real_forced_runtime_probe(monkeypatch):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        scratch = root / 'scratch'
        target = root / 'target'
        scratch.mkdir()
        target.mkdir()
        monkeypatch.setattr(openai_client, 'EXPERIMENT_SCRATCH_ROOT', str(scratch))
        monkeypatch.setattr(openai_client, 'EXPERIMENT_TARGET_ROOT', str(target))
        session = FakeSession(
            tool_call('{"command":"pwd","timeout_seconds":30}'),
            final(),
            tool_call('{"script":"print(1 + 1)","timeout_seconds":30}', call_id='experiment_1', name='run_experiment'),
            final(),
        )

        def execute(*, command, timeout_seconds):
            completed = subprocess.run(
                command,
                shell=True,
                cwd=target,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                'exit_code': completed.returncode,
                'stdout': completed.stdout.decode('utf-8'),
                'stderr': completed.stderr.decode('utf-8'),
                'timed_out': False,
            }

        result = request_fix_proposal(
            api_key='secret-key',
            context={
                'crash': {'stackTrace': {'exceptions': []}},
                'paths': {'target': str(target)},
            },
            execute=execute,
            session=session,
        )

        assert session.payloads[2]['tool_choice'] == {'type': 'function', 'name': 'run_experiment'}
        forced_history = session.payloads[2]['input']
        assert json.loads(forced_history[1]['content'])['crash']['stackTrace']['exceptions'] == []
        assert any(
            item.get('type') == 'function_call_output'
            and json.loads(item['output'])['stdout'] == f'{target}\n'
            for item in forced_history
        )
        assert 'executable Python 3 hypothesis probe' in forced_history[-1]['content']
        assert [item['tool'] for item in result['toolResults']] == ['run_command', 'run_experiment']
        assert result['toolResults'][1]['stdout'] == '2\n'
        assert (scratch / 'experiments' / '2' / 'probe.py').read_text() == 'print(1 + 1)'
        assert (scratch / 'experiments' / '2' / 'stdout.txt').read_text() == '2\n'
        assert session.payloads[2]['max_output_tokens'] < session.payloads[1]['max_output_tokens']
def test_refusal_is_rejected_and_uninvestigated_no_fix_forces_real_probe(monkeypatch):
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

    with tempfile.TemporaryDirectory() as directory:
        scratch = Path(directory) / 'scratch'
        target = Path(directory) / 'target'
        scratch.mkdir()
        target.mkdir()
        monkeypatch.setattr(openai_client, 'EXPERIMENT_SCRATCH_ROOT', str(scratch))
        monkeypatch.setattr(openai_client, 'EXPERIMENT_TARGET_ROOT', str(target))
        session = FakeSession(
            final(),
            tool_call('{"script":"print(1)","timeout_seconds":30}', name='run_experiment'),
            final(),
        )

        def execute(*, command, timeout_seconds):
            completed = subprocess.run(
                shlex.split(command),
                cwd=target,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                'exit_code': completed.returncode,
                'stdout': completed.stdout.decode('utf-8'),
                'stderr': completed.stderr.decode('utf-8'),
                'timed_out': False,
            }

        result = request_fix_proposal(
            api_key='secret-key',
            context={'crash': {'frame': None}},
            execute=execute,
            session=session,
        )
        assert result['decision'] == 'no-fix'
        assert result['toolResults'][0]['tool'] == 'run_experiment'
        assert result['toolResults'][0]['stdout'] == '1\n'
        assert session.payloads[1]['tool_choice'] == {'type': 'function', 'name': 'run_experiment'}


def test_failed_or_timed_out_commands_cannot_support_a_final_decision():
    for command_result, expected_code in (
        ({'exit_code': 1, 'stdout': 'compiler failed', 'stderr': '', 'timed_out': False},
         'investigation_execution_failed'),
        ({'exit_code': 0, 'stdout': '', 'stderr': '', 'timed_out': True},
         'investigation_experiment_failed'),
    ):
        with pytest.raises(FixProposalResponseError) as error:
            request_fix_proposal(
                api_key='secret-key',
                context={},
                execute=lambda **_: command_result,
                session=FakeSession(
                    tool_call(),
                    final(),
                    tool_call('{"script":"print(1)","timeout_seconds":30}', name='run_experiment'),
                    final(),
                ),
            )
        assert error.value.code == expected_code


def test_run_experiment_persists_real_probe_and_nonzero_exit_in_isolated_temp_paths():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        scratch = root / 'scratch'
        target = root / 'target'
        scratch.mkdir()
        target.mkdir()
        script = (
            "import sys\n"
            "print('probe stdout')\n"
            "sys.stderr.write('probe stderr\\n')\n"
            "sys.exit(7)\n"
        )

        def execute(*, command, timeout_seconds):
            completed = subprocess.run(
                shlex.split(command),
                cwd=target,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
            return {
                'exit_code': completed.returncode,
                'stdout': completed.stdout.decode('utf-8'),
                'stderr': completed.stderr.decode('utf-8'),
                'timed_out': False,
            }

        result = _run_experiment(
            execute,
            script=script,
            timeout_seconds=10,
            callback_timeout_seconds=15,
            tool_call_index=17,
            scratch_root=str(scratch),
            target_root=str(target),
        )

        artifacts = scratch / 'experiments' / '17'
        assert result['exit_code'] == 7
        assert result['stdout'] == 'probe stdout\n'
        assert result['stderr'] == 'probe stderr\n'
        assert result['timed_out'] is False
        assert (artifacts / 'probe.py').read_text(encoding='utf-8') == script
        assert (artifacts / 'stdout.txt').read_bytes() == b'probe stdout\n'
        assert (artifacts / 'stderr.txt').read_bytes() == b'probe stderr\n'
        assert (artifacts / 'status.txt').read_text(encoding='utf-8') == '7\n'

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


def test_large_byte_input_uses_exact_count_and_can_complete_investigation(monkeypatch):
    monkeypatch.setattr(openai_client, 'MAX_CUMULATIVE_INPUT_TOKENS', 1000)
    proposal = {
        'decision': 'fix',
        'reason': 'A defect was identified.',
        'analysis': 'Observed a reproducible defect.',
        'sourcePath': 'src/Main.kt',
        'sourceLine': 12,
        'files': [{'path': 'src/Main.kt', 'content': 'class Main'}],
    }

    class Session:
        def __init__(self):
            self.generation_calls = 0
            self.count_calls = 0

        def post(self, url, *, data, **_kwargs):
            if url == openai_client.INPUT_TOKENS_URL:
                self.count_calls += 1
                return FakeResponse({'object': 'response.input_tokens', 'input_tokens': 10})
            self.generation_calls += 1
            if self.generation_calls == 1:
                body = tool_call()
            else:
                body = {
                    'status': 'completed',
                    'output_text': json.dumps(proposal),
                    'usage': {'input_tokens': 10, 'output_tokens': 10},
                    'output': [],
                }
            if self.generation_calls == 1:
                body['usage'] = {'input_tokens': 10, 'output_tokens': 10}
            return FakeResponse(body)

    session = Session()
    result = request_fix_proposal(
        api_key='secret-key',
        context={'evidence': 'large ' * 1000},
        execute=lambda **_: {'exit_code': 0, 'stdout': 'ok', 'stderr': '', 'timed_out': False},
        session=session,
    )
    assert result['decision'] == 'fix'
    assert session.count_calls >= 1
    assert session.generation_calls == 2


@pytest.mark.parametrize('count_result,expected_code', [
    ({'object': 'response.input_tokens', 'input_tokens': 1001}, 'investigation_input_limit'),
    ({'object': 'response.input_tokens', 'input_tokens': True}, 'input_token_count_failed'),
    ({'object': 'response.input_tokens', 'input_tokens': -1}, 'input_token_count_failed'),
    ({'object': 'response', 'input_tokens': 10}, 'input_token_count_failed'),
    (None, 'input_token_count_failed'),
])
def test_over_budget_or_malformed_exact_count_prevents_generation(monkeypatch, count_result, expected_code):
    monkeypatch.setattr(openai_client, 'MAX_CUMULATIVE_INPUT_TOKENS', 1000)

    class Session:
        generation_calls = 0
        count_calls = 0

        def post(self, url, **_kwargs):
            if url == openai_client.INPUT_TOKENS_URL:
                self.count_calls += 1
                if count_result is None:
                    return type('FailedResponse', (), {'status_code': 503})()
                return FakeResponse(count_result)
            self.generation_calls += 1
            return FakeResponse(final())

    session = Session()
    with pytest.raises(FixProposalResponseError) as error:
        request_fix_proposal(
            api_key='secret-key',
            context={'evidence': 'large ' * 1000},
            execute=lambda **_: None,
            session=session,
        )
    assert session.count_calls == 1
    assert session.generation_calls == 0
    assert error.value.code == expected_code
