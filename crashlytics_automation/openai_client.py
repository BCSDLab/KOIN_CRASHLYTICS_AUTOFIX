"""OpenAI Responses API client for sandboxed crash investigation and fix proposals."""

from __future__ import annotations

import json
import re
import time
from typing import Any

import requests

from .candidate import MAX_CANDIDATE_FILES, MAX_FILE_BYTES, canonical_json

RESPONSES_URL = 'https://api.openai.com/v1/responses'
REQUEST_TIMEOUT_SECONDS = 180
MAX_OUTPUT_TOKENS = 32_000
MAX_REASON_LENGTH = 4000
MAX_ANALYSIS_LENGTH = 16_000
MAX_TOOL_CALLS = 100
MAX_COMMAND_OUTPUT_BYTES = 32_000
MAX_TOTAL_TOOL_OUTPUT_BYTES = 256_000
MAX_CUMULATIVE_INPUT_TOKENS = 1_000_000
MAX_INVESTIGATION_SECONDS = 20 * 60
MAX_COMMAND_TIMEOUT_SECONDS = 600
DEFAULT_MODEL = 'gpt-6.1-sol'

MODEL_NAME = re.compile(r'[A-Za-z0-9._-]{1,100}')

SYSTEM_PROMPT = f"""You are an Android/Kotlin crash investigator and fix-proposal assistant for the KOIN_ANDROID repository.

You receive the complete Crashlytics evidence and paths to the complete target and release workspaces. Use the run_command tool to inspect source, dependency sources, build configuration, and diagnostics, and to run commands in the isolated investigation sandbox. Target source is writable. The release workspace is read-only. Scratch files belong in /workspace/scratch. The app frame, when present, is only a hint; investigate even when no application frame exists.

Investigate the crash using real tool output before deciding. You may run builds, tests, emulator commands, and diagnostic shell commands. Do not claim that a command ran unless its output appears in tool results. A nonzero command exit is useful observed output, but final decisions require at least one successful, non-timeout command execution. Distinguish successful reproduction from a successful diagnostic command. Separate observed evidence, tested hypotheses, reproduction/results, and uncertainty in analysis. A latent defect or successful test is not proof that the original incident had that trigger.

Return decision "fix" only for a specific defect supported by the evidence and investigation. Otherwise return "no-fix" with a concise Korean reason. A refusal or a decision without investigation is not a completed result.

For a fix, return complete source file contents and a deterministic regression test class named exactly by context.regressionTestName. Verify it against the actual production fix; run the regression test and report its real outcome in analysis. Only existing Android production .kt/.java files and new regression test .kt files are publishable; do not edit build files, resources, workflows, documentation, or configuration. Temporary test harness and build files may be created in the sandbox. Keep the fix minimal. At most {MAX_CANDIDATE_FILES} files, each at most {MAX_FILE_BYTES} bytes. Never include secrets, tokens, user data, or URLs in returned files.

Return the required JSON fields exactly: decision, reason, analysis, sourcePath, sourceLine, files. sourcePath and sourceLine must identify the defect anchor in the UNMODIFIED /workspace/release checkout, never a target line added by your patch; return both null when no defect is identified. Do not include tool claims in place of the trusted tool execution record."""

RESPONSE_SCHEMA = {
    'type': 'object',
    'additionalProperties': False,
    'required': ['decision', 'reason', 'analysis', 'sourcePath', 'sourceLine', 'files'],
    'properties': {
        'decision': {'type': 'string', 'enum': ['fix', 'no-fix']},
        'reason': {'type': 'string'},
        'analysis': {'type': 'string'},
        'sourcePath': {'type': ['string', 'null']},
        'sourceLine': {'type': ['integer', 'null']},
        'files': {
            'type': 'array',
            'maxItems': MAX_CANDIDATE_FILES,
            'items': {
                'type': 'object',
                'additionalProperties': False,
                'required': ['path', 'content'],
                'properties': {'path': {'type': 'string'}, 'content': {'type': 'string'}},
            },
        },
    },
}

RUN_COMMAND = {
    'type': 'function',
    'name': 'run_command',
    'description': 'Run a command in the isolated investigation workspace and return actual stdout/stderr/exit status.',
    'strict': True,
    'parameters': {
        'type': 'object',
        'additionalProperties': False,
        'required': ['command', 'timeout_seconds'],
        'properties': {
            'command': {'type': 'string'},
            'timeout_seconds': {'type': 'integer'},
        },
    },
}


class FixProposalResponseError(RuntimeError):
    """Rejected provider or structured-output payload."""

    def __init__(self, message: str, code: str | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def _invalid(message: str) -> FixProposalResponseError:
    return FixProposalResponseError(message, code='invalid_model_response')


def _output_text(body: Any) -> str | None:
    if isinstance(body, dict):
        direct = body.get('output_text')
        if isinstance(direct, str) and direct:
            return direct
        output = body.get('output')
        for item in output if isinstance(output, list) else []:
            if not isinstance(item, dict) or item.get('type') != 'message' or item.get('role') != 'assistant':
                continue
            content = item.get('content')
            for part in content if isinstance(content, list) else []:
                if isinstance(part, dict) and part.get('type') == 'output_text' and isinstance(part.get('text'), str):
                    return part['text']
    return None


def _refused(body: Any) -> bool:
    output = body.get('output') if isinstance(body, dict) else None
    for item in output if isinstance(output, list) else []:
        if not isinstance(item, dict) or item.get('type') != 'message':
            continue
        content = item.get('content')
        for part in content if isinstance(content, list) else []:
            if isinstance(part, dict) and part.get('type') == 'refusal':
                return True
    return False


def _normalize_decision(parsed: Any) -> dict[str, Any]:
    if not isinstance(parsed, dict):
        raise _invalid('Model output is not an object')
    decision, reason, analysis = parsed.get('decision'), parsed.get('reason'), parsed.get('analysis')
    source_path, source_line, files = parsed.get('sourcePath'), parsed.get('sourceLine'), parsed.get('files')
    if decision not in ('fix', 'no-fix'):
        raise _invalid('Model output has an invalid decision')
    if not isinstance(reason, str) or len(reason) > MAX_REASON_LENGTH:
        raise _invalid('Model output reason is invalid')
    if not isinstance(analysis, str) or len(analysis) > MAX_ANALYSIS_LENGTH:
        raise _invalid('Model output analysis is invalid')
    if source_path is not None and (not isinstance(source_path, str) or not source_path):
        raise _invalid('Model output sourcePath is invalid')
    if source_line is not None and (type(source_line) is not int or source_line < 1):
        raise _invalid('Model output sourceLine is invalid')
    if (source_path is None) != (source_line is None):
        raise _invalid('Model output source location is incomplete')
    if not isinstance(files, list) or len(files) > MAX_CANDIDATE_FILES:
        raise _invalid('Model output files are invalid')
    normalized: list[dict[str, str]] = []
    for file in files:
        if not isinstance(file, dict):
            raise _invalid('Model output file entry is invalid')
        path, content = file.get('path'), file.get('content')
        if not isinstance(path, str) or not path or not isinstance(content, str):
            raise _invalid('Model output file entry is invalid')
        normalized.append({'path': path, 'content': content})
    if decision == 'fix' and not normalized:
        raise _invalid('Model output fix has no files')
    if decision == 'no-fix' and normalized:
        raise _invalid('Model output no-fix contains files')
    if decision == 'fix' and source_path is None:
        raise _invalid('Model output fix has no source location')
    return {
        'decision': decision,
        'reason': reason,
        'analysis': analysis,
        'sourcePath': source_path,
        'sourceLine': source_line,
        'files': normalized,
    }


def _response(
    http: Any,
    api_key: str,
    model: str,
    request_input: list[dict[str, Any]],
    max_tokens: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    payload = {
        'model': model,
        'input': request_input,
        'tools': [RUN_COMMAND],
        'tool_choice': 'auto',
        'parallel_tool_calls': False,
        'text': {
            'format': {
                'type': 'json_schema',
                'name': 'crashlytics_investigation',
                'strict': True,
                'schema': RESPONSE_SCHEMA,
            },
        },
        'max_output_tokens': max_tokens,
        'store': False,
    }
    try:
        data = canonical_json(payload).encode('utf-8')
    except UnicodeEncodeError as error:
        raise ValueError('Invalid Unicode in generation payload') from error
    try:
        response = http.post(
            RESPONSES_URL,
            data=data,
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            timeout=timeout_seconds,
            allow_redirects=False,
        )
    except (requests.Timeout, TimeoutError) as error:
        raise FixProposalResponseError('OpenAI request timed out', code='provider_timeout') from error
    except requests.RequestException as error:
        raise FixProposalResponseError('OpenAI request failed', code='provider_error') from error
    if response.status_code >= 400:
        raise FixProposalResponseError(
            f'OpenAI API returned {response.status_code}', status=int(response.status_code),
        )
    try:
        result = response.json()
    except ValueError as error:
        raise _invalid('Model response is not valid JSON') from error
    if not isinstance(result, dict):
        raise _invalid('Model response is not an object')
    if result.get('status') == 'incomplete':
        details = result.get('incomplete_details')
        reason = details.get('reason') if isinstance(details, dict) else None
        raise FixProposalResponseError(
            f'OpenAI response incomplete: {reason if isinstance(reason, str) else "unknown"}',
            code='incomplete_model_response',
        )
    if result.get('status') == 'failed':
        error = result.get('error')
        code = error.get('code') if isinstance(error, dict) else None
        raise FixProposalResponseError(
            f'OpenAI response failed: {code if isinstance(code, str) else "unknown"}',
            code='failed_model_response',
        )
    return result


def _tool_calls(body: dict[str, Any]) -> list[dict[str, Any]]:
    output = body.get('output')
    return [
        item for item in output if isinstance(item, dict) and item.get('type') == 'function_call'
    ] if isinstance(output, list) else []


def _redact(value: str, api_key: str) -> str:
    text = value.replace(api_key, '[REDACTED]') if api_key else value
    text = re.sub(r'\b(bearer\s+)[^\s"\']+', r'\1[REDACTED]', text, flags=re.IGNORECASE)
    return re.sub(
        r'\b(password|secret|token|api[_-]?key|authorization)\s*[:=]\s*("[^"]*"|\'[^\']*\'|[^\s,;]+)',
        r'\1=[REDACTED]',
        text,
        flags=re.IGNORECASE,
    )


def _sanitize_context(value: Any, api_key: str) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                '[REDACTED]'
                if re.search(r'(?:password|secret|token|api[_-]?key|authorization)', str(key), re.IGNORECASE)
                else _sanitize_context(item, api_key)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_context(item, api_key) for item in value]
    if isinstance(value, str):
        return _redact(value, api_key)
    return value


def request_fix_proposal(
    *,
    model: str = DEFAULT_MODEL,
    api_key: Any,
    context: Any,
    execute: Any,
    session: Any = None,
) -> dict[str, Any]:
    """Iteratively investigate via the trusted sandbox callback, then return a proposal."""
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError('Missing OpenAI API key')
    if not isinstance(model, str) or not MODEL_NAME.fullmatch(model):
        raise ValueError('Invalid OpenAI model')
    if not isinstance(context, dict):
        raise ValueError('Invalid generation context')
    if not callable(execute):
        raise ValueError('Missing investigation command executor')
    http = session if session is not None else requests
    try:
        context_text = canonical_json(_sanitize_context(context, api_key))
    except (TypeError, ValueError) as error:
        raise ValueError('Invalid generation context') from error

    request_input: list[dict[str, Any]] = [
        {'role': 'system', 'content': SYSTEM_PROMPT},
        {'role': 'user', 'content': context_text},
    ]
    started = time.monotonic()
    calls = 0
    output_bytes = 0
    output_tokens = 0
    tool_results: list[dict[str, Any]] = []
    cumulative_input_tokens = 0
    successful_execution = False
    while True:
        remaining_time = MAX_INVESTIGATION_SECONDS - (time.monotonic() - started)
        if remaining_time <= 0:
            raise FixProposalResponseError('Investigation time limit exceeded', code='investigation_timeout')
        remaining_tokens = MAX_OUTPUT_TOKENS - output_tokens
        if remaining_tokens <= 0:
            raise FixProposalResponseError('Investigation output budget exceeded', code='investigation_output_limit')
        estimated_input_tokens = len(canonical_json(request_input).encode('utf-8'))
        estimated_input_tokens += len(canonical_json([RUN_COMMAND, RESPONSE_SCHEMA]).encode('utf-8'))
        if cumulative_input_tokens + estimated_input_tokens > MAX_CUMULATIVE_INPUT_TOKENS:
            raise FixProposalResponseError(
                'Investigation input budget exceeded', code='investigation_input_limit',
            )
        body = _response(
            http, api_key, model, request_input,
            min(MAX_OUTPUT_TOKENS, remaining_tokens),
            min(REQUEST_TIMEOUT_SECONDS, remaining_time),
        )
        usage = body.get('usage')
        reported_input_tokens = usage.get('input_tokens') if isinstance(usage, dict) else None
        cumulative_input_tokens += (
            reported_input_tokens
            if type(reported_input_tokens) is int and reported_input_tokens >= 0
            else estimated_input_tokens
        )
        if cumulative_input_tokens > MAX_CUMULATIVE_INPUT_TOKENS:
            raise FixProposalResponseError(
                'Investigation input budget exceeded', code='investigation_input_limit',
            )
        usage = body.get('usage')
        reported_tokens = usage.get('output_tokens') if isinstance(usage, dict) else None
        output_tokens += (
            reported_tokens
            if type(reported_tokens) is int and reported_tokens >= 0
            else len(canonical_json(body).encode('utf-8'))
        )
        if output_tokens > MAX_OUTPUT_TOKENS:
            raise FixProposalResponseError('Investigation output budget exceeded', code='investigation_output_limit')
        if _refused(body):
            raise FixProposalResponseError(
                'OpenAI refused the investigation request', code='investigation_refused',
            )
        tool_calls = _tool_calls(body)
        if not tool_calls:
            if not tool_results:
                raise FixProposalResponseError(
                    'Model completed without investigating the workspace', code='investigation_not_performed',
                )
            if not successful_execution:
                raise FixProposalResponseError(
                    'Investigation completed without a successful command execution',
                    code='investigation_execution_failed',
                )
            text = _output_text(body)
            if not text:
                raise _invalid('Model response has no structured output')
            try:
                result = _normalize_decision(json.loads(text))
            except ValueError as error:
                if isinstance(error, FixProposalResponseError):
                    raise
                raise _invalid('Model output is not valid JSON') from error
            result['toolResults'] = tool_results
            return result

        if calls + len(tool_calls) > MAX_TOOL_CALLS:
            raise FixProposalResponseError('Investigation tool-call limit exceeded', code='investigation_call_limit')
        # Responses API stateless continuation must include the complete prior output
        # (including reasoning items) before each function_call_output item.
        prior_output = body.get('output')
        if not isinstance(prior_output, list):
            raise _invalid('Model tool-call response has no output items')
        request_input.extend(prior_output)
        for call in tool_calls:
            calls += 1
            call_id, name, raw_arguments = call.get('call_id'), call.get('name'), call.get('arguments')
            if not isinstance(call_id, str) or not call_id or name != 'run_command' or not isinstance(raw_arguments, str):
                raise _invalid('Model tool call is invalid')
            try:
                arguments = json.loads(raw_arguments)
            except ValueError as error:
                raise _invalid('Model tool arguments are invalid') from error
            if (
                not isinstance(arguments, dict)
                or set(arguments) != {'command', 'timeout_seconds'}
                or not isinstance(arguments['command'], str)
                or not arguments['command'].strip()
                or len(arguments['command']) > 16_000
                or type(arguments['timeout_seconds']) is not int
                or not 1 <= arguments['timeout_seconds'] <= MAX_COMMAND_TIMEOUT_SECONDS
            ):
                raise _invalid('Model tool arguments are invalid')
            command_timeout = min(
                arguments['timeout_seconds'],
                int(MAX_INVESTIGATION_SECONDS - (time.monotonic() - started)),
            )
            if command_timeout < 1:
                raise FixProposalResponseError('Investigation time limit exceeded', code='investigation_timeout')
            try:
                executed = execute(
                    command=arguments['command'],
                    timeout_seconds=command_timeout,
                )
            except Exception as error:
                raise FixProposalResponseError(
                    'Investigation command execution failed', code='tool_execution_failed',
                ) from error
            if (
                not isinstance(executed, dict)
                or set(executed) != {'exit_code', 'stdout', 'stderr', 'timed_out'}
                or (executed['exit_code'] is not None and type(executed['exit_code']) is not int)
                or not isinstance(executed['stdout'], str)
                or not isinstance(executed['stderr'], str)
                or not isinstance(executed['timed_out'], bool)
            ):
                raise FixProposalResponseError('Investigation command returned invalid output', code='tool_output_invalid')
            if executed['exit_code'] == 0 and not executed['timed_out']:
                successful_execution = True
            record = {
                'command': _redact(arguments['command'], api_key),
                'exit_code': executed['exit_code'],
                'stdout': _redact(executed['stdout'], api_key),
                'stderr': _redact(executed['stderr'], api_key),
                'timed_out': executed['timed_out'],
            }
            encoded_size = len(canonical_json(record).encode('utf-8'))
            available = min(MAX_COMMAND_OUTPUT_BYTES, MAX_TOTAL_TOOL_OUTPUT_BYTES - output_bytes)
            if available <= 0:
                raise FixProposalResponseError('Investigation output budget exceeded', code='investigation_output_limit')
            if encoded_size > available:
                fixed_record = dict(record, stdout='', stderr='')
                fixed_size = len(canonical_json(fixed_record).encode('utf-8'))
                keep = max(0, (available - fixed_size - 64) // 2)
                for field in ('stdout', 'stderr'):
                    value = record[field]
                    record[field] = value.encode('utf-8')[:keep].decode('utf-8', errors='ignore') + '\n[output truncated]'
                encoded_size = len(canonical_json(record).encode('utf-8'))
                if encoded_size > available:
                    raise FixProposalResponseError('Investigation output budget exceeded', code='investigation_output_limit')
            output_bytes += encoded_size
            tool_results.append(record)
            request_input.append({
                'type': 'function_call_output',
                'call_id': call_id,
                'output': canonical_json(record),
            })

