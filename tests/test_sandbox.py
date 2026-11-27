import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import pytest

from crashlytics_automation.candidate import regression_test_name
from crashlytics_automation.sandbox import (
    InvestigationSandbox, _COMMAND_WRAPPER, _instrumentation_command,
    _matching_xml, _passed_methods, _read_regular_file, _save_verification_artifacts,
)

def test_junit_method_evidence_excludes_skipped_and_missing_methods(tmp_path: Path) -> None:
    report = tmp_path / 'domain/build/test-results/testDebugUnitTest/TEST-preservation.xml'
    report.parent.mkdir(parents=True)
    report.write_text(
        '<testsuite><testcase classname="example.CrashlyticsPreservationaaaaaaaaaaaaTest" '
        'name="oldValueIsStable"/><testcase '
        'classname="example.CrashlyticsPreservationaaaaaaaaaaaaTest" name="swipeResetsTicker">'
        '<skipped/></testcase></testsuite>',
        encoding='utf-8',
    )
    assert _passed_methods(
        report, 'example.CrashlyticsPreservationaaaaaaaaaaaaTest', tmp_path,
    ) == ['oldValueIsStable']
IDENTITY = 'a' * 64


def _sandbox(tmp_path: Path) -> InvestigationSandbox:
    target = tmp_path / 'target'
    release = tmp_path / 'release'
    target.mkdir()
    release.mkdir()
    (target / 'gradlew').write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
    return InvestigationSandbox(release=release, target=target, image='test-image')


def _candidate(path: str) -> list[dict[str, str]]:
    from crashlytics_automation.behavior import preservation_test_name
    source_path = 'domain/src/main/kotlin/example/Subject.kt'
    preservation_path = f'domain/src/test/kotlin/example/{preservation_test_name(IDENTITY)}'
    source = 'package example\nclass Subject { fun oldValue() = 1 }\n'
    crash_class = path.rsplit('/', 1)[1].removesuffix('.kt')
    preservation_class = preservation_path.rsplit('/', 1)[1].removesuffix('.kt')
    contents = [
        (path, 'test', f'package example\nclass {crash_class} {{ @org.junit.Test fun regressionReproduced() {{}} }}\n'),
        (preservation_path, 'test',
         f'package example\nclass {preservation_class} {{ @org.junit.Test fun oldValueIsStable() {{}} }}\n'),
        (source_path, 'source', source),
    ]
    return [
        {
            'path': item_path, 'kind': kind, 'content': content,
            'beforeSha256': '1' * 64 if kind == 'source' else None,
            'afterSha256': __import__('hashlib').sha256(content.encode()).hexdigest(),
        }
        for item_path, kind, content in contents
    ]


def _review(files: list[dict[str, str]]) -> dict[str, object]:
    from crashlytics_automation.behavior import source_digest
    source_files = [file for file in files if file['kind'] == 'source']
    preservation = next(file['path'] for file in files if 'CrashlyticsPreservation' in file['path'])
    return {
        'version': 1, 'approved': True, 'reason': 'Preserves source behavior.',
        'unrelatedChanges': [],
        'contracts': [{
            'sourcePath': source_files[0]['path'], 'sourceLine': 1,
            'behavior': 'The existing value remains unchanged.',
            'testPath': preservation, 'testMethod': 'oldValueIsStable',
        }],
        'sourceDigest': source_digest(source_files),
    }


def _verify(sandbox: InvestigationSandbox, files: list[dict[str, str]]) -> dict[str, object]:
    return sandbox.verify_candidate(
        files=files, identity_hash=IDENTITY, behavior_review=_review(files),
    )

def test_verify_candidate_rejects_path_escape(tmp_path: Path) -> None:
    sandbox = _sandbox(tmp_path)
    try:
        result = _verify(
            sandbox, _candidate(f'domain/src/test/../../../../tmp/{regression_test_name(IDENTITY)}'),
        )
    finally:
        sandbox.close()

    assert result['passed'] is False
    assert 'escapes' in result['reason']
    assert result['checks'] == []


def test_compile_error_does_not_count_as_baseline_reproduction(tmp_path: Path) -> None:
    sandbox = _sandbox(tmp_path)
    calls: list[str] = []

    def fake_run(
        workspace: Path, command: str, timeout_seconds: int, **kwargs: object,
    ) -> dict[str, object]:
        calls.append(command)
        if command.endswith(':tasks --all'):
            return {'exit_code': 0, 'stdout': 'testDebugUnitTest - Runs unit tests\n', 'stderr': '', 'timed_out': False}
        return {'exit_code': 1, 'stdout': 'Kotlin compilation failed', 'stderr': '', 'timed_out': False}

    sandbox._new_container = lambda *args: 'fake-container'  # type: ignore[method-assign]
    sandbox._run = fake_run  # type: ignore[method-assign]
    try:
        result = _verify(
            sandbox, _candidate(f'domain/src/test/kotlin/example/{regression_test_name(IDENTITY)}'),
        )
    finally:
        sandbox.close()

    assert result['reason'] == 'baseline did not reproduce the crash regression in JUnit XML or trusted Android OOM logs'
    assert result['retryable'] is False
    assert result['checks'][0]['test_result'] == 'missing-failed-or-skipped'
    assert len(calls) == 2  # task discovery, then failed test execution



@pytest.mark.parametrize('exit_code', [70, 1])
def test_android_setup_marker_requires_setup_exit_status(tmp_path: Path, exit_code: int) -> None:
    sandbox = _sandbox(tmp_path)
    sandbox._new_container = lambda *_args: 'fake-container'  # type: ignore[method-assign]
    sandbox._stop_container = lambda *_args: None  # type: ignore[method-assign]
    calls = []

    def setup_failure(_container: str, command: str, _timeout: int) -> dict[str, object]:
        calls.append(command)
        return {
            'exit_code': exit_code,
            'stdout': '',
            'stderr': 'VERIFICATION_SETUP_FAILURE: emulator readiness timed out',
            'timed_out': False,
        }

    sandbox._run = setup_failure  # type: ignore[method-assign]
    test_path = f'domain/src/androidTest/kotlin/example/{regression_test_name(IDENTITY)}'
    try:
        result = _verify(
            sandbox, _candidate(f'domain/src/androidTest/kotlin/example/{regression_test_name(IDENTITY)}'),
        )
    finally:
        sandbox.close()

    assert result['passed'] is False
    assert result['retryable'] is (exit_code == 70)


def test_host_command_timeout_is_retryable(tmp_path: Path) -> None:
    sandbox = _sandbox(tmp_path)
    sandbox._new_container = lambda *_args: 'fake-container'  # type: ignore[method-assign]
    sandbox._stop_container = lambda *_args: None  # type: ignore[method-assign]

    def timed_out(_container: str, command: str, _timeout: int) -> dict[str, object]:
        if command.endswith(':tasks --all'):
            return {'exit_code': 0, 'stdout': 'testDebugUnitTest - Runs unit tests\n',
                    'stderr': '', 'timed_out': False}
        return {'exit_code': None, 'stdout': '', 'stderr': '', 'timed_out': True}

    sandbox._run = timed_out  # type: ignore[method-assign]
    try:
        result = _verify(
            sandbox, _candidate(f'domain/src/test/kotlin/example/{regression_test_name(IDENTITY)}'),
        )
    finally:
        sandbox.close()

    assert result['passed'] is False
    assert result['retryable'] is True
    assert result['checks'][-1]['test_result'] == 'timeout'


def test_sandbox_keeps_host_checkout_untouched_and_sanitizes_secrets(tmp_path: Path) -> None:
    target = tmp_path / 'target'
    release = tmp_path / 'release'
    target.mkdir()
    release.mkdir()
    (target / 'local.properties').write_text('secret=host-only', encoding='utf-8')
    sandbox = InvestigationSandbox(release=release, target=target, image='test-image')
    try:
        assert sandbox.target != target
        assert (target / 'local.properties').read_text(encoding='utf-8') == 'secret=host-only'
        assert 'host-only' not in (sandbox.target / 'local.properties').read_text(encoding='utf-8')
        assert sandbox.artifact_directory.is_dir()
    finally:
        sandbox.close()


class LocalBuildSandbox(InvestigationSandbox):
    """Run filesystem build fixtures locally, replacing only Docker transport."""

    def _new_container(self, workspace: Path, scratch: Path, home: Path, *, read_only: bool = False) -> str:
        if not hasattr(self, 'runs'):
            self.runs: list[tuple[Path, Path, Path]] = []
            self.containers: dict[str, tuple[Path, Path, Path]] = {}
        self.runs.append((workspace, scratch, home))
        name = f'local-{len(self.runs)}'
        self.containers[name] = (workspace, scratch, home)
        self._owned_containers.append(name)
        return name


    def _stop_container(self, container: str) -> None:
        if container in self._owned_containers:
            self._owned_containers.remove(container)

    def _run(self, container: str, command: str, timeout_seconds: int) -> dict:
        workspace, scratch, home = self.containers[container]
        environment = {**os.environ, 'HOME': str(home), 'TEST_SCRATCH': str(scratch)}
        completed = subprocess.run(shlex.split(command), cwd=workspace, env=environment,
                                   capture_output=True, text=True, timeout=timeout_seconds, check=False)
        return {'exit_code': completed.returncode, 'stdout': completed.stdout,
                'stderr': completed.stderr, 'timed_out': False}


_BUILD_FIXTURE = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys

if sys.argv[-1] == '--all':
    print('testDebugUnitTest - Runs unit tests')
    sys.exit(0)
workspace = Path.cwd()
tests = sorted(workspace.glob('domain/src/test/kotlin/example/*.kt'))
report_dir = workspace / 'domain/build/test-results/testDebugUnitTest'
report_dir.mkdir(parents=True, exist_ok=True)
source = workspace / 'domain/src/main/kotlin/example/Subject.kt'
candidate = source.read_text() == 'fixed'
has_failure = False
for test in tests:
    classname = 'example.' + test.stem
    preservation = 'Preservation' in test.stem
    method = 'oldValueIsStable' if preservation else 'regressionReproduced'
    passed = preservation or candidate
    if not passed:
        has_failure = True
    failure = '' if passed else '<failure message="reproduced"/>'
    (report_dir / ('TEST-' + test.stem + '.xml')).write_text(
        '<testsuite><testcase classname="' + classname + '" name="' + method + '">' + failure +
        '</testcase></testsuite>'
    )
    if candidate:
        assert test.stem in test.read_text()
        assert not (Path.home() / '.gradle/init.d/poison.gradle').exists()
if not candidate and any('Preservation' not in test.stem for test in tests):
    # A baseline crash test may mutate every writable location in its own workspace.
    poison = '#!/usr/bin/env python3\nfrom pathlib import Path\np=Path(' + repr(str(report_dir)) + ')\np.mkdir(parents=True,exist_ok=True)\n'
    (workspace / 'gradlew').write_text(poison)
    init = Path.home() / '.gradle/init.d/poison.gradle'
    init.parent.mkdir(parents=True, exist_ok=True)
    init.write_text('poisoned build initialization')
    scratch = Path(os.environ['TEST_SCRATCH'])
    (scratch / 'baseline-0').mkdir()
    (scratch / 'baseline-0/stdout.txt').symlink_to(os.environ['TEST_SENTINEL'])
print('trusted candidate fixture' if candidate else 'trusted baseline fixture')
sys.exit(1 if has_failure else 0)
'''


@pytest.mark.parametrize('fix, expected_passed', [('fixed', True), ('still-broken', False)])
def test_candidate_uses_fresh_build_tools_tests_and_home(tmp_path: Path, monkeypatch, fix: str, expected_passed: bool) -> None:
    target = tmp_path / 'target'
    release = tmp_path / 'release'
    target.mkdir()
    release.mkdir()
    wrapper = target / 'gradlew'
    wrapper.write_text(_BUILD_FIXTURE)
    wrapper.chmod(0o700)
    source = target / 'domain/src/main/kotlin/example/Subject.kt'
    source.parent.mkdir(parents=True)
    source.write_text('original')
    sentinel = tmp_path / 'host-sentinel'
    sentinel.write_text('host data')
    monkeypatch.setenv('TEST_SENTINEL', str(sentinel))
    test_name = regression_test_name(IDENTITY)
    crash_path = f'domain/src/test/kotlin/example/{test_name}'
    files = _candidate(crash_path)
    source_entry = next(file for file in files if file['kind'] == 'source')
    source_entry['content'] = fix
    source_entry['afterSha256'] = __import__('hashlib').sha256(fix.encode()).hexdigest()
    with LocalBuildSandbox(release=release, target=target, image='local-fixture') as sandbox:
        result = sandbox.verify_candidate(
            files=files, identity_hash=IDENTITY, behavior_review=_review(files),
        )
        assert result['passed'] is expected_passed
        expected_checks = [
            ('baseline', 'crash'), ('baseline', 'preservation'), ('candidate', 'crash'),
        ]
        if expected_passed:
            expected_checks.append(('candidate', 'preservation'))
        assert [(check['phase'], check['purpose']) for check in result['checks']] == expected_checks
        baseline_crash, baseline_preservation, candidate = sandbox.runs
        assert baseline_crash[0] != baseline_preservation[0] != candidate[0]
        assert baseline_crash[1] != candidate[1]
        assert baseline_crash[2] != candidate[2]
        if expected_passed:
            assert (candidate[0] / 'gradlew').read_text() == _BUILD_FIXTURE
        assert sandbox._owned_containers == []
        assert sentinel.read_text() == 'host data'
        destination = tmp_path / 'export'
        exported = sandbox.export_artifacts(destination)
        assert any(path.endswith('baseline-crash-scratch/baseline-0/stdout.txt')
                   for path in exported['skipped_non_regular'])
        records = list(destination.glob('*/baseline-crash-0/stdout.txt'))
        assert len(records) == 1
        assert records[0].read_text() == 'trusted baseline fixture\n'
        candidate_records = sorted(destination.glob('*/candidate-*/stdout.txt'))
        assert {path.parent.name for path in candidate_records} == (
            {'candidate-0', 'candidate-1'} if expected_passed else {'candidate-0'}
        )
        before_xml = ET.parse(records[0].parent / 'junit.xml')
        after_xml = ET.parse(candidate_records[0].parent / 'junit.xml')
        assert before_xml.find('.//testcase/failure') is not None
        assert (after_xml.find('.//testcase/failure') is None) is expected_passed
    assert sentinel.read_text() == 'host data'
    assert wrapper.read_text() == _BUILD_FIXTURE
    assert source.read_text() == 'original'


def test_host_diagnostics_are_not_mounted_and_export_rejects_symlinks(tmp_path: Path) -> None:
    with _sandbox(tmp_path) as sandbox:
        sentinel = tmp_path / 'host-sentinel'
        sentinel.write_text('host data')
        run_id = 'test-run'
        workspace, scratch, home = sandbox._verification_workspace(run_id, 'baseline', [], [])
        hostile = scratch / 'baseline-0'
        hostile.mkdir()
        (hostile / 'stdout.txt').symlink_to(sentinel)
        (scratch / 'host-directory').symlink_to(tmp_path, target_is_directory=True)
        trusted = sandbox.artifact_directory / run_id
        trusted.mkdir()
        result = {'stdout': 'captured stdout', 'stderr': 'captured stderr'}
        _save_verification_artifacts(trusted, 'baseline-0', result, None, workspace)
        args = sandbox._docker_args(workspace, scratch, home, 'unused')
        assert all(str(sandbox.artifact_directory) not in arg for arg in args)
        destination = tmp_path / 'export'
        exported = sandbox.export_artifacts(destination)
        assert sentinel.read_text() == 'host data'
        assert (destination / run_id / 'baseline-0/stdout.txt').read_text() == 'captured stdout'
        assert len(exported['skipped_non_regular']) == 2
        assert not (destination / run_id / 'baseline-scratch/host-directory').exists()


def test_junit_and_diagnostics_do_not_read_host_symlinks(tmp_path: Path) -> None:
    with _sandbox(tmp_path) as sandbox:
        host_xml = tmp_path / 'secret.xml'
        host_xml.write_text('<testsuite><testcase classname="example.Test"><failure/></testcase></testsuite>')
        workspace = sandbox.target
        report_dir = workspace / 'domain/build/test-results/testDebugUnitTest'
        report_dir.mkdir(parents=True)
        report = report_dir / 'TEST-host.xml'
        report.symlink_to(host_xml)
        assert _matching_xml(workspace, Path('domain'), 'test', ':domain:testDebugUnitTest', 'example.Test') is None
        assert _read_regular_file(workspace, report, 1024) is None
        report.unlink()
        report_dir.rmdir()
        report_dir.symlink_to(host_xml.parent, target_is_directory=True)
        assert _read_regular_file(workspace, report_dir / host_xml.name, 1024) is None


def test_wrapper_timeout_kills_sigterm_ignoring_descendant(tmp_path: Path) -> None:
    pid_file = tmp_path / 'child.pid'
    child = ('import os, signal, time; from pathlib import Path; '
             'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
             f'Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(300)')
    command = f'{shlex.quote(sys.executable)} -c {shlex.quote(child)}'
    result = subprocess.run([sys.executable, '-c', _COMMAND_WRAPPER, command, '1'],
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == 124
    pid = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    while Path(f'/proc/{pid}/stat').exists() and time.monotonic() < deadline:
        if Path(f'/proc/{pid}/stat').read_text().split()[2] == 'Z':
            break
        time.sleep(0.05)
    if Path(f'/proc/{pid}/stat').exists():
        assert Path(f'/proc/{pid}/stat').read_text().split()[2] == 'Z'


@pytest.mark.parametrize('outer_timeout', [False, True])
def test_run_removes_entire_container_on_inner_or_outer_timeout(tmp_path: Path, monkeypatch, outer_timeout: bool) -> None:
    import crashlytics_automation.sandbox as sandbox_module

    real_popen = subprocess.Popen
    removed: list[str] = []
    processes: list[subprocess.Popen] = []

    class ExecTransport:
        def __init__(self, process: subprocess.Popen) -> None:
            self.process = process
            self.first_wait = True

        @property
        def pid(self) -> int:
            return self.process.pid

        @property
        def returncode(self) -> int | None:
            return self.process.returncode

        def wait(self, timeout=None):
            if outer_timeout and self.first_wait:
                self.first_wait = False
                return self.process.wait(timeout=0.1)
            return self.process.wait(timeout=timeout)

    def docker_exec(args, **kwargs):
        assert args[:3] == ['docker', 'exec', '--workdir']
        wrapper = 'import time; time.sleep(300)' if outer_timeout else _COMMAND_WRAPPER
        process = real_popen([sys.executable, '-c', wrapper, 'sleep 300', '1'], **kwargs)
        processes.append(process)
        return ExecTransport(process)

    def docker_rm(args, **kwargs):
        assert args[:3] == ['docker', 'rm', '--force']
        removed.append(args[3])
        return subprocess.CompletedProcess(args, 0, stderr=b'')

    with _sandbox(tmp_path) as sandbox:
        container = 'timeout-container'
        sandbox._owned_containers.append(container)
        sandbox._model_container = container
        monkeypatch.setattr(sandbox_module.subprocess, 'Popen', docker_exec)
        monkeypatch.setattr(sandbox_module.subprocess, 'run', docker_rm)
        try:
            result = sandbox._run(container, 'sleep 300', 1)
            assert result['timed_out'] is True
            assert result['exit_code'] is None if outer_timeout else result['exit_code'] == 124
            assert removed == [container]
            assert sandbox._owned_containers == []
            assert sandbox._model_container is None
            assert processes[0].poll() is not None
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def _fake_executable(path: Path, body: str) -> None:
    path.write_text(f'#!/bin/sh\n{body}\n')
    path.chmod(0o700)


def _run_instrumentation_fixture(tmp_path: Path, monkeypatch, gradle: str, adb: str) -> tuple[subprocess.CompletedProcess, Path]:
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    home = tmp_path / 'home'
    home.mkdir()
    scratch = tmp_path / 'scratch'
    scratch.mkdir()
    _fake_executable(bin_dir / 'avdmanager', 'mkdir -p "$HOME/.android/avd/crashlytics-verification.avd"; echo fixture > "$HOME/.android/avd/crashlytics-verification.avd/config.ini"')
    _fake_executable(bin_dir / 'emulator', 'exec sleep 20')
    _fake_executable(bin_dir / 'adb', adb)
    _fake_executable(bin_dir / 'timeout', 'shift; exec "$@"')
    _fake_executable(bin_dir / 'seq', 'echo 1')
    wrapper = tmp_path / 'gradlew'
    _fake_executable(wrapper, gradle)
    monkeypatch.setenv('PATH', f'{bin_dir}:{os.environ["PATH"]}')
    monkeypatch.setenv('HOME', str(home))
    command = _instrumentation_command(':domain:connectedDebugAndroidTest', 'example.GeneratedTest', 'run.logcat')
    command = command.replace('/workspace/scratch', str(scratch))
    completed = subprocess.run(['/bin/sh', '-c', command], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    return completed, scratch


def test_instrumentation_build_failure_precedes_emulator_start(tmp_path: Path, monkeypatch) -> None:
    completed, scratch = _run_instrumentation_fixture(
        tmp_path, monkeypatch,
        'echo "$*" >> "$HOME/gradle.log"; exit 1',
        'exit 1',
    )
    assert completed.returncode == 1
    assert 'assembleDebug' in (tmp_path / 'home/gradle.log').read_text()
    assert not (scratch / 'emulator.log').exists()


def test_instrumentation_unready_emulator_is_bounded_setup_failure(tmp_path: Path, monkeypatch) -> None:
    completed, scratch = _run_instrumentation_fixture(
        tmp_path, monkeypatch,
        'echo "$*" >> "$HOME/gradle.log"; exit 0',
        'if [ "$1" = get-state ]; then echo offline; exit 1; fi; exit 1',
    )
    assert completed.returncode == 70
    assert 'VERIFICATION_SETUP_FAILURE: emulator readiness timed out' in completed.stderr
    assert 'assembleDebugAndroidTest' in (tmp_path / 'home/gradle.log').read_text()
    assert (scratch / 'emulator.log').exists()


def test_instrumentation_disconnection_does_not_hang_logcat_collection(tmp_path: Path, monkeypatch) -> None:
    adb = '''case "$1" in
get-state) count=0; [ -f "$HOME/adb-count" ] && count=$(cat "$HOME/adb-count"); count=$((count + 1)); echo "$count" > "$HOME/adb-count"; [ "$count" -eq 1 ] && echo device || echo offline ;;
shell) echo 1 ;;
logcat) exit 0 ;;
esac'''
    completed, scratch = _run_instrumentation_fixture(
        tmp_path, monkeypatch,
        'case "$*" in *assembleDebug*) exit 0 ;; *) exit 0 ;; esac',
        adb,
    )
    assert completed.returncode == 70
    assert 'VERIFICATION_SETUP_FAILURE: emulator disconnected during instrumentation' in completed.stderr
    assert (scratch / 'logcat.status').read_text() == 'emulator disconnected; logcat unavailable\n'
