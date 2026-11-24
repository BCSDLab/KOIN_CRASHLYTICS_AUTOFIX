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
    InvestigationSandbox, _COMMAND_WRAPPER, _matching_xml,
    _read_regular_file, _save_verification_artifacts,
)

IDENTITY = 'a' * 64


def _sandbox(tmp_path: Path) -> InvestigationSandbox:
    target = tmp_path / 'target'
    release = tmp_path / 'release'
    target.mkdir()
    release.mkdir()
    (target / 'gradlew').write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
    return InvestigationSandbox(release=release, target=target, image='test-image')


def _candidate(path: str) -> list[dict[str, str]]:
    return [{'path': path, 'kind': 'test', 'content': 'class Test'},
            {'path': 'domain/src/main/kotlin/example/Subject.kt', 'kind': 'source', 'content': 'class Subject'}]


def test_verify_candidate_rejects_path_escape(tmp_path: Path) -> None:
    sandbox = _sandbox(tmp_path)
    try:
        result = sandbox.verify_candidate(
            files=_candidate(f'domain/src/test/../../../../tmp/{regression_test_name(IDENTITY)}'),
            identity_hash=IDENTITY,
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
        result = sandbox.verify_candidate(
            files=_candidate(f'domain/src/test/kotlin/example/{regression_test_name(IDENTITY)}'),
            identity_hash=IDENTITY,
        )
    finally:
        sandbox.close()

    assert result['passed'] is False
    assert result['reason'] == 'baseline did not reproduce the regression in JUnit XML or trusted Android OOM logs'
    assert result['checks'][0]['test_result'] == 'missing-or-not-failing'
    assert len(calls) == 2  # task discovery, then failed test execution


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

    def _new_container(self, workspace: Path, scratch: Path, home: Path) -> str:
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
test = next(workspace.glob('domain/src/test/kotlin/example/*.kt'))
classname = 'example.' + test.stem
report = workspace / 'domain/build/test-results/testDebugUnitTest/TEST-regression.xml'
report.parent.mkdir(parents=True, exist_ok=True)
passed = '<testsuite><testcase classname="' + classname + '" name="regression"/></testsuite>'
failed = '<testsuite><testcase classname="' + classname + '" name="regression"><failure message="reproduced"/></testcase></testsuite>'
source = workspace / 'domain/src/main/kotlin/example/Subject.kt'
if source.read_text() == 'fixed':
    assert test.read_text() == 'package example\nclass ' + test.stem
    assert not (Path.home() / '.gradle/init.d/poison.gradle').exists()
    report.write_text(passed)
    print('trusted candidate fixture')
    sys.exit(0)
report.write_text(failed)
# A baseline test can mutate every one of these container-writable locations.
poison = '#!/usr/bin/env python3\nfrom pathlib import Path\np=Path(' + repr(str(report)) + ')\np.parent.mkdir(parents=True,exist_ok=True)\np.write_text(' + repr(passed) + ')\n'
(workspace / 'gradlew').write_text(poison)
test.write_text('poisoned test')
init = Path.home() / '.gradle/init.d/poison.gradle'
init.parent.mkdir(parents=True, exist_ok=True)
init.write_text('poisoned build initialization')
scratch = Path(os.environ['TEST_SCRATCH'])
(scratch / 'baseline-0').mkdir()
(scratch / 'baseline-0/stdout.txt').symlink_to(os.environ['TEST_SENTINEL'])
print('trusted baseline fixture')
sys.exit(1)
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
    files = [
        {'path': f'domain/src/test/kotlin/example/{test_name}',
         'content': f'package example\nclass {Path(test_name).stem}'},
        {'path': 'domain/src/main/kotlin/example/Subject.kt', 'content': fix},
    ]
    with LocalBuildSandbox(release=release, target=target, image='local-fixture') as sandbox:
        result = sandbox.verify_candidate(files=files, identity_hash=IDENTITY)
        assert result['passed'] is expected_passed
        assert [check['phase'] for check in result['checks']] == ['baseline', 'candidate']
        baseline, candidate = sandbox.runs
        assert baseline[0] != candidate[0]
        assert baseline[1] != candidate[1]
        assert baseline[2] != candidate[2]
        if expected_passed:
            assert (candidate[0] / 'gradlew').read_text() == _BUILD_FIXTURE
        assert sandbox._owned_containers == []
        assert sentinel.read_text() == 'host data'
        destination = tmp_path / 'export'
        exported = sandbox.export_artifacts(destination)
        assert any(path.endswith('baseline-scratch/baseline-0/stdout.txt')
                   for path in exported['skipped_non_regular'])
        records = list(destination.glob('*/baseline-0/stdout.txt'))
        assert len(records) == 1
        assert records[0].read_text() == 'trusted baseline fixture\n'
        candidate_records = list(destination.glob('*/candidate-0/stdout.txt'))
        assert len(candidate_records) == 1
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
