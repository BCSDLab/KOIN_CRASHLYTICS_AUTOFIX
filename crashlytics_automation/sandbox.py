"""Isolated execution and trusted before/after verification for investigations."""

from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import uuid
import shutil
import stat
import signal
import subprocess
import time
import tempfile
import xml.etree.ElementTree as ET
from typing import Any

from .candidate import regression_test_name

_MAX_COMMAND_SECONDS = 900
_MAX_OUTPUT_BYTES = 64 * 1024
_COMMAND_WRAPPER = r'''import os, selectors, signal, subprocess, sys, time
command = sys.argv[1]
timeout = int(sys.argv[2])
captured = [bytearray(), bytearray()]
os.makedirs(os.environ.get('HOME', '/tmp/home'), exist_ok=True)
child = subprocess.Popen(command, shell=True, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
selector = selectors.DefaultSelector()
selector.register(child.stdout, selectors.EVENT_READ, captured[0])
selector.register(child.stderr, selectors.EVENT_READ, captured[1])
deadline = time.monotonic() + timeout
result = None
while selector.get_map() or child.poll() is None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        result = 124
        break
    for key, _ in selector.select(min(remaining, 0.1)):
        chunk = os.read(key.fileobj.fileno(), 8192)
        if not chunk:
            selector.unregister(key.fileobj)
        elif len(key.data) < 65536:
            key.data.extend(chunk[:65536-len(key.data)])
selector.close()
if result is None:
    result = child.wait()
sys.stdout.buffer.write(captured[0])
sys.stderr.buffer.write(captured[1])
sys.exit(result if result >= 0 else 128 - result)
'''


class InvestigationSandbox:
    """Run untrusted commands in disposable Docker containers."""

    def __init__(
        self, *, release: pathlib.Path, target: pathlib.Path, image: str,
        android_sdk: pathlib.Path | None = None,
    ) -> None:
        release_source = pathlib.Path(release).resolve(strict=True)
        target_source = pathlib.Path(target).resolve(strict=True)
        if not release_source.is_dir() or not target_source.is_dir():
            raise ValueError('release and target must be directories')
        if not isinstance(image, str) or not image.strip() or image.startswith('-'):
            raise ValueError('invalid Docker image')
        self.image = image
        self.android_sdk = pathlib.Path(android_sdk).resolve(strict=True) if android_sdk is not None else None
        if self.android_sdk is not None and not self.android_sdk.is_dir():
            raise ValueError('android_sdk must be a directory')
        self._temp = tempfile.TemporaryDirectory(prefix='crashlytics-investigation-')
        self._root = pathlib.Path(self._temp.name)
        self._snapshot = self._root / 'snapshot'
        self.target = self._root / 'target'
        self._model_workspace = self.target
        self._release_view = self._root / 'release'
        self._artifacts = self._root / 'artifacts'
        self._model_home = self._root / 'model-home'
        self._scratch = self._root / 'scratch'
        self._owned_containers: list[str] = []
        self._model_container: str | None = None
        ignored = shutil.ignore_patterns('.git', '.gradle', 'build', '.idea', 'local.properties',
                                         'google-services.json', 'google-credentials.json', '*.jks')
        shutil.copytree(target_source, self._snapshot, symlinks=True, ignore=ignored)
        shutil.copytree(self._snapshot, self.target, symlinks=True)
        shutil.copytree(release_source, self._release_view, symlinks=True, ignore=ignored)
        self._artifacts.mkdir()
        self._model_home.mkdir()
        self._scratch.mkdir()
        self._artifact_sources = [(self._artifacts, pathlib.PurePosixPath()),
                                  (self._scratch, pathlib.PurePosixPath('investigation'))]
        self._closed = False
        self._prepare_build_config(self._model_workspace)

    @staticmethod
    def _prepare_build_config(workspace: pathlib.Path) -> None:
        # The public KOIN build reads these local.properties entries; dummy values
        # suffice for compile/test tasks and avoid transferring signing/API secrets.
        (workspace / 'local.properties').write_text(
            'sdk.dir=/opt/android-sdk\nnavermap_key=crashlytics-test-key\n'
            'koin_store_password=crashlytics-test-password\nkakao_native_app_key=crashlytics-test-key\n',
            encoding='utf-8')
        app = workspace / 'koin'
        if app.is_dir():
            common = {
                'project_info': {
                    'project_number': '123456789000',
                    'project_id': 'crashlytics-test',
                    'storage_bucket': 'crashlytics-test.invalid',
                },
                'configuration_version': '1',
            }

            def firebase_config(packages: tuple[str, ...]) -> str:
                clients = []
                for index, package in enumerate(packages):
                    clients.append({
                        'client_info': {
                            'mobilesdk_app_id': f'1:123456789000:android:{index:016x}',
                            'android_client_info': {'package_name': package},
                        },
                        'api_key': [{'current_key': 'crashlytics-test-key'}],
                    })
                return json.dumps({**common, 'client': clients}, separators=(',', ':')) + '\n'

            (app / 'google-services.json').write_text(
                firebase_config(('in.koreatech.koin', 'in.koreatech.koin.dev')), encoding='utf-8')
            debug_config = app / 'src' / 'debug' / 'google-services.json'
            debug_config.parent.mkdir(parents=True, exist_ok=True)
            debug_config.write_text(firebase_config(('in.koreatech.koin.dev',)), encoding='utf-8')

    def __enter__(self) -> 'InvestigationSandbox':
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _stop_container(self, container: str) -> None:
        if container not in self._owned_containers:
            return
        try:
            result = subprocess.run(
                ['docker', 'rm', '--force', container],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f'could not stop owned investigation container: {type(exc).__name__}') from None
        if result.returncode != 0:
            detail = result.stderr.decode('utf-8', errors='replace')[-300:]
            raise RuntimeError(f'could not stop owned investigation container: {detail}')
        self._owned_containers.remove(container)
        if container == self._model_container:
            self._model_container = None

    def _stop_owned_containers(self) -> None:
        while self._owned_containers:
            self._stop_container(self._owned_containers[-1])

    def close(self) -> None:
        if self._closed:
            return
        self._stop_owned_containers()
        self._temp.cleanup()
        self._closed = True

    def export_artifacts(self, destination: pathlib.Path) -> dict[str, Any]:
        """Stop owned containers, then safely copy bounded regular diagnostics."""
        self._stop_owned_containers()
        destination = pathlib.Path(destination)
        if destination.is_symlink():
            raise ValueError('artifact destination may not be a symlink')
        destination = destination.resolve()
        if destination.is_relative_to(self._root):
            raise ValueError('artifact destination must be outside the sandbox')
        destination.mkdir(parents=True, exist_ok=True)
        max_total = 100 * 1024 * 1024
        total = 0
        copied = 0
        skipped_oversized: list[str] = []
        skipped_non_regular: list[str] = []
        omitted = 0

        def record(bucket: list[str], value: str) -> None:
            nonlocal omitted
            if len(bucket) < 1000:
                bucket.append(value)
            else:
                omitted += 1

        for artifact_root, prefix in self._artifact_sources:
            for parent, directories, filenames in os.walk(artifact_root, topdown=True, followlinks=False):
                parent_path = pathlib.Path(parent)
                safe_directories = []
                for name in directories:
                    child = parent_path / name
                    if child.is_symlink():
                        record(skipped_non_regular, (prefix / child.relative_to(artifact_root)).as_posix())
                    else:
                        safe_directories.append(name)
                directories[:] = safe_directories
                for name in filenames:
                    source = parent_path / name
                    relative = prefix / source.relative_to(artifact_root)
                    try:
                        info = source.lstat()
                    except OSError:
                        record(skipped_non_regular, relative.as_posix())
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        record(skipped_non_regular, relative.as_posix())
                        continue
                    if info.st_size > max_total or total + info.st_size > max_total:
                        record(skipped_oversized, relative.as_posix())
                        continue
                    try:
                        source_fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                        with os.fdopen(source_fd, 'rb') as input_stream:
                            opened = os.fstat(input_stream.fileno())
                            if not stat.S_ISREG(opened.st_mode):
                                record(skipped_non_regular, relative.as_posix())
                                continue
                            target = destination / relative
                            target.parent.mkdir(parents=True, exist_ok=True)
                            if not target.parent.resolve().is_relative_to(destination):
                                record(skipped_non_regular, relative.as_posix())
                                continue
                            target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                                getattr(os, 'O_NOFOLLOW', 0), 0o600)
                            with os.fdopen(target_fd, 'wb') as output_stream:
                                shutil.copyfileobj(input_stream, output_stream)
                            total += opened.st_size
                            copied += 1
                    except OSError:
                        record(skipped_non_regular, relative.as_posix())
        return {'destination': str(destination), 'copied_files': copied, 'bytes': total,
                'skipped_oversized': skipped_oversized, 'skipped_non_regular': skipped_non_regular,
                'omitted_entries': omitted}

    @property
    def artifact_directory(self) -> pathlib.Path:
        """Host-only verification records; export_artifacts also includes sandbox scratch logs."""
        return self._artifacts

    def _docker_args(
        self, workspace: pathlib.Path, scratch: pathlib.Path, home: pathlib.Path, name: str,
    ) -> list[str]:
        args = [
            'docker', 'run', '--detach', '--init', '--name', name,
            '--network', 'bridge', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--pids-limit=1024', '--memory=8g', '--memory-swap=8g', '--cpus=4', '--shm-size=2g',
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--workdir', '/workspace/target',
            '-v', f'{workspace}:/workspace/target:rw',
            '-v', f'{self._release_view}:/workspace/release:ro',
            '-v', f'{scratch}:/workspace/scratch:rw',
            '-v', f'{home}:/home:rw',
        ]
        if self.android_sdk is not None:
            args.extend(['-v', f'{self.android_sdk}:/opt/android-sdk:ro'])
        if os.path.exists('/dev/kvm') and os.access('/dev/kvm', os.R_OK | os.W_OK):
            args.extend(['--device', '/dev/kvm:/dev/kvm'])
        args.extend([
            '-e', 'HOME=/home', '-e', 'JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64',
            '-e', 'JAVA_TOOL_OPTIONS=-Duser.home=/home', '-e', 'GRADLE_USER_HOME=/home/.gradle',
            '-e', 'ANDROID_HOME=/opt/android-sdk', '-e', 'ANDROID_SDK_ROOT=/opt/android-sdk',
            '-e', 'ANDROID_AVD_HOME=/home/.android/avd',
            '-e', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/emulator:/opt/android-sdk/cmdline-tools/latest/bin',
            self.image, 'sleep', 'infinity',
        ])
        return args

    def _new_container(
        self, workspace: pathlib.Path, scratch: pathlib.Path, home: pathlib.Path,
    ) -> str:
        name = f'crashlytics-investigation-{uuid.uuid4().hex}'
        self._owned_containers.append(name)
        try:
            result = subprocess.run(
                self._docker_args(workspace, scratch, home, name),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self._owned_containers.remove(name)
            raise RuntimeError(f'could not start investigation container: {type(exc).__name__}') from None
        if result.returncode != 0:
            self._owned_containers.remove(name)
            detail = result.stderr.decode('utf-8', errors='replace')[-500:]
            raise RuntimeError(f'could not start investigation container: {detail}')
        return name

    def _run(self, container: str, command: str, timeout_seconds: int) -> dict[str, Any]:
        if self._closed:
            raise RuntimeError('sandbox is closed')
        if not isinstance(command, str) or not command.strip():
            raise ValueError('command must be a non-empty string')
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise ValueError('timeout_seconds must be a positive integer')
        timeout = min(timeout_seconds, _MAX_COMMAND_SECONDS)
        args = ['docker', 'exec', '--workdir', '/workspace/target', container,
                'python3', '-c', _COMMAND_WRAPPER, command, str(timeout)]
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=True, close_fds=True)
            timed_out = False
            try:
                process.wait(timeout=timeout + 45)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    # Killing docker exec alone does not stop the process in Docker.
                    self._stop_container(container)
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait(timeout=5)
                    except (ProcessLookupError, subprocess.TimeoutExpired):
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
            if process.returncode == 124:
                # Includes descendants that escaped the wrapper's process group.
                self._stop_container(container)
            stdout = _read_tail(out, _MAX_OUTPUT_BYTES)
            stderr = _read_tail(err, _MAX_OUTPUT_BYTES)
        code = process.returncode
        return {'exit_code': None if timed_out else code, 'stdout': stdout, 'stderr': stderr,
                'timed_out': timed_out or (code == 124)}

    def execute(self, *, command: str, timeout_seconds: int) -> dict[str, Any]:
        """Execute commands in the persistent, isolated writable model workspace."""
        if self._model_container is None:
            self._model_container = self._new_container(
                self._model_workspace, self._scratch, self._model_home)
        return self._run(self._model_container, command, timeout_seconds)

    def verify_candidate(self, *, files: list[dict[str, Any]], identity_hash: str) -> dict[str, Any]:
        """Reproduce every proposed regression against clean base, then verify fixes."""
        checks: list[dict[str, Any]] = []
        deadline = time.monotonic() + 900
        verifier: str | None = None
        try:
            test_name = regression_test_name(identity_hash)
            tests: list[dict[str, Any]] = []
            sources: list[tuple[pathlib.PurePosixPath, str]] = []
            for item in files:
                if not isinstance(item, dict) or not isinstance(item.get('path'), str) or not isinstance(item.get('content'), str):
                    raise ValueError('candidate file entry is malformed')
                rel = pathlib.PurePosixPath(item['path'])
                if rel.is_absolute() or not rel.parts or any(part in ('..', '.') for part in rel.parts) or '\\' in item['path']:
                    raise ValueError('candidate path escapes verification workspace')
                if rel.parts[-1] == test_name and 'src' in rel.parts:
                    source_index = rel.parts.index('src')
                    if (source_index + 2 >= len(rel.parts) or
                            rel.parts[source_index + 1] not in ('test', 'androidTest') or
                            rel.parts[source_index + 2] not in ('java', 'kotlin') or
                            pathlib.PurePosixPath(rel.parts[-1]).suffix != '.kt'):
                        raise ValueError('regression test must be a Kotlin file under src/test or src/androidTest')
                    module = pathlib.PurePosixPath(*rel.parts[:source_index])
                    if not module.parts:
                        raise ValueError('regression test must belong to a module')
                    tests.append({
                        'path': rel, 'content': item['content'],
                        'kind': rel.parts[source_index + 1], 'module': module,
                        'class': _test_class_name(rel, item['content']),
                    })
                elif rel.parts[-1].endswith(('.kt', '.java')) and 'src' in rel.parts:
                    source_index = rel.parts.index('src')
                    if (source_index + 2 >= len(rel.parts) or
                            rel.parts[source_index + 1] != 'main' or
                            rel.parts[source_index + 2] not in ('java', 'kotlin')):
                        raise ValueError('source fix must be under src/main/java or src/main/kotlin')
                    sources.append((rel, item['content']))
                else:
                    raise ValueError(f"unsupported verification file: {item['path']}")
            if not tests:
                raise ValueError('candidate must contain at least one generated regression test')

            run_id = uuid.uuid4().hex
            run_artifacts = self._artifacts / run_id
            run_artifacts.mkdir()
            workspace, scratch, verify_home = self._verification_workspace(run_id, 'baseline', tests, [])
            verifier = self._new_container(workspace, scratch, verify_home)

            unit_tests: dict[pathlib.PurePosixPath, list[dict[str, Any]]] = {}
            for test in tests:
                if test['kind'] == 'test':
                    unit_tests.setdefault(test['module'], []).append(test)
            unit_tasks: dict[pathlib.PurePosixPath, str] = {}
            for module in unit_tests:
                remaining = _remaining_timeout(deadline, 300)
                if not remaining:
                    return {'passed': False, 'reason': 'verification time budget exhausted during task discovery', 'checks': checks}
                module_task = ':'.join(module.parts)
                listing = self._run(verifier, f'./gradlew --no-daemon :{module_task}:tasks --all', remaining)
                task = _unit_test_task(listing['stdout'], module_task)
                if task is None or listing['exit_code'] != 0 or listing['timed_out']:
                    checks.append({'phase': 'task-discovery', 'module': module.as_posix(),
                                   'exit_code': listing['exit_code'], 'timed_out': listing['timed_out']})
                    return {'passed': False, 'reason': 'trusted base build exposes no usable unit-test task', 'checks': checks}
                unit_tasks[module] = task

            baseline_unit: dict[pathlib.PurePosixPath, dict[str, Any]] = {}
            for index, test in enumerate(tests):
                module = test['module']
                instrumented = test['kind'] == 'androidTest'
                if not instrumented and module in baseline_unit:
                    baseline = baseline_unit[module]
                else:
                    remaining = _remaining_timeout(deadline, 900)
                    if not remaining:
                        return {'passed': False, 'reason': 'verification time budget exhausted before baseline', 'checks': checks}
                    if instrumented:
                        module_task = ':'.join(module.parts)
                        task = f':{module_task}:connectedDebugAndroidTest'
                        log_name = f'baseline-{index}.logcat.txt'
                        command = _instrumentation_command(task, test['class'], log_name)
                    else:
                        task = unit_tasks[module]
                        log_name = ''
                        command = f'./gradlew --no-daemon --stacktrace {task}'
                    if verifier is None:
                        verifier = self._new_container(workspace, scratch, verify_home)
                    baseline = self._run(verifier, command, remaining)
                    self._stop_container(verifier)
                    verifier = None
                    if not instrumented:
                        baseline_unit[module] = baseline
                task = (':'.join(module.parts) + ':connectedDebugAndroidTest'
                        if instrumented else unit_tasks[module])
                xml_path = _matching_xml(workspace, module, test['kind'], task, test['class'])
                _save_verification_artifacts(run_artifacts, f'baseline-{index}', baseline, xml_path, workspace)
                xml_failure = xml_path is not None and _has_failure(xml_path, test['class'], workspace)
                oom = _fatal_oom_proof(
                    workspace, module, test['class'], scratch / f'baseline-{index}.logcat.txt',
                    baseline['stdout'] + '\n' + baseline['stderr'],
                ) if instrumented and not baseline['timed_out'] else None
                reproduced = baseline['exit_code'] != 0 and not baseline['timed_out'] and (xml_failure or oom is not None)
                checks.append({
                    'phase': 'baseline', 'path': test['path'].as_posix(),
                    'exit_code': baseline['exit_code'], 'timed_out': baseline['timed_out'],
                    'test_result': 'failed' if xml_failure else 'fatal-oom' if oom else 'missing-or-not-failing',
                    'evidence': oom if oom else {'source': 'junit-xml'} if xml_failure else None,
                })
                if not reproduced:
                    return {'passed': False,
                            'reason': 'baseline did not reproduce the regression in JUnit XML or trusted Android OOM logs',
                            'checks': checks}

            workspace, scratch, verify_home = self._verification_workspace(run_id, 'candidate', tests, sources)

            candidate_unit: dict[pathlib.PurePosixPath, dict[str, Any]] = {}
            all_passed = True
            for index, test in enumerate(tests):
                module = test['module']
                instrumented = test['kind'] == 'androidTest'
                if not instrumented and module in candidate_unit:
                    after = candidate_unit[module]
                else:
                    remaining = _remaining_timeout(deadline, 900)
                    if not remaining:
                        return {'passed': False, 'reason': 'verification time budget exhausted before candidate run', 'checks': checks}
                    if instrumented:
                        module_task = ':'.join(module.parts)
                        task = f':{module_task}:connectedDebugAndroidTest'
                        log_name = f'candidate-{index}.logcat.txt'
                        command = _instrumentation_command(task, test['class'], log_name)
                    else:
                        task = unit_tasks[module]
                        log_name = ''
                        command = f'./gradlew --no-daemon --stacktrace {task}'
                    if verifier is None:
                        verifier = self._new_container(workspace, scratch, verify_home)
                    after = self._run(verifier, command, remaining)
                    self._stop_container(verifier)
                    verifier = None
                    if not instrumented:
                        candidate_unit[module] = after
                task = (':'.join(module.parts) + ':connectedDebugAndroidTest'
                        if instrumented else unit_tasks[module])
                xml_path = _matching_xml(workspace, module, test['kind'], task, test['class'])
                _save_verification_artifacts(run_artifacts, f'candidate-{index}', after, xml_path, workspace)
                passed = (after['exit_code'] == 0 and not after['timed_out'] and
                          xml_path is not None and _all_passed(xml_path, test['class'], workspace))
                oom = _fatal_oom_proof(
                    workspace, module, test['class'], scratch / f'candidate-{index}.logcat.txt',
                    after['stdout'] + '\n' + after['stderr'],
                ) if instrumented and not after['timed_out'] else None
                checks.append({
                    'phase': 'candidate', 'path': test['path'].as_posix(),
                    'exit_code': after['exit_code'], 'timed_out': after['timed_out'],
                    'test_result': 'passed' if passed else 'fatal-oom' if oom else 'missing-failed-or-skipped',
                    'evidence': {'source': 'junit-xml'} if passed else oom,
                })
                all_passed = all_passed and passed
            return {'passed': all_passed,
                    'reason': 'all regressions reproduced and passed with candidate' if all_passed else 'candidate did not pass every reproduced regression',
                    'checks': checks}
        except (OSError, ValueError, TypeError, ET.ParseError) as exc:
            return {'passed': False, 'reason': str(exc)[:300], 'checks': checks}
        finally:
            if verifier is not None:
                self._stop_container(verifier)

    def _verification_workspace(
        self, run_id: str, phase: str, tests: list[dict[str, Any]],
        sources: list[tuple[pathlib.PurePosixPath, str]],
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        phase_root = self._root / f'verification-{run_id}' / phase
        phase_root.mkdir(parents=True)
        workspace = phase_root / 'target'
        shutil.copytree(self._snapshot, workspace, symlinks=True)
        self._prepare_build_config(workspace)
        for test in tests:
            _write_candidate(workspace, test['path'], test['content'])
        for path, content in sources:
            _write_candidate(workspace, path, content)
        scratch = phase_root / 'scratch'
        scratch.mkdir()
        home = phase_root / 'home'
        home.mkdir()
        self._artifact_sources.append((scratch, pathlib.PurePosixPath(run_id, f'{phase}-scratch')))
        return workspace, scratch, home


def _remaining_timeout(deadline: float, maximum: int) -> int:
    return max(0, min(maximum, int(deadline - time.monotonic())))


def _save_verification_artifacts(
    artifact_root: pathlib.Path, phase: str, result: dict[str, Any],
    junit_xml: pathlib.Path | None, workspace: pathlib.Path,
) -> None:
    destination = artifact_root / phase
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'stdout.txt').write_text(result['stdout'], encoding='utf-8')
    (destination / 'stderr.txt').write_text(result['stderr'], encoding='utf-8')
    if junit_xml is not None:
        data = _read_regular_file(workspace, junit_xml, 5 * 1024 * 1024)
        if data is not None:
            (destination / 'junit.xml').write_bytes(data)



def _read_regular_file(root: pathlib.Path, path: pathlib.Path, maximum: int) -> bytes | None:
    """Read stopped-container output without following any host-side symlinks."""
    try:
        relative = path.relative_to(root)
        if not relative.parts or any(part in ('.', '..') for part in relative.parts):
            return None
        parent = root
        for part in relative.parts[:-1]:
            parent = parent / part
            if not stat.S_ISDIR(parent.lstat().st_mode):
                return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                return None
            data = stream.read(maximum + 1)
            return data if len(data) <= maximum else None
    except (OSError, ValueError):
        return None


def _read_tail(stream: Any, maximum: int) -> str:
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(max(0, size - maximum))
    return stream.read(maximum).decode('utf-8', errors='replace')


def _write_candidate(workspace: pathlib.Path, rel: pathlib.PurePosixPath, content: str) -> None:
    destination = workspace.joinpath(*rel.parts)
    root = workspace.resolve()
    if not destination.parent.resolve().is_relative_to(root):
        raise ValueError('candidate path escapes verification workspace')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValueError('candidate path resolves through a symlink')
    destination.write_text(content, encoding='utf-8')


def _unit_test_task(output: str, module_task: str) -> str | None:
    names = set(re.findall(r'^([A-Za-z][A-Za-z0-9]*)\s+-', output, re.MULTILINE))
    if 'testDebugUnitTest' in names:
        return f':{module_task}:testDebugUnitTest'
    if 'test' in names:
        return f':{module_task}:test'
    return None


def _instrumentation_command(task: str, test_class: str, log_name: str) -> str:
    class_filter = shlex.quote(test_class)
    log_path = shlex.quote(f'/workspace/scratch/{log_name}')
    return (
        'mkdir -p \"$HOME/.android/avd\"; '
        'echo no | avdmanager create avd --force --name crashlytics-verification '
        '--package \"system-images;android-34;google_apis;x86_64\" --device pixel_2 >/tmp/avd.log 2>&1; '
        'emulator -avd crashlytics-verification -no-window -no-audio -no-boot-anim '
        '-gpu swiftshader_indirect -no-snapshot -wipe-data >/tmp/emulator.log 2>&1 & '
        "EMULATOR_PID=$!; trap 'kill \"$EMULATOR_PID\" 2>/dev/null || true' EXIT; "
        'adb wait-for-device; '
        'until [ \"$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d \"\\\\r\")\" = 1 ]; do sleep 2; done; '
        'adb logcat -c; '
        f'./gradlew --no-daemon --stacktrace {task} '
        f'-Pandroid.testInstrumentationRunnerArguments.class={class_filter}; result=$?; '
        f'adb logcat -d -v threadtime -t 20000 > {log_path}; exit \"$result\"'
    )


def _test_class_name(path: pathlib.PurePosixPath, content: str) -> str:
    source_index = path.parts.index('src')
    package_match = re.search(r'^[ \t]*package\s+([A-Za-z0-9_.]+)', content, re.MULTILINE)
    if package_match:
        package = package_match.group(1)
    else:
        package = '.'.join(path.parts[source_index + 3:-1])
    return f'{package}.{path.stem}' if package else path.stem


def _fatal_oom_proof(
    workspace: pathlib.Path, module: pathlib.PurePosixPath, test_class: str,
    log_path: pathlib.Path, runner_output: str,
) -> dict[str, Any] | None:
    status_class = f'INSTRUMENTATION_STATUS: class={test_class}'
    if status_class not in runner_output:
        return None
    metadata_paths = list((workspace / module / 'build' / 'outputs' / 'apk').glob('**/output-metadata.json'))
    app_id = None
    for metadata_path in metadata_paths:
        try:
            data = _read_regular_file(workspace, metadata_path, 1024 * 1024)
            if data is None:
                continue
            metadata = json.loads(data)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(metadata, dict) and isinstance(metadata.get('applicationId'), str):
            app_id = metadata['applicationId']
            break
    if not app_id:
        return None
    data = _read_regular_file(log_path.parent, log_path, 16 * 1024 * 1024)
    if data is None:
        return None
    lines = data.decode('utf-8', errors='replace').splitlines()
    for index, line in enumerate(lines):
        process = re.search(rf'Process:\s*{re.escape(app_id)},\s*PID:\s*(\d+)', line)
        if process is None:
            continue
        pid = process.group(1)
        started = any(re.search(rf'Start proc\s+{pid}:{re.escape(app_id)}/', entry) for entry in lines[:index + 1])
        if not started:
            continue
        process_log = [
            entry for entry in lines
            if re.match(rf'^\d\d-\d\d\s+\S+\s+{pid}\s+\d+\s', entry)
        ]
        fatal = any('AndroidRuntime: FATAL EXCEPTION' in entry for entry in process_log)
        oom = any('OutOfMemoryError' in entry for entry in process_log)
        if fatal and oom:
            return {'source': 'android-logcat', 'package': app_id, 'pid': int(pid),
                    'failure': 'fatal OutOfMemoryError', 'testClass': test_class}
    return None


def _matching_xml(
    workspace: pathlib.Path, module: pathlib.PurePosixPath, kind: str,
    task: str, test_class: str,
) -> pathlib.Path | None:
    module_root = workspace / module
    if kind == 'test':
        task_name = task.rsplit(':', 1)[-1]
        paths = list(module_root.glob(f'build/test-results/{task_name}/TEST-*.xml'))
    else:
        paths = list(module_root.glob('build/outputs/androidTest-results/connected/**/*.xml'))
        paths.extend(module_root.glob('build/outputs/androidTest-results/**/*.xml'))
    for path in paths:
        try:
            data = _read_regular_file(workspace, path, 5 * 1024 * 1024)
            if data is None:
                continue
            root = ET.fromstring(data)
        except (OSError, ET.ParseError):
            continue
        if any(_matches_testcase(node, test_class) for node in root.iter('testcase')):
            return path
    return None


def _matches_testcase(node: ET.Element, test_class: str) -> bool:
    short_name = test_class.rsplit('.', 1)[-1]
    classname = node.attrib.get('classname', '')
    if classname:
        return classname == test_class
    return node.attrib.get('name') in (test_class, short_name)


def _has_failure(path: pathlib.Path, test_class: str, workspace: pathlib.Path) -> bool:
    try:
        data = _read_regular_file(workspace, path, 5 * 1024 * 1024)
        if data is None:
            return False
        root = ET.fromstring(data)
    except (OSError, ET.ParseError):
        return False
    return any(_matches_testcase(node, test_class) and node.find('failure') is not None
               for node in root.iter('testcase'))


def _all_passed(path: pathlib.Path, test_class: str, workspace: pathlib.Path) -> bool:
    try:
        data = _read_regular_file(workspace, path, 5 * 1024 * 1024)
        if data is None:
            return False
        root = ET.fromstring(data)
    except (OSError, ET.ParseError):
        return False
    matched = [node for node in root.iter('testcase') if _matches_testcase(node, test_class)]
    return bool(matched) and all(
        node.find('failure') is None and node.find('error') is None and
        'skipped' not in node.attrib and node.find('skipped') is None
        for node in matched
    )
