"""One-time, no-generation repair of the two already verified #1789 publications."""
import base64
import hashlib
import json
import os
import pathlib
import tempfile
from contextlib import ExitStack
from datetime import datetime, timezone

from crashlytics_automation.candidate import candidate_manifest, canonical_json, identity_hash_for, manifest_digest, validate_candidate
from crashlytics_automation.investigation_jobs import InvestigationQueue, MAX_VERIFICATION_ATTEMPTS
from crashlytics_automation.models import FileChange, PublishedFix
from crashlytics_automation.openai_client import _normalize_decision
from crashlytics_automation.pull_requests import _create_commit, _create_tree, _pull_request_body, branch_head_sha
from crashlytics_automation.repository import REPOSITORY_PATH
from crashlytics_automation.sandbox import InvestigationSandbox, _write_candidate
from crashlytics_automation.worker import _report, runtime_config, worker_github

JOB = '512ac5b6c09e2591aea9344697da891ad80d9736643a70ed9cc6ffece07a2e42'
ORIGIN = '41071baf8465e0083f156da61a80b30296c63715'
EXPECTED = {
    'production': (1793, '56de218ae609265135dc35807393ed4fc1e627eb'),
    'develop': (1794, 'fc380d1725f1d7787dd6bdcd272921eb7ec5ba30'),
}
SOURCE = 'feature/banner/src/main/java/in/koreatech/koin/feature/banner/component/BannerImage.kt'
TEST = 'feature/banner/src/androidTest/java/in/koreatech/koin/feature/banner/component/CrashlyticsRegressiona9a611a788d7Test.kt'


def main():
    config = runtime_config()
    os.environ.pop('CRASHLYTICS_OPENAI_API_KEY', None)
    github = worker_github()
    queue = InvestigationQueue(github)
    entries = queue._entries(queue._head())
    job = queue._read(JOB, entries['jobs/' + JOB + '.json'])
    if (job['issueNumber'] != 1789 or job.get('releaseSha') != ORIGIN or
            job.get('attempts') != {'production': 4} or
            job.get('attemptLimits') != {'production': 4} or
            job.get('verificationOnly') is not True or
            job.get('verificationAttempts', {}).get('production') != 2 or
            set(job['branches']) != set(EXPECTED)):
        raise RuntimeError('Saved case changed; refusing publication repair')
    if branch_head_sha(github, 'production') != ORIGIN:
        raise RuntimeError('Production origin moved')
    pulls = {}
    for target, (number, old_head) in EXPECTED.items():
        pull = github.rest('GET', f'{REPOSITORY_PATH}/pulls/{number}')
        if (job['branches'][target]['headSha'] != old_head or
                job['branchBases'].get(target) != ORIGIN or
                pull.get('state') != 'open' or pull.get('draft') is not True or
                pull['head']['sha'] != old_head or pull['base']['ref'] != target or
                pull['base']['sha'] != job['branches'][target]['baseSha'] or
                pull['user']['login'] != config['botLogin']):
            raise RuntimeError('PR identity, base, or draft hold changed')
        pulls[target] = pull
    raw = base64.b64decode(os.environ['PROPOSAL_B64'], validate=True)
    if len(raw) > 45000 or hashlib.sha256(raw).hexdigest() != os.environ['PROPOSAL_SHA256']:
        raise RuntimeError('Revised candidate payload changed')
    decision = _normalize_decision(json.loads(raw))
    if decision['decision'] != 'fix' or decision['sourcePath'] != SOURCE or decision['sourceLine'] != 60 or (
        len(decision['files']) != 2 or {item['path'] for item in decision['files']} != {SOURCE, TEST}
    ):
        raise RuntimeError('Unexpected repair file scope')
    identity = identity_hash_for('0250620e4e9c331c7a8aa39c9f9f1454', ORIGIN)
    artifacts = pathlib.Path(os.environ['INVESTIGATION_ARTIFACTS']) / JOB / 'publication-repair'
    artifacts.mkdir(parents=True)
    try:
        with tempfile.TemporaryDirectory(prefix='crashlytics-publication-repair-') as tmp:
            root = pathlib.Path(tmp)
            github.checkout(ORIGIN, root / 'release')
            github.checkout(ORIGIN, root / 'target')
            baseline = {SOURCE: (root / 'target' / SOURCE).read_text()}
            if (root / 'target' / TEST).exists():
                raise RuntimeError('Regression already exists on the pristine base')
            validated = validate_candidate(decision['files'], baseline, identity)
            if not validated['valid']:
                raise RuntimeError(validated['reason'])
            decision['files'] = validated['files']
            job['status'] = 'running'
            job['startedAt'] = datetime.now(timezone.utc).isoformat()
            job['runUrl'] = f'https://github.com/{os.environ["GITHUB_REPOSITORY"]}/actions/runs/{os.environ["GITHUB_RUN_ID"]}'
            job['verificationResumeRequired'] = True
            for target in EXPECTED:
                queue.save_proposal(job, target, decision, release_sha=ORIGIN,
                                    branch_base_sha=ORIGIN, base_sha=job['branches'][target]['baseSha'])
            (artifacts / 'proposal.json').write_text(json.dumps(decision, ensure_ascii=False, indent=2))
            with InvestigationSandbox(release=root / 'release', target=root / 'target',
                                      image=os.environ['INVESTIGATION_IMAGE'],
                                      android_sdk=pathlib.Path(os.environ['ANDROID_HOME'])) as sandbox, ExitStack() as exports:
                exports.callback(sandbox.export_artifacts, artifacts)
                # This workspace contains only pristine tooling and the validated candidate;
                # no model commands have run. The verifier keeps its own original snapshot.
                for item in validated['files']:
                    _write_candidate(sandbox.target, pathlib.PurePosixPath(item['path']), item['content'])
                style = sandbox.execute(
                    command='./gradlew --no-daemon --max-workers=2 --no-configuration-cache -Dorg.gradle.jvmargs=-Xmx1536m -Pkotlin.compiler.execution.strategy=in-process :feature:banner:detekt',
                    timeout_seconds=600,
                )
                (sandbox.artifact_directory / 'detekt.json').write_text(json.dumps(style, ensure_ascii=False))
                if style['exit_code'] != 0 or style['timed_out']:
                    raise RuntimeError('Revised banner did not pass the actual module detekt task')
                used = job.setdefault('verificationAttempts', {}).get('production', 0)
                if used >= MAX_VERIFICATION_ATTEMPTS:
                    raise RuntimeError('Trusted verification retry limit reached')
                job['verificationAttempts']['production'] = used + 1
                queue.put(job)
                verification = sandbox.verify_candidate(files=validated['files'], identity_hash=identity)
                job['analyses']['production']['verification'] = verification
                queue.put(job)
                if verification.get('passed') is not True:
                    raise RuntimeError(verification.get('reason') or 'Trusted verification failed')
            if branch_head_sha(github, 'production') != ORIGIN:
                raise RuntimeError('Production moved during verification')
            file_pins = [{key: item[key] for key in ('path', 'kind', 'beforeSha256', 'afterSha256')}
                         for item in validated['files']]
            proof_digest = hashlib.sha256(canonical_json(file_pins).encode()).hexdigest()
            repository = github.rest('GET', REPOSITORY_PATH)
            for target, (number, old_head) in EXPECTED.items():
                manifest = candidate_manifest(
                    issue_id='0250620e4e9c331c7a8aa39c9f9f1454', issue_number=1789,
                    identity_hash=identity, base_sha=job['branches'][target]['baseSha'],
                    branch_base_sha=ORIGIN, source_sha=ORIGIN, source_path=SOURCE, files=file_pins,
                )
                changes = tuple(FileChange(item['path'], item['content']) for item in validated['files'])
                tree = _create_tree(github, ORIGIN, changes)
                new_head = _create_commit(github, manifest, ORIGIN, tree)
                queue.put_publication(new_head, manifest)
                github.graphql('''mutation($repository:ID!,$updates:[RefUpdate!]!) {
                    updateRefs(input:{repositoryId:$repository,refUpdates:$updates}) { clientMutationId }
                }''', {'repository': repository['node_id'], 'updates': [{
                    'name': 'refs/heads/' + pulls[target]['head']['ref'],
                    'beforeOid': old_head, 'afterOid': new_head, 'force': True,
                }]})
                github.rest('PATCH', f'{REPOSITORY_PATH}/pulls/{number}', {
                    'body': _pull_request_body(manifest, 1789, target),
                })
                job['branches'][target] = PublishedFix(number, new_head,
                    manifest['baseSha'], manifest_digest(manifest), target, reused=True).to_payload()
                job['analyses'][target]['analysis'] = decision['analysis']
                job['analyses'][target]['reason'] = decision['reason']
                job['analyses'][target]['verification'] = verification
                job['analyses'][target]['verificationProvenance'] = {
                    'runUrl': job['runUrl'], 'productionOrigin': ORIGIN,
                    'filesDigest': proof_digest, 'sharedExactSourceProof': True,
                }
                queue.put(job)
            job['status'] = 'manual'
            job['verificationResumeRequired'] = False
            job['reason'] = '사용자 요청에 따라 앱 PR만 정리했습니다. 기존 Maestro CI 오류는 범위 밖이며 자동 머지를 보류합니다.'
            job['reportPending'] = True
            queue.put(job)
            _report(github, queue, job, config)
            print(json.dumps({'outcome': 'metadata-free-publications-held', 'branches': job['branches'],
                              'modelAttempts': job['attempts'], 'proofFilesDigest': proof_digest, 'draft': True}))
    except Exception as error:
        job['status'], job['reason'], job['reportPending'] = 'manual', str(error)[:1000], True
        queue.put(job)
        _report(github, queue, job, config)
        raise


if __name__ == '__main__':
    main()
