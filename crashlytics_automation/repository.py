"""Repository identity comes from trusted deployment config, never event payloads."""

from __future__ import annotations

import os
import re

REPOSITORY: str = os.environ.get('AUTOFIX_GITHUB_REPOSITORY', 'BCSDLab/KOIN_ANDROID')
if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}', REPOSITORY):
    raise ValueError('AUTOFIX_GITHUB_REPOSITORY must be an owner/repository name')
OWNER: str
REPO: str
OWNER, REPO = REPOSITORY.split('/', 1)
REPOSITORY_PATH: str = f'/repos/{REPOSITORY}'
TARGET_BRANCHES: tuple[str, str] = ('production', 'develop')

STATE_REPOSITORY: str = os.environ.get('AUTOFIX_STATE_REPOSITORY', f'{OWNER}/KOIN_CRASHLYTICS_AUTOFIX')
if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}', STATE_REPOSITORY):
    raise ValueError('AUTOFIX_STATE_REPOSITORY must be an owner/repository name')
STATE_OWNER, STATE_REPO = STATE_REPOSITORY.split('/', 1)
if STATE_OWNER != OWNER or STATE_REPOSITORY == REPOSITORY:
    raise ValueError('State storage must use a separate repository in the same installation owner')
STATE_REPOSITORY_PATH: str = f'/repos/{STATE_REPOSITORY}'
STATE_REFERENCE: str = 'refs/automation/crashlytics-investigations'

ANDROID_APPLICATION_ID: str = os.environ.get('CRASHLYTICS_BUNDLE_ID', 'in.koreatech.koin')
if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', ANDROID_APPLICATION_ID):
    raise ValueError('CRASHLYTICS_BUNDLE_ID must be a dotted Android application ID')
