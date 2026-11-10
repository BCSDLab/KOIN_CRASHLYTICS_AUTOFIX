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

ANDROID_APPLICATION_ID: str = os.environ.get('CRASHLYTICS_BUNDLE_ID', 'in.koreatech.koin')
if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', ANDROID_APPLICATION_ID):
    raise ValueError('CRASHLYTICS_BUNDLE_ID must be a dotted Android application ID')
