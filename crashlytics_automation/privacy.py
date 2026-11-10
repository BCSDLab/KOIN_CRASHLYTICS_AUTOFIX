"""Redact sensitive values before sending crash summaries outside Crashlytics."""

from __future__ import annotations

import re
from typing import Any


def safe_text(value: Any, max_length: int = 1000) -> str:
    text = '' if value is None else str(value)
    text = re.sub(r'https?://\S+', '[URL]', text, flags=re.I)
    text = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[EMAIL]', text)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP]', text)
    text = re.sub(r'\b(bearer\s+)[\w.\-]+', r'\1[REDACTED]', text, flags=re.I)
    text = re.sub(r'\b(token|password|secret|authorization|api[_-]?key)\s*[:=]\s*\S+', r'\1=[REDACTED]', text, flags=re.I)
    text = re.sub(r'[\x00-\x1f\x7f]', ' ', text).replace('@', '＠')
    return re.sub(r'[<>`]', '', text)[:max_length]
