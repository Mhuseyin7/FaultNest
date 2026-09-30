"""Local-only capture records for FaultNest; no network or environment collection."""
from __future__ import annotations
import json, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

_SECRET = re.compile(r"(?:bearer\s+|gh[pousr]_)[A-Za-z0-9._~+\/-]{12,}|(?:authorization|cookie|x-api-key)\s*[:=]\s*[^\r\n]+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return _IP.sub("<IP>", _EMAIL.sub("<EMAIL>", _SECRET.sub("<SECRET>", value)))
    if isinstance(value, Mapping): return {str(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [_sanitize(v) for v in value]
    return value

def capture_error(error: BaseException, context: Mapping[str, Any] | None = None, file: str = ".faultnest/requests.jsonl") -> Path:
    """Append a sanitized JSONL event locally and return its path."""
    target = Path(file).resolve(); target.parent.mkdir(parents=True, exist_ok=True)
    event = _sanitize({"timestamp": datetime.now(timezone.utc).isoformat(), "error": {"type": type(error).__name__, "message": str(error)}, "context": context or {}})
    with target.open("a", encoding="utf-8") as handle: handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    return target
