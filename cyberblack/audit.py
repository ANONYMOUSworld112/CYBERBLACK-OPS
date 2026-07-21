from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runner import ExecutionResult

DEFAULT_LOG_PATH = Path.home() / ".cyberblack" / "run_log.jsonl"


def log_execution(result: "ExecutionResult", *, path: Path = DEFAULT_LOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "command": result.command,
        "exit_code": result.exit_code,
        "interrupted": result.interrupted,
        "error": result.error,
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def read_recent(n: int = 20, *, path: Path = DEFAULT_LOG_PATH) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines[-n:] if line.strip()]
