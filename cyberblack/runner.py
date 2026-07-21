from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass

from .audit import log_execution

_SHELL_METACHARACTERS = ("&&", "||", "|", ">", "<", ";", "$(", "`")


@dataclass(slots=True, frozen=True)
class ExecutionResult:
    command: str
    exit_code: int | None = None
    interrupted: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class ConfirmationRequiredError(Exception):
    pass


def run_trusted(command: str) -> ExecutionResult:
    return _execute(command)


def run_freeform(command: str, *, confirmed: bool) -> ExecutionResult:
    if not confirmed:
        raise ConfirmationRequiredError("Free-form execution requires explicit confirmation.")
    return _execute(command)


def _execute(command: str) -> ExecutionResult:
    needs_shell = any(token in command for token in _SHELL_METACHARACTERS)
    try:
        if needs_shell:
            proc = subprocess.run(command, shell=True)
        else:
            proc = subprocess.run(shlex.split(command))
        result = ExecutionResult(command=command, exit_code=proc.returncode)
    except KeyboardInterrupt:
        result = ExecutionResult(command=command, interrupted=True)
    except FileNotFoundError as exc:
        result = ExecutionResult(command=command, error=str(exc))
    log_execution(result)
    return result
