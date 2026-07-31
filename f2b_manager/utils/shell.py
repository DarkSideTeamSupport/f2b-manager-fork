"""
f2b_manager.utils.shell
=======================

Обёртка над subprocess: безопасный запуск команд.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class CommandResult:
    """Результат выполнения команды."""
    returncode: int
    stdout: str
    stderr: str
    success: bool

    @property
    def output(self) -> str:
        """Объединённый stdout + stderr."""
        return (self.stdout + self.stderr).strip()


def run_command(
    cmd: str | list[str],
    *,
    timeout: int = 120,
    check: bool = False,
    input_text: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> CommandResult:
    """Выполнить shell-команду.

    Args:
        cmd: строка команды или список аргументов
        timeout: таймаут в секундах
        check: при True ненулевой код выхода → CalledProcessError
        input_text: текст для stdin
        env: дополнительные переменные окружения

    Returns:
        CommandResult
    """
    if isinstance(cmd, str):
        args = shlex.split(cmd)
    else:
        args = list(cmd)

    full_env = None
    if env:
        import os
        full_env = os.environ.copy()
        full_env.update(env)

    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_text,
        env=full_env,
    )

    result = CommandResult(
        returncode=proc.returncode,
        stdout=proc.stdout.strip(),
        stderr=proc.stderr.strip(),
        success=(proc.returncode == 0),
    )

    if check and not result.success:
        raise subprocess.CalledProcessError(
            proc.returncode, args, proc.stdout, proc.stderr
        )

    return result


def which(binary: str) -> Optional[str]:
    """Проверить наличие команды; вернуть полный путь или None."""
    result = run_command(f"which {binary}", timeout=5)
    return result.stdout if result.success else None
