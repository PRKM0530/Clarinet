"""
clarinet/core_svc/runner.py
Injectable command runner for M1 core services.

Provides an abstraction over subprocess so that all Linux-only commands
(nft, ip, arp-scan, etc.) can be faked in tests without os-level mocking.

Pattern: pass a Runner instance into functions that need to run commands;
  default to the real SystemRunner; tests inject FakeRunner.
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod


class Runner(ABC):
    """Abstract command runner interface."""

    @abstractmethod
    def run(
        self,
        args: list[str],
        timeout: float = 10.0,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        """Run a command and return CompletedProcess."""
        ...

    def check_output(
        self,
        args: list[str],
        timeout: float = 10.0,
    ) -> str:
        """Run a command and return stdout as a string."""
        result = self.run(args, timeout=timeout, check=True)
        return result.stdout or ""


class SystemRunner(Runner):
    """Real runner that calls subprocess.run."""

    def run(
        self,
        args: list[str],
        timeout: float = 10.0,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )


class FakeRunner(Runner):
    """
    Test double — returns pre-programmed outputs.
    Register responses with `register(args[0], stdout)`.
    """

    def __init__(self) -> None:
        self._responses: dict[str, str] = {}
        self._calls: list[list[str]] = []

    def register(self, command: str, stdout: str = "", returncode: int = 0) -> None:
        self._responses[command] = stdout

    def run(
        self,
        args: list[str],
        timeout: float = 10.0,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        self._calls.append(args)
        cmd = args[0] if args else ""
        stdout = self._responses.get(cmd, "")
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout=stdout,
            stderr="",
        )

    @property
    def calls(self) -> list[list[str]]:
        return list(self._calls)


# Module-level default runner (can be overridden in tests)
_default_runner: Runner = SystemRunner()


def get_runner() -> Runner:
    return _default_runner


def set_runner(runner: Runner) -> None:
    global _default_runner
    _default_runner = runner
