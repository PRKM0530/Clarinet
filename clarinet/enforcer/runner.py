"""
clarinet/enforcer/runner.py
Injectable command runner for nft, tc, ip.

Tests pass FakeRunner; production uses RealRunner.
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

log = logging.getLogger("clarinet.enforcer.runner")


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class RealRunner:
    """Runs commands via subprocess."""

    def run(self, argv: list[str], input: str | None = None, timeout: int = 5) -> CommandResult:
        try:
            proc = subprocess.run(
                argv,
                input=input.encode() if input else None,
                capture_output=True,
                timeout=timeout,
            )
            return CommandResult(
                returncode=proc.returncode,
                stdout=proc.stdout.decode(errors="replace"),
                stderr=proc.stderr.decode(errors="replace"),
            )
        except FileNotFoundError:
            log.debug("Command not found: %s (Linux only?)", argv[0])
            return CommandResult(returncode=127, stderr=f"{argv[0]}: not found")
        except Exception as exc:
            log.error("Runner error for %s: %s", argv, exc)
            return CommandResult(returncode=1, stderr=str(exc))


# Module-level default (tests may replace this)
_runner: RealRunner = RealRunner()


def get_runner() -> RealRunner:
    return _runner


def set_runner(r) -> None:
    global _runner
    _runner = r


def run(argv: list[str], input: str | None = None, timeout: int = 5) -> CommandResult:
    return _runner.run(argv, input=input, timeout=timeout)

