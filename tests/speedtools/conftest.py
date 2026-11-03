"""
Speed-tool tests run the REAL subprocess code against fake executables. PATH contains only the fake
directory, so no real speed test tool can ever be reached and no internet is used.
"""
import stat
import pytest


@pytest.fixture()
def tools(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setenv("CLARINET_NO_VENV_TOOLS", "1")   # never fall back to the real venv tools
    for helper in ("cat", "sleep"):                     # the only real programs the fake scripts need
        (bindir / helper).symlink_to(f"/usr/bin/{helper}")

    def install(name, stdout="", exit_code=0, sleep=0):
        f = bindir / name
        f.write_text(f"#!/bin/sh\n{'sleep ' + str(sleep) if sleep else ''}\ncat <<'EOF'\n{stdout}\nEOF\nexit {exit_code}\n")
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return install
