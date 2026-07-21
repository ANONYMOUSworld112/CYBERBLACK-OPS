import json, tempfile, pytest
from pathlib import Path
from unittest import mock
from cyberblack.runner import ConfirmationRequiredError, ExecutionResult, run_trusted, run_freeform
from cyberblack.audit import log_execution, read_recent


class TestResult:
    def test_ok_zero(self):
        assert ExecutionResult(command="t", exit_code=0).ok is True

    def test_ok_nonzero(self):
        assert ExecutionResult(command="t", exit_code=1).ok is False


class TestRunTrusted:
    @mock.patch("cyberblack.runner.subprocess.run")
    def test_simple(self, m):
        m.return_value.returncode = 0
        r = run_trusted("echo hi")
        assert r.exit_code == 0

    @mock.patch("cyberblack.runner.subprocess.run")
    def test_pipe_shell(self, m):
        m.return_value.returncode = 0
        r = run_trusted("a | b")
        assert m.call_args.kwargs.get("shell") is True

    @mock.patch("cyberblack.runner.subprocess.run")
    def test_chain_shell(self, m):
        m.return_value.returncode = 0
        r = run_trusted("a && b")
        assert m.call_args.kwargs.get("shell") is True

    @mock.patch("cyberblack.runner.subprocess.run")
    def test_redirect_shell(self, m):
        m.return_value.returncode = 0
        r = run_trusted("a > b")
        assert m.call_args.kwargs.get("shell") is True

    @mock.patch("cyberblack.runner.subprocess.run")
    def test_ctor_shell(self, m):
        m.return_value.returncode = 0
        r = run_trusted("a ; b")
        assert m.call_args.kwargs.get("shell") is True

    @mock.patch("cyberblack.runner.subprocess.run")
    def test_keyboard_interrupt(self, m):
        m.side_effect = KeyboardInterrupt()
        r = run_trusted("sleep")
        assert r.interrupted is True


class TestRunFreeform:
    def test_no_confirm(self):
        with pytest.raises(ConfirmationRequiredError):
            run_freeform("echo", confirmed=False)

    @mock.patch("cyberblack.runner.subprocess.run")
    def test_with_confirm(self, m):
        m.return_value.returncode = 0
        r = run_freeform("echo", confirmed=True)
        assert r.exit_code == 0


class TestAuditLog:
    def test_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "log.jsonl"
            log_execution(ExecutionResult(command="c", exit_code=0), path=p)
            assert p.exists()

    def test_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "log.jsonl"
            for i in range(3):
                log_execution(ExecutionResult(command=f"c{i}", exit_code=i), path=p)
            assert len(p.read_text().splitlines()) == 3

    def test_read_recent(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "log.jsonl"
            for i in range(5):
                log_execution(ExecutionResult(command=f"c{i}", exit_code=i), path=p)
            recent = read_recent(n=3, path=p)
            assert len(recent) == 3
            assert recent[0]["command"] == "c2"

    def test_read_empty(self):
        assert read_recent(path=Path("/nonexistent/path.jsonl")) == []
