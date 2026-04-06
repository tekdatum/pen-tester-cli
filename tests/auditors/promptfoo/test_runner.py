import subprocess
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from pentester.auditors.promptfoo.runner import PromptfooRunner


def _make_runner(**kwargs: Any) -> PromptfooRunner:
    defaults: dict[str, Any] = {"results_path": Path("/tmp/results")}
    defaults.update(kwargs)
    return PromptfooRunner(**defaults)


class TestInit:
    def test_initializes_with_explicit_arguments(self) -> None:
        runner = _make_runner(
            results_path=Path("/my/results"),
            files_parallel=10,
            concurrency=8,
        )
        assert runner.results_path == Path("/my/results")
        assert runner.files_parallel == 10
        assert runner.concurrency == 8

    def test_initializes_with_defaults(self) -> None:
        runner = PromptfooRunner(results_path=Path("/tmp"))
        assert runner.files_parallel == 5
        assert runner.concurrency == 4
        assert runner.max_tests == 20000
        assert runner.default_email == "tools@tekdatum.com"

    def test_initializes_with_custom_default_email(self) -> None:
        runner = _make_runner(default_email="custom@example.com")
        assert runner.default_email == "custom@example.com"

    def test_initializes_with_max_tests(self) -> None:
        runner = _make_runner(max_tests=500)
        assert runner.max_tests == 500


class TestRunEval:
    @pytest.fixture(autouse=True)
    def _patch_subprocess(self) -> Generator[None]:
        self.mock_result = MagicMock()
        self.mock_result.stdout = "eval output"
        self.mock_result.stderr = ""
        with patch(
            "pentester.auditors.promptfoo.runner.subprocess.run",
            return_value=self.mock_result,
        ) as self.mock_run:
            yield

    def test_returns_expected_values_on_success(self) -> None:
        success, name, output = _make_runner().run_eval(Path("/test/config.yaml"))

        assert success is True
        assert name == "config.yaml"
        assert output == "eval output"

    def test_returns_success_on_non_zero_exit_code(self) -> None:
        self.mock_result.returncode = 1
        success, name, output = _make_runner().run_eval(Path("/test/config.yaml"))

        assert success is True
        assert name == "config.yaml"
        assert output == "eval output"

    def test_returns_false_on_os_error(self) -> None:
        self.mock_run.side_effect = OSError("promptfoo not found")
        success, _, output = _make_runner().run_eval(Path("/test/config.yaml"))

        assert success is False
        assert output == "promptfoo not found"

    def test_builds_correct_subprocess_command(self) -> None:
        _make_runner(concurrency=12).run_eval(Path("/test/my_test.yaml"))

        self.mock_run.assert_called_once()
        command = self.mock_run.call_args[0][0]
        kwargs = self.mock_run.call_args[1]

        # Verify command structure and flags
        assert command[0:2] == ["promptfoo", "eval"]
        assert (
            "-c" in command and command[command.index("-c") + 1] == "/test/my_test.yaml"
        )
        assert "-j" in command and command[command.index("-j") + 1] == "12"
        assert "-n" in command and command[command.index("-n") + 1] == "20000"
        assert "--output" in command
        assert "my_test_result" in command[command.index("--output") + 1]
        assert command[command.index("--output") + 1].endswith(".jsonl")

        # Verify boolean flags
        assert "--no-cache" in command
        assert "--no-progress-bar" in command
        assert "--no-table" in command

        # Verify subprocess parameters — check=True is no longer used
        assert "check" not in kwargs
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True

    def test_max_tests_flag_uses_configured_value(self) -> None:
        _make_runner(max_tests=42).run_eval(Path("/test/my_test.yaml"))

        command = self.mock_run.call_args[0][0]
        assert "-n" in command and command[command.index("-n") + 1] == "42"


class TestRunRedteamGenerate:
    @pytest.fixture(autouse=True)
    def _patch_subprocess(self) -> Generator[None]:
        self.mock_result = MagicMock()
        self.mock_result.stdout = "generate output"
        self.mock_result.stderr = ""
        with patch(
            "pentester.auditors.promptfoo.runner.subprocess.run",
            return_value=self.mock_result,
        ) as self.mock_run:
            yield

    def test_returns_true_on_success(self) -> None:
        result = _make_runner().run_redteam_generate(
            Path("/config.yaml"), Path("/output.yaml")
        )
        assert result is True

    def test_returns_false_on_error(self) -> None:
        self.mock_run.side_effect = subprocess.CalledProcessError(
            1, "cmd", stderr="fail"
        )
        result = _make_runner().run_redteam_generate(
            Path("/config.yaml"), Path("/output.yaml")
        )
        assert result is False

    def test_builds_correct_subprocess_command(self) -> None:
        _make_runner().run_redteam_generate(Path("/config.yaml"), Path("/output.yaml"))

        self.mock_run.assert_called_once()
        command = self.mock_run.call_args[0][0]
        kwargs = self.mock_run.call_args[1]

        # Verify command structure and flags
        assert command[:3] == ["promptfoo", "redteam", "generate"]
        assert (
            "--output" in command
            and command[command.index("--output") + 1] == "/output.yaml"
        )
        assert (
            "--config" in command
            and command[command.index("--config") + 1] == "/config.yaml"
        )

        # Verify subprocess parameters
        assert kwargs["check"] is True
        assert kwargs["capture_output"] is True


class TestRunAll:
    def test_processes_multiple_files_and_returns_full_results(self) -> None:
        runner = _make_runner()
        files = [Path("/test/a.yaml"), Path("/test/b.yaml")]

        # Mocking side_effect allows us to return different results per file
        # This is done to ensure data maps correctly
        mock_returns = [(True, "a.yaml", "ok"), (False, "b.yaml", "error")]
        with patch.object(runner, "run_eval", side_effect=mock_returns) as mock_eval:
            results = runner.run_all(files)

        assert mock_eval.call_count == 2
        assert len(results) == 2

        # Verify the structure of the returned tuples: (Path, Success, Name, Output)
        assert results[0] == (files[0], True, "a.yaml", "ok")
        assert results[1] == (files[1], False, "b.yaml", "error")

    def test_handles_empty_input(self) -> None:
        runner = _make_runner()

        with patch.object(runner, "run_eval") as mock_eval:
            results = runner.run_all([])

        mock_eval.assert_not_called()
        assert results == []


class TestEnsureEmailConfigured:
    @pytest.fixture(autouse=True)
    def _patch_subprocess(self) -> Generator[None]:
        self.mock_result = MagicMock()
        self.mock_result.stdout = ""
        self.mock_result.returncode = 0
        with patch(
            "pentester.auditors.promptfoo.runner.subprocess.run",
            return_value=self.mock_result,
        ) as self.mock_run:
            yield

    def test_sets_email(self) -> None:
        _make_runner().ensure_email_configured()

        self.mock_run.assert_called_once_with(
            ["promptfoo", "config", "set", "email", "tools@tekdatum.com"],
            capture_output=True,
            text=True,
        )

    def test_uses_custom_default_email(self) -> None:
        _make_runner(default_email="custom@example.com").ensure_email_configured()

        self.mock_run.assert_called_once_with(
            ["promptfoo", "config", "set", "email", "custom@example.com"],
            capture_output=True,
            text=True,
        )
