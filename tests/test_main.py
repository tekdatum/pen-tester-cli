"""Tests for src/pentester/main.py.

Auditor modules (garak, pyrit, inspect_ai) are stubbed via sys.modules so the
suite runs without the real packages installed.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Stub auditor modules so their heavy third-party imports never load.
# ---------------------------------------------------------------------------
for _mod in (
    "pentester.auditors.garak",
    "pentester.auditors.pyrit",
    "pentester.auditors.inspect_ai",
    "pyrit",
    "pyrit.datasets",
    "pyrit.executor",
    "pyrit.executor.attack",
    "pyrit.executor.attack.core",
    "pyrit.executor.attack.multi_turn",
    "pyrit.memory",
    "pyrit.models",
    "pyrit.models.attack_result",
    "pyrit.prompt_target",
    "pyrit.score",
    "pyrit.score.true_false",
    "pyrit.score.true_false.self_ask_true_false_scorer",
    "pyrit.setup",
    "inspect_ai",
):
    sys.modules.setdefault(_mod, MagicMock())

import click.testing  # noqa: E402

from pentester.config.settings import PentesterSettings  # noqa: E402
from pentester.enums.target_type import TargetType  # noqa: E402
from pentester.main import main  # noqa: E402


# ---------------------------------------------------------------------------
# TestMain
# ---------------------------------------------------------------------------


class TestMain:
    def test_calls_orchestrator_execute(self) -> None:
        mock_orchestrator = MagicMock()
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", return_value=mock_orchestrator):
            result = runner.invoke(main, [])
        assert result.exit_code == 0
        mock_orchestrator.execute.assert_called_once()

    def test_passes_settings_to_orchestrator(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, [])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        assert isinstance(called_settings, PentesterSettings)

    def test_target_type_sets_field(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, ["--target-type", "LLM"])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        assert called_settings.target_type == TargetType.LLM

    def test_curl_command_sets_field(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, ["--curl-command", "curl http://x"])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        assert called_settings.scanner.curl_command == "curl http://x"

    def test_generator_keys_sets_field(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, ["--generator-keys", "pdf,html"])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        assert called_settings.reporting.generator_keys == "pdf,html"

    def test_output_dir_path_sets_field(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, ["--output-dir-path", "/out/"])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        assert called_settings.reporting.output_dir_path == "/out/"

    def test_none_options_do_not_overwrite(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, [])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        default_settings = PentesterSettings()
        assert called_settings.target_type == TargetType.SEMANTIC_FENCE
        assert called_settings.scanner.curl_command is None
        assert (
            called_settings.reporting.output_dir_path
            == default_settings.reporting.output_dir_path
        )

    def test_curl_file_sets_field(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, ["--curl-file", "/path/to/cmd.curl"])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        assert called_settings.scanner.curl_file == "/path/to/cmd.curl"

    def test_custom_handler_sets_field(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, ["--custom-handler", "handler.py:MyHandler"])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        assert called_settings.scanner.custom_handler == "handler.py:MyHandler"

    def test_auditors_sets_field(self) -> None:
        mock_orchestrator_cls = MagicMock()
        mock_orchestrator_cls.return_value.execute.return_value = None
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
            result = runner.invoke(main, ["--auditors", "garak,pyrit"])
        assert result.exit_code == 0
        called_settings = mock_orchestrator_cls.call_args.args[0]
        assert called_settings.auditors == ["garak", "pyrit"]

    def test_exit_code_zero(self) -> None:
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator") as mock_orchestrator_cls:
            mock_orchestrator_cls.return_value.execute.return_value = None
            result = runner.invoke(main, ["--target-type", "LLM"])
        assert result.exit_code == 0


class TestAuditorsCLI:
    def test_auditors_calls_execute_auditors(self) -> None:
        mock_orchestrator = MagicMock()
        runner = click.testing.CliRunner()
        with patch(
            "pentester.main.Orchestrator", return_value=mock_orchestrator
        ):
            result = runner.invoke(main, ["--auditors", "promptfoo"])
        assert result.exit_code == 0
        mock_orchestrator.execute_auditors.assert_called_once_with(["promptfoo"])
        mock_orchestrator.execute.assert_not_called()

    def test_auditors_multiple_calls_execute_auditors(self) -> None:
        mock_orchestrator = MagicMock()
        runner = click.testing.CliRunner()
        with patch(
            "pentester.main.Orchestrator", return_value=mock_orchestrator
        ):
            result = runner.invoke(main, ["--auditors", "promptfoo,garak"])
        assert result.exit_code == 0
        mock_orchestrator.execute_auditors.assert_called_once_with(
            ["promptfoo", "garak"]
        )

    def test_no_auditors_calls_execute(self) -> None:
        mock_orchestrator = MagicMock()
        runner = click.testing.CliRunner()
        with patch(
            "pentester.main.Orchestrator", return_value=mock_orchestrator
        ):
            result = runner.invoke(main, [])
        assert result.exit_code == 0
        mock_orchestrator.execute.assert_called_once()
        mock_orchestrator.execute_auditors.assert_not_called()


# class TestPromptfooCLI:
#     def test_promptfoo_config_path_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-config-path", "./custom"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.config_path == "./custom"

#     def test_promptfoo_output_path_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-output-path", "./out"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.output_path == "./out"

#     def test_promptfoo_plugins_per_file_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-plugins-per-file", "3"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.plugins_per_file == 3

#     def test_promptfoo_max_test_files_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-max-test-files", "10"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.max_test_files == 10

#     def test_promptfoo_assertion_wrapper_path_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-assertion-wrapper-path", "assert.py"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.assertion_wrapper_path == "assert.py"

#     def test_promptfoo_replace_existing_file_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-replace-existing-file"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.replace_existing_file is True

#     def test_promptfoo_files_parallel_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-files-parallel", "5"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.files_parallel == 5

#     def test_promptfoo_internal_concurrency_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-internal-concurrency", "4"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.internal_concurrency == 4

#     def test_promptfoo_max_tests_sets_field(self) -> None:
#         mock_orchestrator_cls = MagicMock()
#         mock_orchestrator_cls.return_value.execute.return_value = None
#         runner = click.testing.CliRunner()
#         with patch("pentester.main.Orchestrator", mock_orchestrator_cls):
#             result = runner.invoke(
#                 main, ["--promptfoo-max-tests", "10"]
#             )
#         assert result.exit_code == 0
#         called_settings = mock_orchestrator_cls.call_args.args[0]
#         assert called_settings.promptfoo.max_tests == 10
