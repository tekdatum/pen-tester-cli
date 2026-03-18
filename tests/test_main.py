"""Tests for src/pentester/main.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import click.testing

from pentester.config.settings import PentesterSettings
from pentester.enums.target_type import TargetType
from pentester.main import main


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

    def test_exit_code_zero(self) -> None:
        runner = click.testing.CliRunner()
        with patch("pentester.main.Orchestrator") as mock_orchestrator_cls:
            mock_orchestrator_cls.return_value.execute.return_value = None
            result = runner.invoke(main, ["--target-type", "LLM"])
        assert result.exit_code == 0
