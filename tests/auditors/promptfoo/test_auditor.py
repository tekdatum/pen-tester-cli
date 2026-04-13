from __future__ import annotations

import copy
import os
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call, mock_open, patch

import pandas as pd
import pytest

from pentester.auditors.models.probe_result import ProbeResult
from pentester.auditors.promptfoo.auditor import PromptfooAuditor
from pentester.auditors.promptfoo.runner import PromptfooRunner
from pentester.config.auditors.promptfoo_settings import (
    KNOWN_MULTITURN_STRATEGIES,
    PromptfooSettings,
)
from pentester.config.settings import TargetType
from pentester.enums.auditor_key import AuditorKey
from pentester.scanners.request_handlers.curl_handlers.curl_handler import CurlHandler


_FAKE_CONFIG: dict[str, Any] = {
    "prompts": ["You are a helpful assistant"],
    "providers": [
        {"id": "http", "config": {"url": "http://example.com", "method": "POST"}}
    ],
    "redteam": {
        "strategies": [
            {"id": "basic"},
            {"id": "jailbreak"},
            {
                "id": "crescendo",
                "config": {
                    "maxTurns": 5,
                    "maxBacktracks": 5,
                    "stateful": False,
                    "continueAfterSuccess": False,
                },
            },
            {
                "id": "goat",
                "config": {
                    "maxTurns": 5,
                    "stateful": False,
                    "continueAfterSuccess": False,
                },
            },
            {"id": "crescendo", "config": {"maxTurns": 5}},
            {"id": "mischievous-user", "config": {"maxTurns": 5, "stateful": False}},
        ],
        "plugins": ["harmful:hate", "harmful:violent-crime"],
        "defaultAssertions": [{"type": "llm-rubric"}],
    },
    "defaultTest": {"assert": [{"type": "is-json"}]},
    "tests": [
        {"vars": {"input": "test1"}, "assert": [{"type": "is-json"}]},
        {"vars": {"input": "test2"}, "assert": [{"type": "is-json"}]},
    ],
    "commandLineOptions": {"maxConcurrency": 4},
    "metadata": {"version": "1.0"},
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(**kwargs: object) -> PromptfooSettings:
    defaults: dict[str, object] = {"config_path": "/tmp/promptfoo_test"}
    defaults.update(kwargs)
    return PromptfooSettings(**defaults)


def _make_auditor(
    settings: PromptfooSettings | None = None,
    scanner: object = None,
    target_type: TargetType = TargetType.SEMANTIC_FENCE,
) -> PromptfooAuditor:
    s = settings or _make_settings()
    with (
        patch("pathlib.Path.mkdir"),
        patch("builtins.open", mock_open(read_data="")),
        patch(
            "pentester.auditors.promptfoo.auditor.yaml.safe_load",
            return_value=copy.deepcopy(_FAKE_CONFIG),
        ),
    ):
        return PromptfooAuditor(settings=s, scanner=scanner, target_type=target_type)


# ---------------------------------------------------------------------------
# TestInit & TestEnsureDirectories
# ---------------------------------------------------------------------------


class TestInit:
    def test_initializes_with_explicit_settings(self) -> None:
        s = _make_settings(
            config_path="/custom", files_parallel=7, internal_concurrency=3
        )
        auditor = _make_auditor(s)

        assert auditor.settings is s
        assert auditor.runner.results_path == Path("./output/promptfoo") / "results"
        assert auditor.runner.files_parallel == 7
        assert auditor.runner.concurrency == 3
        assert auditor.collector.results_path == Path("./output/promptfoo") / "results"
        assert isinstance(auditor.results_df, pd.DataFrame)
        assert len(auditor.results_df) == 0

    def test_initializes_with_default_settings_when_none_provided(self) -> None:
        with (
            patch("pathlib.Path.mkdir"),
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
        ):
            auditor = PromptfooAuditor(settings=None)

        assert isinstance(auditor.settings, PromptfooSettings)

    def test_scanner_defaults_to_none(self) -> None:
        auditor = _make_auditor()
        assert auditor._scanner is None

    def test_scanner_is_stored_when_provided(self) -> None:
        mock_scanner = MagicMock()
        auditor = _make_auditor(scanner=mock_scanner)
        assert auditor._scanner is mock_scanner


class TestEnsureDirectories:
    def test_creates_required_directories_with_correct_flags(self) -> None:
        with (
            patch("pathlib.Path.mkdir") as mock_mkdir,
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
        ):
            PromptfooAuditor(settings=_make_settings())

        assert mock_mkdir.call_count == 4
        for call_obj in mock_mkdir.call_args_list:
            assert call_obj[1].get("parents") is True
            assert call_obj[1].get("exist_ok") is True


class TestLoadConfig:
    def test_extracts_all_expected_fields_from_yaml(self) -> None:
        auditor = _make_auditor()
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
        ):
            config = auditor._load_config(Path("/fake.yaml"))

        expected_keys = {
            "prompts",
            "providers",
            "redteam",
            "defaultTest",
            "tests",
            "commandLineOptions",
            "metadata",
        }
        assert set(config.keys()) == expected_keys
        assert config["prompts"] == _FAKE_CONFIG["prompts"]
        assert config["providers"] == _FAKE_CONFIG["providers"]
        assert config["metadata"] == {"version": "1.0"}

    def test_applies_defaults_for_missing_fields(self) -> None:
        auditor = _make_auditor()
        minimal_config = {
            "prompts": ["p"]
        }  # Missing providers and metadata, prompts supplied
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=minimal_config,
            ),
        ):
            config = auditor._load_config(Path("/fake.yaml"))

        assert config["providers"] is None
        assert config["metadata"] == {}

        # Test missing prompts specifically
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value={"providers": None},
            ),
        ):
            empty_prompts_config = auditor._load_config(Path("/fake.yaml"))
            assert empty_prompts_config["prompts"] == []


class TestOpenConfig:
    def test_sets_all_config_attributes(self) -> None:
        # _open_config is implicitly called during _make_auditor init
        auditor = _make_auditor()

        assert isinstance(auditor.config, dict)
        assert auditor.prompts == _FAKE_CONFIG["prompts"]
        assert auditor.providers == _FAKE_CONFIG["providers"]
        assert auditor.redteam == _FAKE_CONFIG["redteam"]
        assert auditor.defaultTest == _FAKE_CONFIG["defaultTest"]
        assert auditor.tests == _FAKE_CONFIG["tests"]
        assert auditor.commandLineOptions == _FAKE_CONFIG["commandLineOptions"]
        assert auditor.metadata == _FAKE_CONFIG["metadata"]


# ---------------------------------------------------------------------------
# Test Plugin Configs & Redteam Generation
# ---------------------------------------------------------------------------


class TestWritePluginConfigs:
    def test_writes_new_configs_with_correct_formatting(self, tmp_path: Path) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(["harmful:hate", "harmful:xss"], configs_dir)

        assert mock_dump.call_count == 2
        first_config = mock_dump.call_args_list[0][0][0]
        second_config = mock_dump.call_args_list[1][0][0]

        assert "metadata" not in first_config
        assert first_config["redteam"]["plugins"] == ["harmful:hate"]
        assert "defaultAssertions" not in first_config["redteam"]
        assert second_config["redteam"]["plugins"] == ["harmful:xss"]
        assert (configs_dir / "test_1.yaml").exists()
        assert (configs_dir / "test_2.yaml").exists()
        assert "defaultAssertions" in auditor.config["redteam"]  # original unchanged

    def test_warns_when_existing_file_has_different_plugin_count(
        self, tmp_path: Path
    ) -> None:
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        existing_file = configs_dir / "test_1.yaml"
        existing_file.write_text("placeholder")

        auditor = _make_auditor(
            _make_settings(plugins_per_file=1, replace_existing_file=False)
        )

        existing_config = copy.deepcopy(_FAKE_CONFIG)
        existing_config["redteam"]["plugins"] = [
            "harmful:hate",
            "harmful:xss",
        ]  # 2 plugins

        with (
            patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger,
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=existing_config,
            ),
        ):
            auditor._write_plugin_configs(["harmful:hate"], configs_dir)

        mock_logger.warning.assert_called_once()
        assert "differs from" in mock_logger.warning.call_args[0][0]

    def test_no_warning_when_existing_file_has_matching_plugin_count(
        self, tmp_path: Path
    ) -> None:
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        existing_file = configs_dir / "test_1.yaml"
        existing_file.write_text("placeholder")

        auditor = _make_auditor(
            _make_settings(plugins_per_file=1, replace_existing_file=False)
        )

        existing_config = copy.deepcopy(_FAKE_CONFIG)
        existing_config["redteam"]["plugins"] = [
            "harmful:hate"
        ]  # matches plugins_per_file=1

        with (
            patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger,
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=existing_config,
            ),
        ):
            auditor._write_plugin_configs(["harmful:hate"], configs_dir)

        mock_logger.warning.assert_not_called()
        mock_logger.info.assert_called()

    def test_handles_existing_files_based_on_replace_setting(
        self, tmp_path: Path
    ) -> None:
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        existing_file = configs_dir / "test_1.yaml"

        # Test replace = False — mock safe_load so _load_config returns a valid dict
        s_no_replace = _make_settings(replace_existing_file=False)
        existing_file.write_text("placeholder")
        on_disk = copy.deepcopy(_FAKE_CONFIG)
        on_disk["redteam"]["plugins"] = [
            "harmful:hate"
        ]  # 1 plugin matches default plugins_per_file
        with (
            patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump,
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=on_disk,
            ),
        ):
            _make_auditor(s_no_replace)._write_plugin_configs(
                ["harmful:hate"], configs_dir
            )
            mock_dump.assert_not_called()

        # Test replace = True
        s_replace = _make_settings(replace_existing_file=True)
        existing_file.write_text("old data")
        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            _make_auditor(s_replace)._write_plugin_configs(
                ["harmful:hate"], configs_dir
            )
            mock_dump.assert_called()


class TestWritePluginConfigsChunking:
    def test_plugins_per_file_chunks_correctly(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(plugins_per_file=2))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        plugins = ["a", "b", "c", "d", "e"]

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(plugins, configs_dir)

        assert mock_dump.call_count == 3  # ceil(5/2) = 3
        assert mock_dump.call_args_list[0][0][0]["redteam"]["plugins"] == ["a", "b"]
        assert mock_dump.call_args_list[1][0][0]["redteam"]["plugins"] == ["c", "d"]
        assert mock_dump.call_args_list[2][0][0]["redteam"]["plugins"] == ["e"]

    def test_max_test_files_caps_output(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(max_test_files=2))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        plugins = ["a", "b", "c", "d", "e"]

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(plugins, configs_dir)

        assert mock_dump.call_count == 2
        assert mock_dump.call_args_list[0][0][0]["redteam"]["plugins"] == ["a"]
        assert mock_dump.call_args_list[1][0][0]["redteam"]["plugins"] == ["b"]

    def test_plugins_per_file_and_max_test_files_combined(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(plugins_per_file=2, max_test_files=1))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        plugins = ["a", "b", "c", "d"]

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(plugins, configs_dir)

        assert mock_dump.call_count == 1
        assert mock_dump.call_args_list[0][0][0]["redteam"]["plugins"] == ["a", "b"]

    def test_max_test_files_none_generates_all(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(max_test_files=None))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        plugins = ["a", "b", "c"]

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(plugins, configs_dir)

        assert mock_dump.call_count == 3


class TestRunRedteamGenerateForConfigs:
    def test_calls_runner_for_all_configs_handling_replace_setting(
        self, tmp_path: Path
    ) -> None:
        configs_dir = tmp_path / "configurations"
        llm_dir = tmp_path / "llm_assert"
        configs_dir.mkdir()
        llm_dir.mkdir()

        (configs_dir / "test_1.yaml").write_text("data")
        (configs_dir / "test_2.yaml").write_text("data")

        # Setup auditor
        auditor = _make_auditor(_make_settings(replace_existing_file=False))
        auditor.runner = MagicMock()

        # If replace is false and output exists, it should skip.
        (llm_dir / "test_1.yaml").write_text("existing output")

        auditor._run_redteam_generate_for_configs(configs_dir, llm_dir)

        # test_1 was skipped, test_2 was generated
        assert auditor.runner.run_redteam_generate.call_count == 1
        call_args = auditor.runner.run_redteam_generate.call_args
        assert call_args[0][1] == llm_dir / "test_2.yaml"


class TestRemoveCloudOnlyTests:
    def test_removes_jailbreak_meta_tests_from_yaml(self, tmp_path: Path) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        llm_dir = tmp_path / "llm_assert"
        llm_dir.mkdir()

        config_with_mixed = {
            "prompts": ["p"],
            "providers": None,
            "redteam": [],
            "defaultTest": [],
            "tests": [
                {"vars": {"input": "a"}, "metadata": {"strategyId": "jailbreak:meta"}},
                {"vars": {"input": "b"}, "metadata": {"strategyId": "other"}},
                {"vars": {"input": "c"}, "metadata": {"strategyId": "jailbreak:meta"}},
            ],
            "commandLineOptions": [],
            "metadata": {},
        }
        with open(llm_dir / "test_1.yaml", "w") as f:
            import yaml

            yaml.dump(config_with_mixed, f)

        auditor._remove_cloud_only_tests(llm_dir)

        with open(llm_dir / "test_1.yaml") as f:
            result = yaml.safe_load(f)
        assert len(result["tests"]) == 1
        assert result["tests"][0]["vars"]["input"] == "b"

    def test_skips_file_when_no_jailbreak_meta_tests(self, tmp_path: Path) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        llm_dir = tmp_path / "llm_assert"
        llm_dir.mkdir()

        config_no_meta = {
            "prompts": ["p"],
            "providers": None,
            "redteam": [],
            "defaultTest": [],
            "tests": [
                {"vars": {"input": "a"}, "metadata": {"strategyId": "other"}},
            ],
            "commandLineOptions": [],
            "metadata": {},
        }
        file_path = llm_dir / "test_1.yaml"
        import yaml

        with open(file_path, "w") as f:
            yaml.dump(config_no_meta, f)

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._remove_cloud_only_tests(llm_dir)
            mock_dump.assert_not_called()

    def test_handles_tests_without_metadata(self, tmp_path: Path) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        llm_dir = tmp_path / "llm_assert"
        llm_dir.mkdir()

        config = {
            "prompts": ["p"],
            "providers": None,
            "redteam": [],
            "defaultTest": [],
            "tests": [
                {"vars": {"input": "a"}},
                {"vars": {"input": "b"}, "metadata": {}},
                {"vars": {"input": "c"}, "metadata": {"strategyId": "jailbreak:meta"}},
            ],
            "commandLineOptions": [],
            "metadata": {},
        }
        import yaml

        with open(llm_dir / "test_1.yaml", "w") as f:
            yaml.dump(config, f)

        auditor._remove_cloud_only_tests(llm_dir)

        with open(llm_dir / "test_1.yaml") as f:
            result = yaml.safe_load(f)
        assert len(result["tests"]) == 2
        assert result["tests"][0]["vars"]["input"] == "a"
        assert result["tests"][1]["vars"]["input"] == "b"

    def test_logs_removal_count(self, tmp_path: Path) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        llm_dir = tmp_path / "llm_assert"
        llm_dir.mkdir()

        config = {
            "prompts": ["p"],
            "providers": None,
            "redteam": [],
            "defaultTest": [],
            "tests": [
                {"vars": {"input": "a"}, "metadata": {"strategyId": "jailbreak:meta"}},
                {"vars": {"input": "b"}, "metadata": {"strategyId": "jailbreak:meta"}},
                {"vars": {"input": "c"}, "metadata": {"strategyId": "other"}},
            ],
            "commandLineOptions": [],
            "metadata": {},
        }
        import yaml

        with open(llm_dir / "test_1.yaml", "w") as f:
            yaml.dump(config, f)

        with patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger:
            auditor._remove_cloud_only_tests(llm_dir)

        mock_logger.info.assert_any_call(
            "Removed %d jailbreak:meta test(s) from %s",
            2,
            "test_1.yaml",
        )


class TestGenerateTestsFiles:
    def test_orchestrates_plugin_writing_and_generation(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_write_plugin_configs") as mock_write,
            patch.object(auditor, "_run_redteam_generate_for_configs") as mock_gen,
            patch.object(
                auditor, "_configure_provider_in_test_files"
            ),
        ):
            auditor.generate_tests_files()

        mock_write.assert_called_once()
        assert mock_write.call_args[0][0] == _FAKE_CONFIG["redteam"]["plugins"]
        mock_gen.assert_called_once()

    def test_configures_provider_in_configurations_and_llm_assert_dirs(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_write_plugin_configs"),
            patch.object(auditor, "_run_redteam_generate_for_configs"),
            patch.object(
                auditor, "_configure_provider_in_test_files"
            ) as mock_configure,
        ):
            auditor.generate_tests_files()

        configurations_dir = auditor.settings.tests_path / "configurations"
        llm_assert_dir = auditor.settings.tests_path / "llm_as_judge_assert"
        assert mock_configure.call_count == 2
        mock_configure.assert_any_call(configurations_dir)
        mock_configure.assert_any_call(llm_assert_dir)

    def test_calls_remove_cloud_only_tests_for_llm_target(self) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with (
            patch.object(auditor, "_write_plugin_configs"),
            patch.object(auditor, "_configure_provider_in_test_files"),
            patch.object(auditor, "_run_redteam_generate_for_configs"),
            patch.object(auditor, "_remove_cloud_only_tests") as mock_remove,
        ):
            auditor.generate_tests_files()

        mock_remove.assert_called_once_with(
            auditor.settings.tests_path / "llm_as_judge_assert"
        )

    def test_does_not_call_remove_cloud_only_tests_for_semantic_fence(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with (
            patch.object(auditor, "_write_plugin_configs"),
            patch.object(auditor, "_configure_provider_in_test_files"),
            patch.object(auditor, "_run_redteam_generate_for_configs"),
            patch.object(auditor, "_remove_cloud_only_tests") as mock_remove,
        ):
            auditor.generate_tests_files()

        mock_remove.assert_not_called()


# ---------------------------------------------------------------------------
# Test Providers & Config Cleaning
# ---------------------------------------------------------------------------


class TestProviders:
    def test_sets_html_provider_correctly(self) -> None:
        auditor = _make_auditor()
        new_config = {"url": "http://new.com", "method": "GET"}
        auditor._set_html_provider(new_config)
        assert auditor.providers[0]["id"] == "http"
        assert auditor.providers[0]["config"] == new_config

    def test_sets_https_provider_id_for_https_url(self) -> None:
        auditor = _make_auditor()
        new_config = {"url": "https://secure.com", "method": "GET"}
        auditor._set_html_provider(new_config)
        assert auditor.providers[0]["config"] == new_config

    def test_retrieves_http_provider_correctly(self) -> None:
        from pentester.auditors.promptfoo.http_provider import PromptfooHTTPProvider

        auditor = _make_auditor()

        # Mix of valid and invalid providers
        auditor.config["providers"] = [
            {"id": "openai", "config": {}},
            {"id": "http", "config": {"url": "http://example.com"}},
        ]

        providers = auditor.get_providers()
        assert len(providers) == 1
        assert isinstance(providers["http"], PromptfooHTTPProvider)

    def test_returns_empty_dict_when_no_http_provider(self) -> None:
        auditor = _make_auditor()
        auditor.config["providers"] = [{"id": "openai", "config": {}}]
        assert auditor.get_providers() == {}


class TestSetProviderFromScanner:
    def test_custom_handler_sets_file_provider_id(self) -> None:
        auditor = _make_auditor()
        scanner = MagicMock()
        scanner.request_handler = MagicMock()
        scanner.custom_handler = "path/to/file.py:MyHandler"

        auditor._set_provider_from_scanner(scanner)

        expected_path = Path("path/to/file.py:MyHandler").resolve().as_posix()
        assert len(auditor.providers) == 1
        assert auditor.providers[0] == {
            "id": f"file://{expected_path}.promptfoo_call_api"
        }
        assert "config" not in auditor.providers[0]

    def test_non_curl_without_custom_handler_leaves_providers_unchanged(self) -> None:
        auditor = _make_auditor()
        original_providers = auditor.providers
        scanner = MagicMock()
        scanner.request_handler = MagicMock()
        scanner.custom_handler = None

        auditor._set_provider_from_scanner(scanner)

        assert auditor.providers is original_providers

    def test_curl_handler_sets_http_provider(self) -> None:
        auditor = _make_auditor()
        scanner = MagicMock()
        handler = MagicMock(spec=CurlHandler)
        parsed = MagicMock(
            url="http://test.com",
            method="POST",
            headers={"Content-Type": "application/json"},
            data='{"text":"$PROMPT"}',
        )
        handler._parse_command.return_value = parsed
        handler.curl_command = "curl http://test.com"
        scanner.request_handler = handler

        auditor._set_provider_from_scanner(scanner)

        assert auditor.providers[0]["id"] == "http"
        assert auditor.providers[0]["config"]["url"] == "http://test.com"
        assert auditor.providers[0]["config"]["method"] == "POST"

    def test_curl_handler_no_providers_skips_setup(self) -> None:
        auditor = _make_auditor()
        auditor.providers = []
        scanner = MagicMock()
        scanner.request_handler = MagicMock(spec=CurlHandler)

        auditor._set_provider_from_scanner(scanner)

        assert auditor.providers == []


class TestConfigureProviderInTestFiles:
    def test_custom_handler_replaces_providers_in_yaml(self, tmp_path: Path) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        auditor.provider_id = "file://handler.py:H.promptfoo_call_api"
        auditor.providers = [{"id": "file://handler.py:H.promptfoo_call_api"}]

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        auditor._configure_provider_in_test_files(cfg_dir)

        import yaml

        result = yaml.safe_load((cfg_dir / "test_1.yaml").read_text())
        assert result["providers"] == [{"id": "file://handler.py:H.promptfoo_call_api"}]

    def test_http_provider_updates_config_in_yaml(self, tmp_path: Path) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        auditor.provider_id = "http"
        auditor.providers = [
            {"id": "http", "config": {"url": "http://new.com", "method": "POST"}}
        ]

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        auditor._configure_provider_in_test_files(cfg_dir)

        import yaml

        result = yaml.safe_load((cfg_dir / "test_1.yaml").read_text())
        assert result["providers"][0]["id"] == "http"
        assert result["providers"][0]["config"]["url"] == "http://new.com"

    def test_http_provider_updates_id_to_https_in_yaml(self, tmp_path: Path) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        auditor.provider_id = "https"
        auditor.providers = [
            {"id": "https", "config": {"url": "https://new.com", "method": "POST"}}
        ]

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        auditor._configure_provider_in_test_files(cfg_dir)

        import yaml

        result = yaml.safe_load((cfg_dir / "test_1.yaml").read_text())
        assert result["providers"][0]["id"] == "https"
        assert result["providers"][0]["config"]["url"] == "https://new.com"

    def test_applies_custom_handler_to_all_yaml_files(self, tmp_path: Path) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        auditor.provider_id = "file://h.py:H.promptfoo_call_api"
        auditor.providers = [{"id": "file://h.py:H.promptfoo_call_api"}]

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        for name in ["test_1.yaml", "test_2.yaml", "multiturn_test_1.yaml"]:
            (cfg_dir / name).write_text(yaml_content)

        auditor._configure_provider_in_test_files(cfg_dir)

        import yaml

        for name in ["test_1.yaml", "test_2.yaml", "multiturn_test_1.yaml"]:
            result = yaml.safe_load((cfg_dir / name).read_text())
            assert result["providers"] == [{"id": "file://h.py:H.promptfoo_call_api"}]

    def test_skips_when_no_scanner(self, tmp_path: Path) -> None:
        auditor = _make_auditor()
        auditor._scanner = None

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        auditor._configure_provider_in_test_files(cfg_dir)

        content = (cfg_dir / "test_1.yaml").read_text()
        assert "http://old.com" in content

    def test_skips_when_no_providers(self, tmp_path: Path) -> None:
        auditor = _make_auditor()
        auditor._scanner = MagicMock()
        auditor.providers = []

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        auditor._configure_provider_in_test_files(cfg_dir)

        content = (cfg_dir / "test_1.yaml").read_text()
        assert "http://old.com" in content


class TestCleanConfig:
    def test_raises_error_for_llm_target_type(self, tmp_path: Path) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with pytest.raises(Exception, match="not allowed"):
            auditor.clean_config(Path("/test.yaml"), tmp_path / "output")

    def test_cleans_and_writes_config_correctly(self, tmp_path: Path) -> None:
        auditor = _make_auditor(_make_settings(assertion_wrapper_path="/my/assert.py"))
        output = tmp_path / "output"
        output.mkdir()
        (output / "test.yaml").write_text("old")

        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
            patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump,
        ):
            auditor.clean_config(Path("/test.yaml"), output)

        assert output.exists()
        written = mock_dump.call_args[0][0]
        for test in written["tests"]:
            assert test["assert"][0]["type"] == "python"
            assert "/my/assert.py" in test["assert"][0]["value"]

    def test_handles_existing_files_based_on_replace_setting(
        self, tmp_path: Path
    ) -> None:
        output = tmp_path / "output"
        output.mkdir()
        (output / "test.yaml").write_text("old")

        # For SEMANTIC_FENCE, clean_config rewrites regardless of replace_existing_file
        auditor_no_replace = _make_auditor(_make_settings(replace_existing_file=False))
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.auditor.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
            patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump,
        ):
            auditor_no_replace.clean_config(Path("/test.yaml"), output)
            mock_dump.assert_called()


# ---------------------------------------------------------------------------
# Test Audit Preparation & Results Processing
# ---------------------------------------------------------------------------


class TestPrepareAuditFiles:
    def test_raises_error_when_no_yaml_files_found(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(output_path=str(tmp_path)), target_type=TargetType.LLM
        )
        (tmp_path / "tests" / "llm_as_judge_assert").mkdir(parents=True, exist_ok=True)

        with pytest.raises(FileNotFoundError):
            auditor._prepare_audit_files()

    def test_prepares_semantic_fence_files(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(output_path=str(tmp_path)),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        llm_dir = tmp_path / "tests" / "llm_as_judge_assert"
        custom_dir = tmp_path / "tests" / "custom_assert"
        llm_dir.mkdir(parents=True, exist_ok=True)
        custom_dir.mkdir(parents=True, exist_ok=True)

        (llm_dir / "test_1.yaml").write_text("data")
        (custom_dir / "test_1.yaml").write_text("cleaned")

        with (
            patch.object(auditor, "clean_config") as mock_clean,
            patch.object(
                auditor, "_configure_provider_in_test_files"
            ) as mock_configure,
        ):
            files = auditor._prepare_audit_files()

        mock_clean.assert_called_once()
        mock_configure.assert_called_once_with(custom_dir)
        assert all(str(f).startswith(str(custom_dir)) for f in files)

    def test_configures_provider_in_custom_assert_dir(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(output_path=str(tmp_path)),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        llm_dir = tmp_path / "tests" / "llm_as_judge_assert"
        custom_dir = tmp_path / "tests" / "custom_assert"
        llm_dir.mkdir(parents=True, exist_ok=True)
        custom_dir.mkdir(parents=True, exist_ok=True)

        (llm_dir / "test_1.yaml").write_text("data")
        (custom_dir / "test_1.yaml").write_text("cleaned")

        with (
            patch.object(auditor, "clean_config"),
            patch.object(
                auditor, "_configure_provider_in_test_files"
            ) as mock_configure,
        ):
            auditor._prepare_audit_files()

        mock_configure.assert_called_once_with(custom_dir)

    def test_prepares_llm_target_files(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(output_path=str(tmp_path)), target_type=TargetType.LLM
        )
        llm_dir = tmp_path / "tests" / "llm_as_judge_assert"
        llm_dir.mkdir(parents=True, exist_ok=True)
        (llm_dir / "test_1.yaml").write_text("data")

        files = auditor._prepare_audit_files()
        assert len(files) == 1
        assert files[0].parent == llm_dir


class TestProcessEvalResults:
    def test_validates_successful_evaluations_only(self) -> None:
        auditor = _make_auditor()
        auditor.collector = MagicMock()
        results = [
            (Path("/a.yaml"), True, "a.yaml", "ok"),
            (Path("/b.yaml"), False, "b.yaml", "error"),
            (Path("/c.yaml"), True, "c.yaml", "ok"),
        ]

        with patch.object(auditor, "_load_config", return_value={"tests": [1, 2]}):
            auditor._process_eval_results(results)

        # Only validates the 2 successful ones. Each yaml loaded had 2 tests.
        assert auditor.collector.validate.call_count == 2
        assert (
            auditor.collector.validate.call_args_list[0][0][2] == 2
        )  # Checks test count is passed


# ---------------------------------------------------------------------------
# Test Probe Results Generation
# ---------------------------------------------------------------------------


class TestGenerateProbeResults:
    def _make_results_df(self, **overrides: object) -> pd.DataFrame:
        row: dict = {
            "reason_code": "category_0",
            "prompt": "my_prompt",
            "api_response": {"data": "response_data"},
            "valid": True,
            "accept_score": 0.9,
            "http_status": 200,
            "duration": 1.5,
            "latency_ms": 100,
            "cached": False,
            "strategy_id": "jailbreak-templates",
            "plugin_id": "competitors",
            "error": None,
            "success": True,
            "grading_score": 1.0,
            "grading_reason": "All assertions passed",
        }
        row.update(overrides)
        return pd.DataFrame([row])

    def test_maps_dataframe_rows_to_probe_results_correctly(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df()

        results = auditor._generate_probe_results()

        assert len(results) == 1
        res = results[0]
        assert isinstance(res, ProbeResult)
        assert res.auditor == "promptfoo"
        assert res.attack_category == "jailbreak-templates"
        assert res.attack_type == "competitors"
        assert res.prompt == "my_prompt"
        assert "response_data" in res.response
        assert res.bypassed is False
        assert res.score == 1.0
        assert res.metadata == {
            "http_status": 200,
            "duration": 1.5,
            "latency_ms": 100,
            "cached": False,
            "error": None,
            "grading_reason": "All assertions passed",
            "is_multiturn": False,
        }

    def test_attack_category_defaults_to_basic_when_strategy_id_is_none(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(strategy_id=None)

        results = auditor._generate_probe_results()

        assert results[0].attack_category == "basic"
        assert results[0].attack_type == "competitors"

    def test_returns_empty_list_for_empty_dataframe(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = pd.DataFrame()
        assert auditor._generate_probe_results() == []

    def test_score_defaults_to_zero_when_accept_score_is_none(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(
            grading_score=None, accept_score=None
        )

        results = auditor._generate_probe_results()

        assert results[0].score == 0.0

    def test_error_included_in_metadata(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(error="some error")

        results = auditor._generate_probe_results()

        assert results[0].metadata["error"] == "some error"

    def test_no_error_metadata_is_none(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(error=None)

        results = auditor._generate_probe_results()

        assert results[0].metadata["error"] is None

    def test_bypassed_is_false_when_error_present(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(
            success=False, error="HTTP 422 error"
        )

        results = auditor._generate_probe_results()

        assert results[0].bypassed is False

    def test_bypassed_is_true_when_success_false_and_no_error(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(success=False, error=None)

        results = auditor._generate_probe_results()

        assert results[0].bypassed is True

    def test_bypassed_is_false_when_success_true(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = self._make_results_df(success=True, error=None)

        results = auditor._generate_probe_results()

        assert results[0].bypassed is False


# ---------------------------------------------------------------------------
# Test Pre-audit Precondition Validation
# ---------------------------------------------------------------------------


class TestValidatePreconditions:
    @pytest.fixture(autouse=True)
    def _patch_ensure_email(self) -> Generator[None, None, None]:
        with patch.object(PromptfooRunner, "ensure_email_configured"):
            yield

    def test_semantic_fence_passes_when_assert_file_exists(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with patch("pathlib.Path.exists", return_value=True):
            auditor._validate_preconditions()  # should not raise

    def test_semantic_fence_raises_when_assert_file_missing(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(ValueError, match="Assert file not found"):
                auditor._validate_preconditions()

    def test_llm_passes_when_openai_key_is_set(self) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
            auditor._validate_preconditions()  # should not raise

    def test_llm_passes_when_any_known_key_is_set(self) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=True):
            auditor._validate_preconditions()  # should not raise

    def test_llm_raises_when_no_key_is_set(self) -> None:
        auditor = _make_auditor(target_type=TargetType.LLM)
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="No LLM API key found"):
                auditor._validate_preconditions()

    def test_semantic_fence_unsets_llm_api_keys(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch.dict(
                os.environ,
                {"OPENAI_API_KEY": "sk-test", "ANTHROPIC_API_KEY": "sk-ant"},
                clear=True,
            ),
        ):
            auditor._unset_llm_api_keys()

            assert "OPENAI_API_KEY" not in os.environ
            assert "ANTHROPIC_API_KEY" not in os.environ
            assert auditor._saved_llm_keys == {
                "OPENAI_API_KEY": "sk-test",
                "ANTHROPIC_API_KEY": "sk-ant",
            }

    def test_semantic_fence_does_not_fail_when_no_keys_present(self) -> None:
        auditor = _make_auditor(target_type=TargetType.SEMANTIC_FENCE)
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch.dict(os.environ, {}, clear=True),
        ):
            auditor._unset_llm_api_keys()
            assert auditor._saved_llm_keys == {}


class TestRestoreLlmApiKeys:
    def test_restores_saved_keys_to_environment(self) -> None:
        auditor = _make_auditor()
        auditor._saved_llm_keys = {"OPENAI_API_KEY": "sk-restored"}

        with patch.dict(os.environ, {}, clear=True):
            auditor._restore_llm_api_keys()

            assert os.environ["OPENAI_API_KEY"] == "sk-restored"
            assert auditor._saved_llm_keys == {}

    def test_noop_when_no_saved_keys(self) -> None:
        auditor = _make_auditor()
        with patch.dict(os.environ, {}, clear=True):
            auditor._restore_llm_api_keys()  # should not raise
            assert auditor._saved_llm_keys == {}


# ---------------------------------------------------------------------------
# Test Audit Pipeline orchestration
# ---------------------------------------------------------------------------


class TestAudit:
    def test_executes_full_audit_pipeline(self) -> None:
        auditor = _make_auditor()
        files = [Path("/a.yaml")]
        runner_output = [(Path("/a.yaml"), True, "a.yaml", "ok")]
        expected_df = pd.DataFrame({"col": [1]})
        expected_probes = [MagicMock(spec=ProbeResult)]

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files") as mock_gen,
            patch.object(auditor.collector, "clean") as mock_clean,
            patch.object(
                auditor, "_prepare_audit_files", return_value=files
            ) as mock_prep,
            patch.object(
                auditor.runner, "run_all", return_value=runner_output
            ) as mock_run,
            patch.object(auditor, "_process_eval_results") as mock_proc,
            patch.object(
                auditor.collector, "build_dataframe", return_value=expected_df
            ) as mock_build,
            patch.object(
                auditor, "_generate_probe_results", return_value=expected_probes
            ) as mock_gen_probes,
        ):
            result, _ = auditor.audit()

        mock_gen.assert_called_once()
        mock_clean.assert_called_once()
        mock_prep.assert_called_once()
        mock_run.assert_called_once_with(files)
        mock_proc.assert_called_once_with(runner_output)
        mock_build.assert_called_once()
        mock_gen_probes.assert_called_once()

        assert auditor.results_df is expected_df
        assert result is expected_probes

    def test_returns_empty_list_when_no_results(self) -> None:
        auditor = _make_auditor()
        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(auditor, "_prepare_audit_files", return_value=[]),
            patch.object(auditor.runner, "run_all", return_value=[]),
            patch.object(auditor, "_process_eval_results"),
            patch.object(
                auditor.collector, "build_dataframe", return_value=pd.DataFrame()
            ),
            patch.object(auditor, "_generate_probe_results", return_value=[]),
        ):
            result, _ = auditor.audit()
            assert result == []

    def test_builds_dataframe_and_logs_errors_when_all_evals_failed(self) -> None:
        auditor = _make_auditor()
        all_failed = [
            (Path("/a.yaml"), False, "a.yaml", "error A"),
            (Path("/b.yaml"), False, "b.yaml", "error B"),
        ]
        expected_df = pd.DataFrame({"col": [1]})
        error_probe = MagicMock(spec=ProbeResult)
        error_probe.is_error = True
        error_probe.attack_category = "cat"
        error_probe.attack_type = "type"
        error_probe.metadata = {"error": "something went wrong"}

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(
                auditor,
                "_prepare_audit_files",
                return_value=[Path("/a.yaml"), Path("/b.yaml")],
            ),
            patch.object(auditor.runner, "run_all", return_value=all_failed),
            patch.object(auditor, "_process_eval_results"),
            patch.object(
                auditor.collector, "build_dataframe", return_value=expected_df
            ) as mock_build,
            patch.object(
                auditor, "_generate_probe_results", return_value=[error_probe]
            ) as mock_gen_probes,
            patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger,
        ):
            result, _ = auditor.audit()

        assert mock_build.call_count == 1
        assert mock_gen_probes.call_count == 2
        mock_logger.error.assert_called_once_with(
            "Probe error — category: %s | type: %s | error: %s",
            "cat",
            "type",
            "something went wrong",
        )
        assert result == [error_probe]
        assert auditor.results_df is expected_df

    def test_no_error_logs_when_all_evals_failed_but_no_error_probes(self) -> None:
        auditor = _make_auditor()
        all_failed = [
            (Path("/a.yaml"), False, "a.yaml", "error A"),
        ]
        non_error_probe = MagicMock(spec=ProbeResult)
        non_error_probe.is_error = False

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(
                auditor, "_prepare_audit_files", return_value=[Path("/a.yaml")]
            ),
            patch.object(auditor.runner, "run_all", return_value=all_failed),
            patch.object(auditor, "_process_eval_results"),
            patch.object(
                auditor.collector, "build_dataframe", return_value=pd.DataFrame()
            ),
            patch.object(
                auditor, "_generate_probe_results", return_value=[non_error_probe]
            ),
            patch("pentester.auditors.promptfoo.auditor.logger") as mock_logger,
        ):
            result, _ = auditor.audit()

        mock_logger.error.assert_not_called()
        assert result == [non_error_probe]

    def test_calls_build_dataframe_when_at_least_one_eval_succeeded(self) -> None:
        auditor = _make_auditor()
        mixed_results = [
            (Path("/a.yaml"), True, "a.yaml", "ok"),
            (Path("/b.yaml"), False, "b.yaml", "error B"),
        ]
        expected_df = pd.DataFrame({"col": [1]})
        expected_probes = [MagicMock(spec=ProbeResult)]

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(
                auditor,
                "_prepare_audit_files",
                return_value=[Path("/a.yaml"), Path("/b.yaml")],
            ),
            patch.object(auditor.runner, "run_all", return_value=mixed_results),
            patch.object(auditor, "_process_eval_results"),
            patch.object(
                auditor.collector, "build_dataframe", return_value=expected_df
            ) as mock_build,
            patch.object(
                auditor, "_generate_probe_results", return_value=expected_probes
            ),
        ):
            result, _ = auditor.audit()

        mock_build.assert_called_once()
        assert result is expected_probes


# ---------------------------------------------------------------------------
# Multi-turn Strategy Tests
# ---------------------------------------------------------------------------


class TestStripMultiturnStrategies:
    def test_strips_multiturn_keeps_single_turn(self) -> None:
        result = PromptfooAuditor._strip_multiturn_strategies(
            copy.deepcopy(_FAKE_CONFIG)
        )
        ids = {s["id"] for s in result["redteam"]["strategies"]}
        assert ids == {"basic", "jailbreak"}

    def test_does_not_mutate_input(self) -> None:
        original = copy.deepcopy(_FAKE_CONFIG)
        original_count = len(original["redteam"]["strategies"])
        PromptfooAuditor._strip_multiturn_strategies(original)
        assert len(original["redteam"]["strategies"]) == original_count

    def test_handles_empty_strategies_list(self) -> None:
        config = copy.deepcopy(_FAKE_CONFIG)
        config["redteam"]["strategies"] = []
        result = PromptfooAuditor._strip_multiturn_strategies(config)
        assert result["redteam"]["strategies"] == []


class TestApplyMultiturnOverrides:
    def test_filters_to_allowlist(self) -> None:
        auditor = _make_auditor(
            _make_settings(
                enable_multiturn=True,
                multiturn_strategies=["crescendo", "goat"],
            )
        )
        result = auditor._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        mt_ids = {
            s["id"]
            for s in result["redteam"]["strategies"]
            if s["id"] in KNOWN_MULTITURN_STRATEGIES
        }
        assert mt_ids == {"crescendo", "goat"}

    def test_keeps_all_single_turn_strategies(self) -> None:
        auditor = _make_auditor(
            _make_settings(
                enable_multiturn=True,
                multiturn_strategies=["crescendo", "goat", "mischievous-user"],
            )
        )
        result = auditor._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        ids = [s["id"] for s in result["redteam"]["strategies"]]
        assert "goat" in ids
        assert "crescendo" in ids

    def test_patches_max_turns(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True, multiturn_max_turns=10)
        )
        result = auditor._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        for s in result["redteam"]["strategies"]:
            if s["id"] in KNOWN_MULTITURN_STRATEGIES:
                assert s["config"]["maxTurns"] == 10

    def test_patches_crescendo_specific_fields(self) -> None:
        auditor = _make_auditor(
            _make_settings(
                enable_multiturn=True,
                multiturn_max_backtracks=3,
                multiturn_stateful=True,
            )
        )
        result = auditor._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        crescendo = next(
            s for s in result["redteam"]["strategies"] if s["id"] == "crescendo"
        )
        assert crescendo["config"]["maxBacktracks"] == 3
        assert crescendo["config"]["stateful"] is True
        assert crescendo["config"]["continueAfterSuccess"] is False

    def test_patches_crescendo_continue_after_success_true(self) -> None:
        auditor = _make_auditor(
            _make_settings(
                enable_multiturn=True,
                multiturn_continue_after_success=True,
            )
        )
        result = auditor._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        crescendo = next(
            s for s in result["redteam"]["strategies"] if s["id"] == "crescendo"
        )
        assert crescendo["config"]["continueAfterSuccess"] is True

    def test_patches_goat_specific_fields(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True, multiturn_stateful=True)
        )
        result = auditor._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        goat = next(s for s in result["redteam"]["strategies"] if s["id"] == "goat")
        assert goat["config"]["stateful"] is True
        assert goat["config"]["continueAfterSuccess"] is False

    def test_patches_goat_continue_after_success_true(self) -> None:
        auditor = _make_auditor(
            _make_settings(
                enable_multiturn=True,
                multiturn_continue_after_success=True,
            )
        )
        result = auditor._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        goat = next(s for s in result["redteam"]["strategies"] if s["id"] == "goat")
        assert goat["config"]["continueAfterSuccess"] is True

    def test_mischievous_user_includes_stateful(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True, multiturn_stateful=True)
        )
        result = auditor._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        mu = next(
            s for s in result["redteam"]["strategies"] if s["id"] == "mischievous-user"
        )
        assert mu["config"]["stateful"] is True
        assert "continueAfterSuccess" not in mu["config"]

    def test_does_not_mutate_input(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True, multiturn_max_turns=10)
        )
        original = copy.deepcopy(_FAKE_CONFIG)
        crescendo_before = next(
            s for s in original["redteam"]["strategies"] if s["id"] == "crescendo"
        )
        original_max = crescendo_before["config"]["maxTurns"]
        auditor._apply_multiturn_overrides(original)
        crescendo_after = next(
            s for s in original["redteam"]["strategies"] if s["id"] == "crescendo"
        )
        assert crescendo_after["config"]["maxTurns"] == original_max


class TestWritePluginConfigsMultiturn:
    def test_generates_multiturn_files_when_enabled(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True), target_type=TargetType.LLM
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(["harmful:hate"], configs_dir)

        # 1 single-turn + 1 multiturn = 2 dumps
        assert mock_dump.call_count == 2
        mt_config = mock_dump.call_args_list[1][0][0]
        strategy_ids = [s["id"] for s in mt_config["redteam"]["strategies"]]
        assert "crescendo" in strategy_ids

    def test_single_turn_file_has_no_multiturn_strategies(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True), target_type=TargetType.LLM
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(["harmful:hate"], configs_dir)

        st_config = mock_dump.call_args_list[0][0][0]
        st_ids = {s["id"] for s in st_config["redteam"]["strategies"]}
        assert st_ids.isdisjoint(KNOWN_MULTITURN_STRATEGIES)

    def test_multiturn_file_has_correct_prefix(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True), target_type=TargetType.LLM
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump"):
            auditor._write_plugin_configs(["harmful:hate"], configs_dir)

        files = list(configs_dir.glob("*.yaml"))
        names = {f.name for f in files}
        assert "test_1.yaml" in names
        assert "multiturn_test_1.yaml" in names

    def test_no_multiturn_files_when_disabled(self, tmp_path: Path) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=False), target_type=TargetType.LLM
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch("pentester.auditors.promptfoo.auditor.yaml.dump") as mock_dump:
            auditor._write_plugin_configs(["harmful:hate"], configs_dir)

        assert mock_dump.call_count == 1  # single-turn only
        st_config = mock_dump.call_args_list[0][0][0]
        st_ids = {s["id"] for s in st_config["redteam"]["strategies"]}
        assert st_ids.isdisjoint(KNOWN_MULTITURN_STRATEGIES)


class TestSplitAuditFiles:
    def test_splits_by_prefix(self) -> None:
        files = [
            Path("/test_1.yaml"),
            Path("/multiturn_test_1.yaml"),
            Path("/test_2.yaml"),
            Path("/multiturn_test_2.yaml"),
        ]
        single, multi = PromptfooAuditor._split_audit_files(files)
        assert len(single) == 2
        assert len(multi) == 2
        assert all(not f.name.startswith("multiturn_") for f in single)
        assert all(f.name.startswith("multiturn_") for f in multi)

    def test_returns_empty_lists_when_no_files(self) -> None:
        single, multi = PromptfooAuditor._split_audit_files([])
        assert single == []
        assert multi == []

    def test_all_single_turn(self) -> None:
        files = [Path("/test_1.yaml"), Path("/test_2.yaml")]
        single, multi = PromptfooAuditor._split_audit_files(files)
        assert len(single) == 2
        assert multi == []


class TestValidatePreconditionsMultiturn:
    @pytest.fixture(autouse=True)
    def _patch_ensure_email(self) -> Generator[None, None, None]:
        with patch.object(PromptfooRunner, "ensure_email_configured"):
            yield

    def test_requires_llm_key_for_multiturn_semantic_fence(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(ValueError, match="Multi-turn strategies require"),
        ):
            auditor._validate_preconditions()

    def test_requires_llm_key_for_multiturn_llm_target(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True),
            target_type=TargetType.LLM,
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(ValueError, match="Multi-turn strategies require"),
        ):
            auditor._validate_preconditions()

    def test_passes_with_key_for_multiturn_semantic_fence(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        with (
            patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True),
            patch("pathlib.Path.exists", return_value=True),
        ):
            auditor._validate_preconditions()  # should not raise


class TestAuditTwoPassSemanticFence:
    def test_two_pass_when_semantic_fence_and_multiturn(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        single_files = [Path("/test_1.yaml")]
        multi_files = [Path("/multiturn_test_1.yaml")]
        all_files = single_files + multi_files
        runner_output = [(Path("/a.yaml"), True, "a.yaml", "ok")]
        expected_df = pd.DataFrame({"col": [1]})

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(auditor, "_prepare_audit_files", return_value=all_files),
            patch.object(
                auditor, "_split_audit_files", return_value=(single_files, multi_files)
            ) as mock_split,
            patch.object(auditor, "_unset_llm_api_keys") as mock_unset,
            patch.object(auditor, "_restore_llm_api_keys") as mock_restore,
            patch.object(auditor, "_run_eval_pass", return_value=runner_output),
            patch.object(
                auditor.collector, "build_dataframe", return_value=expected_df
            ),
            patch.object(auditor, "_generate_probe_results", return_value=[]),
        ):
            auditor.audit()

        mock_split.assert_called_once_with(all_files)
        # Pass 1: unset keys, run single-turn, restore
        mock_unset.assert_called_once()
        # restore called: once after pass 1 + once in finally
        assert mock_restore.call_count == 2

    def test_single_pass_when_semantic_fence_without_multiturn(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=False),
            target_type=TargetType.SEMANTIC_FENCE,
        )
        files = [Path("/test_1.yaml")]
        runner_output = [(Path("/a.yaml"), True, "a.yaml", "ok")]

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(auditor, "_prepare_audit_files", return_value=files),
            patch.object(auditor, "_unset_llm_api_keys") as mock_unset,
            patch.object(auditor, "_restore_llm_api_keys"),
            patch.object(auditor, "_run_eval_pass", return_value=runner_output),
            patch.object(
                auditor.collector, "build_dataframe", return_value=pd.DataFrame()
            ),
            patch.object(auditor, "_generate_probe_results", return_value=[]),
        ):
            auditor.audit()

        mock_unset.assert_called_once()


class TestAuditSinglePassLLM:
    def test_single_pass_for_llm_with_multiturn(self) -> None:
        auditor = _make_auditor(
            _make_settings(enable_multiturn=True),
            target_type=TargetType.LLM,
        )
        files = [Path("/test_1.yaml"), Path("/multiturn_test_1.yaml")]
        runner_output = [(Path("/a.yaml"), True, "a.yaml", "ok")]

        with (
            patch.object(auditor, "_validate_preconditions"),
            patch.object(auditor, "generate_tests_files"),
            patch.object(auditor.collector, "clean"),
            patch.object(auditor, "_prepare_audit_files", return_value=files),
            patch.object(auditor, "_unset_llm_api_keys") as mock_unset,
            patch.object(auditor, "_restore_llm_api_keys"),
            patch.object(
                auditor, "_run_eval_pass", return_value=runner_output
            ) as mock_eval,
            patch.object(
                auditor.collector, "build_dataframe", return_value=pd.DataFrame()
            ),
            patch.object(auditor, "_generate_probe_results", return_value=[]),
        ):
            auditor.audit()

        mock_unset.assert_not_called()
        mock_eval.assert_has_calls(
            [
                call([Path("/test_1.yaml")]),
                call([Path("/multiturn_test_1.yaml")]),
            ]
        )
        assert mock_eval.call_count == 2


class TestGenerateProbeResultsMultiturn:
    def test_is_multiturn_true_for_multiturn_strategy(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = pd.DataFrame(
            [
                {
                    "strategy_id": "crescendo",
                    "plugin_id": "harmful:hate",
                    "prompt": "p",
                    "api_response": "r",
                    "success": False,
                    "error": None,
                    "grading_score": 1.0,
                    "accept_score": None,
                    "http_status": 200,
                    "duration": 1.0,
                    "latency_ms": 50,
                    "cached": False,
                    "grading_reason": None,
                }
            ]
        )
        results = auditor._generate_probe_results()
        assert results[0].metadata["is_multiturn"] is True

    def test_is_multiturn_false_for_single_turn_strategy(self) -> None:
        auditor = _make_auditor()
        auditor.results_df = pd.DataFrame(
            [
                {
                    "strategy_id": "basic",
                    "plugin_id": "harmful:hate",
                    "prompt": "p",
                    "api_response": "r",
                    "success": True,
                    "error": None,
                    "grading_score": 1.0,
                    "accept_score": None,
                    "http_status": 200,
                    "duration": 1.0,
                    "latency_ms": 50,
                    "cached": False,
                    "grading_reason": None,
                }
            ]
        )
        results = auditor._generate_probe_results()
        assert results[0].metadata["is_multiturn"] is False


# ---------------------------------------------------------------------------
# Multiturn Explosion Helpers
# ---------------------------------------------------------------------------


def _make_multiturn_messages(num_turns: int = 3) -> list[dict[str, str]]:
    """Create alternating user/assistant message pairs."""
    messages = []
    for i in range(1, num_turns + 1):
        messages.append({"role": "user", "content": f"user_msg_{i}"})
        messages.append({"role": "assistant", "content": f"assistant_resp_{i}"})
    return messages


def _make_multiturn_row(
    num_turns: int = 3,
    successful_turns: list[int] | None = None,
    grader_score: float = 0.0,
    grader_reason: str = "attack succeeded",
    grader_pass: bool = False,
    **overrides: object,
) -> dict[str, Any]:
    """Build a dict representing a multiturn DataFrame row."""
    attacks = [
        {"turn": t, "prompt": f"user_msg_{t}", "response": f"assistant_resp_{t}"}
        for t in (successful_turns or [])
    ]
    row: dict[str, Any] = {
        "strategy_id": "crescendo",
        "plugin_id": "competitors",
        "prompt": f"user_msg_{num_turns}",
        "api_response": f"assistant_resp_{num_turns}",
        "success": False,
        "error": None,
        "grading_score": 1.0,
        "accept_score": None,
        "http_status": 201,
        "duration": 1.5,
        "latency_ms": 100,
        "cached": False,
        "grading_reason": None,
        "multiturn_messages": _make_multiturn_messages(num_turns),
        "successful_attacks": attacks,
        "stored_grader_result": {
            "score": grader_score,
            "reason": grader_reason,
            "pass": grader_pass,
        },
    }
    row.update(overrides)
    return row


class TestIsMultiturnRow:
    def test_returns_true_when_multiturn_messages_is_nonempty_list(self) -> None:
        row = pd.Series(
            {"multiturn_messages": [{"role": "user"}, {"role": "assistant"}]}
        )
        assert PromptfooAuditor._is_multiturn_row(row) is True

    @pytest.mark.parametrize(
        "messages",
        [
            None,
            [],
            [{"role": "user"}],
        ],
        ids=["none", "empty_list", "single_message"],
    )
    def test_returns_false_for_non_multiturn_messages(self, messages: object) -> None:
        row = pd.Series({"multiturn_messages": messages})
        assert PromptfooAuditor._is_multiturn_row(row) is False

    def test_returns_false_when_column_missing(self) -> None:
        row = pd.Series({"other": "value"})
        assert PromptfooAuditor._is_multiturn_row(row) is False


class TestBuildSuccessfulTurnsSet:
    def test_returns_set_of_turn_numbers(self) -> None:
        attacks = [{"turn": 2, "prompt": "p"}, {"turn": 5, "prompt": "p"}]
        assert PromptfooAuditor._build_successful_turns_set(attacks) == {2, 5}

    @pytest.mark.parametrize("attacks", [None, []], ids=["none", "empty_list"])
    def test_returns_empty_set_for_empty_input(self, attacks: list | None) -> None:
        assert PromptfooAuditor._build_successful_turns_set(attacks) == set()

    def test_skips_entries_without_turn_key(self) -> None:
        attacks = [{"turn": 3}, {"prompt": "no turn key"}]
        assert PromptfooAuditor._build_successful_turns_set(attacks) == {3}


class TestExplodeMultiturnRow:
    def test_explodes_into_correct_number_of_probes(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=3))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert len(results) == 3

    def test_prompt_and_response_per_turn(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=2))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert results[0].prompt == "user_msg_1"
        assert results[0].response == "assistant_resp_1"
        assert results[1].prompt == "user_msg_2"
        assert results[1].response == "assistant_resp_2"

    def test_bypassed_and_score_per_turn(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=3, successful_turns=[2]))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert results[0].bypassed is False
        assert results[1].bypassed is True
        assert results[2].bypassed is False
        assert results[0].score == 1.0
        assert results[1].score == 0.0
        assert results[2].score == 1.0

    def test_blocked_turn_score_is_one(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=2, successful_turns=[1]))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert results[0].score == 0.0  # bypassed
        assert results[1].score == 1.0  # blocked

    def test_grading_reason_for_bypassed_turns_only(self) -> None:
        row = pd.Series(
            _make_multiturn_row(
                num_turns=2, successful_turns=[2], grader_reason="defense failed"
            )
        )
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert results[0].metadata["grading_reason"] is None
        assert results[1].metadata["grading_reason"] == "defense failed"

    def test_conversation_id_shared_across_turns(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=3))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-abc", "promptfoo")
        for r in results:
            assert r.metadata["conversation_id"] == "conv-abc"

    def test_turn_number_is_one_indexed(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=3))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert [r.metadata["turn_number"] for r in results] == [1, 2, 3]

    def test_is_multiturn_true_for_all_turns(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=2))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        for r in results:
            assert r.metadata["is_multiturn"] is True

    def test_attack_category_from_strategy_id(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=1, strategy_id="goat"))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert results[0].attack_category == "goat"

    def test_attack_type_from_plugin_id(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=1, plugin_id="harmful:hate"))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert results[0].attack_type == "harmful:hate"

    def test_odd_message_count_ignores_trailing_user_message(self) -> None:
        messages = _make_multiturn_messages(2)
        messages.append({"role": "user", "content": "trailing"})
        row_data = _make_multiturn_row(num_turns=2)
        row_data["multiturn_messages"] = messages
        row = pd.Series(row_data)
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert len(results) == 2

    def test_empty_successful_attacks_means_no_bypasses(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=3, successful_turns=[]))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert all(r.bypassed is False for r in results)
        assert all(r.score == 1.0 for r in results)

    def test_metadata_includes_row_level_fields(self) -> None:
        row = pd.Series(_make_multiturn_row(num_turns=1))
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        m = results[0].metadata
        assert m["http_status"] == 201
        assert m["duration"] == 1.5
        assert m["latency_ms"] == 100
        assert m["cached"] is False
        assert m["error"] is None

    def test_stored_grader_result_none_handled(self) -> None:
        row_data = _make_multiturn_row(num_turns=1, successful_turns=[1])
        row_data["stored_grader_result"] = None
        row = pd.Series(row_data)
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert results[0].bypassed is True
        assert results[0].score == 0.0
        assert results[0].metadata["grading_reason"] is None

    def test_conversation_bypassed_true_when_grader_fails(self) -> None:
        """conversation_bypassed is True when storedGraderResult.pass is
        false, meaning the overall conversation was compromised."""
        row = pd.Series(
            _make_multiturn_row(
                num_turns=2,
                successful_turns=[1],
                grader_pass=False,
            )
        )
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert all(r.metadata["conversation_bypassed"] is True for r in results)

    def test_conversation_bypassed_false_when_grader_passes(self) -> None:
        """conversation_bypassed is False when storedGraderResult.pass is
        true, even if there are intermediate successful attacks."""
        row = pd.Series(
            _make_multiturn_row(
                num_turns=3,
                successful_turns=[2],
                grader_pass=True,
            )
        )
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert all(r.metadata["conversation_bypassed"] is False for r in results)

    def test_bypassed_turns_independent_of_grader_pass(self) -> None:
        """Turns in successfulAttacks are bypassed regardless of the
        conversation-level grader outcome."""
        row = pd.Series(
            _make_multiturn_row(
                num_turns=3,
                successful_turns=[2],
                grader_pass=True,
            )
        )
        results = PromptfooAuditor._explode_multiturn_row(row, "conv-123", "promptfoo")
        assert results[0].bypassed is False
        assert results[1].bypassed is True
        assert results[2].bypassed is False
        assert results[0].score == 1.0
        assert results[1].score == 0.0
        assert results[2].score == 1.0


def _make_single_turn_row() -> dict[str, Any]:
    return {
        "strategy_id": "basic",
        "plugin_id": "harmful:hate",
        "prompt": "single prompt",
        "api_response": {"data": "resp"},
        "success": True,
        "error": None,
        "grading_score": 1.0,
        "accept_score": 0.9,
        "http_status": 200,
        "duration": 0.5,
        "latency_ms": 50,
        "cached": False,
        "grading_reason": "passed",
        "multiturn_messages": None,
        "successful_attacks": None,
        "stored_grader_result": None,
    }


class TestGenerateProbeResultsMixed:
    def test_mixed_single_and_multiturn_rows(self) -> None:
        auditor = _make_auditor()
        single = _make_single_turn_row()
        multi = _make_multiturn_row(num_turns=3, successful_turns=[2])
        auditor.results_df = pd.DataFrame([single, multi])

        results = auditor._generate_probe_results()

        # 1 single-turn + 3 exploded turns = 4
        assert len(results) == 4
        assert results[0].metadata.get("conversation_id") is None
        assert results[0].metadata["is_multiturn"] is False
        assert results[1].metadata["is_multiturn"] is True
        assert results[1].metadata["turn_number"] == 1
        assert results[3].metadata["turn_number"] == 3

    def test_multiturn_conversation_ids_are_unique_per_row(self) -> None:
        auditor = _make_auditor()
        multi1 = _make_multiturn_row(num_turns=2)
        multi2 = _make_multiturn_row(num_turns=2)
        auditor.results_df = pd.DataFrame([multi1, multi2])

        results = auditor._generate_probe_results()

        conv_ids = {r.metadata["conversation_id"] for r in results}
        assert len(conv_ids) == 2  # two distinct conversation IDs


def test_auditor_key_is_promptfoo() -> None:
    assert _make_auditor().auditor_key == AuditorKey.PROMPTFOO


# ---------------------------------------------------------------------------
# TestMaxAttacks
# ---------------------------------------------------------------------------


class TestMaxAttacks:
    def test_max_attacks_defaults_to_none(self) -> None:
        auditor = _make_auditor(settings=_make_settings())
        assert auditor.settings.max_attacks is None

    def test_max_attacks_is_readable_when_set(self) -> None:
        auditor = _make_auditor(settings=_make_settings(max_attacks=75))
        assert auditor.settings.max_attacks == 75
