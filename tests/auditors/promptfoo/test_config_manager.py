from __future__ import annotations

import copy
from pathlib import Path
from typing import Any
from unittest.mock import mock_open, patch

import pytest

from pentester.auditors.promptfoo.config_manager import PromptfooConfigManager
from pentester.config.auditors.promptfoo_settings import (
    KNOWN_MULTITURN_STRATEGIES,
    PromptfooSettings,
)
from pentester.config.settings import TargetType
from pentester.scanners.response_serializers.json_dot_serializer import (
    JSONDotSerializer,
)


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


def _make_scanner_with_dot_target(target: str) -> object:
    from unittest.mock import MagicMock

    handler = MagicMock()
    handler.response_serializer = JSONDotSerializer(target)
    scanner = MagicMock()
    scanner.request_handler = handler
    return scanner


def _make_config_manager(
    settings: PromptfooSettings | None = None,
    target_type: TargetType = TargetType.SEMANTIC_FENCE,
    json_dot_target: str | None = None,
    config: dict[str, Any] | None = None,
) -> PromptfooConfigManager:
    s = settings or _make_settings()
    cm = PromptfooConfigManager(s, target_type, json_dot_target)
    cm.config = copy.deepcopy(config if config is not None else _FAKE_CONFIG)
    return cm


# ---------------------------------------------------------------------------
# TestLoadConfig
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_extracts_all_expected_fields_from_yaml(self) -> None:
        cm = _make_config_manager()
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
        ):
            config = cm.load_config(Path("/fake.yaml"))

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
        cm = _make_config_manager()
        minimal_config = {"prompts": ["p"]}
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=minimal_config,
            ),
        ):
            config = cm.load_config(Path("/fake.yaml"))

        assert config["providers"] is None
        assert config["metadata"] == {}

    def test_returns_empty_prompts_for_missing_prompts_key(self) -> None:
        cm = _make_config_manager()
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value={"providers": None},
            ),
        ):
            config = cm.load_config(Path("/fake.yaml"))

        assert config["prompts"] == []


# ---------------------------------------------------------------------------
# TestOpenConfig
# ---------------------------------------------------------------------------


class TestOpenConfig:
    def test_loads_config_from_settings_path_and_stores_it(self) -> None:
        cm = PromptfooConfigManager(_make_settings(), TargetType.SEMANTIC_FENCE)
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
        ):
            result = cm.open_config()

        assert cm.config["prompts"] == _FAKE_CONFIG["prompts"]
        assert result is cm.config

    def test_returns_the_loaded_dict(self) -> None:
        cm = PromptfooConfigManager(_make_settings(), TargetType.SEMANTIC_FENCE)
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
        ):
            result = cm.open_config()

        assert isinstance(result, dict)
        assert "prompts" in result


# ---------------------------------------------------------------------------
# TestWritePluginConfigs
# ---------------------------------------------------------------------------


class TestWritePluginConfigs:
    def test_writes_new_configs_with_correct_formatting(self, tmp_path: Path) -> None:
        cm = _make_config_manager(target_type=TargetType.LLM)
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(["harmful:hate", "harmful:xss"], configs_dir)

        assert mock_dump.call_count == 2
        first_config = mock_dump.call_args_list[0][0][0]
        second_config = mock_dump.call_args_list[1][0][0]

        assert "metadata" not in first_config
        assert first_config["redteam"]["plugins"] == ["harmful:hate"]
        assert "defaultAssertions" not in first_config["redteam"]
        assert second_config["redteam"]["plugins"] == ["harmful:xss"]
        assert (configs_dir / "test_1.yaml").exists()
        assert (configs_dir / "test_2.yaml").exists()
        assert "defaultAssertions" in cm.config["redteam"]  # original unchanged

    def test_warns_when_existing_file_has_different_plugin_count(
        self, tmp_path: Path
    ) -> None:
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        existing_file = configs_dir / "test_1.yaml"
        existing_file.write_text("placeholder")

        cm = _make_config_manager(
            _make_settings(plugins_per_file=1, replace_existing_file=False)
        )

        existing_config = copy.deepcopy(_FAKE_CONFIG)
        existing_config["redteam"]["plugins"] = [
            "harmful:hate",
            "harmful:xss",
        ]  # 2 plugins

        with (
            patch("pentester.auditors.promptfoo.config_manager.logger") as mock_logger,
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=existing_config,
            ),
        ):
            cm.write_plugin_configs(["harmful:hate"], configs_dir)

        mock_logger.warning.assert_called_once()
        assert "differs from" in mock_logger.warning.call_args[0][0]

    def test_no_warning_when_existing_file_has_matching_plugin_count(
        self, tmp_path: Path
    ) -> None:
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        existing_file = configs_dir / "test_1.yaml"
        existing_file.write_text("placeholder")

        cm = _make_config_manager(
            _make_settings(plugins_per_file=1, replace_existing_file=False)
        )

        existing_config = copy.deepcopy(_FAKE_CONFIG)
        existing_config["redteam"]["plugins"] = [
            "harmful:hate"
        ]  # matches plugins_per_file=1

        with (
            patch("pentester.auditors.promptfoo.config_manager.logger") as mock_logger,
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=existing_config,
            ),
        ):
            cm.write_plugin_configs(["harmful:hate"], configs_dir)

        mock_logger.warning.assert_not_called()
        mock_logger.info.assert_called()

    def test_handles_existing_files_based_on_replace_setting(
        self, tmp_path: Path
    ) -> None:
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        existing_file = configs_dir / "test_1.yaml"

        # Test replace = False — existing file with matching plugin count is skipped
        s_no_replace = _make_settings(replace_existing_file=False)
        existing_file.write_text("placeholder")
        on_disk = copy.deepcopy(_FAKE_CONFIG)
        on_disk["redteam"]["plugins"] = [
            "harmful:hate"
        ]  # 1 plugin matches default plugins_per_file
        with (
            patch("pentester.auditors.promptfoo.config_manager.yaml.dump") as mock_dump,
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=on_disk,
            ),
        ):
            _make_config_manager(s_no_replace).write_plugin_configs(
                ["harmful:hate"], configs_dir
            )
            mock_dump.assert_not_called()

        # Test replace = True
        s_replace = _make_settings(replace_existing_file=True)
        existing_file.write_text("old data")
        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            _make_config_manager(s_replace).write_plugin_configs(
                ["harmful:hate"], configs_dir
            )
            mock_dump.assert_called()


class TestWritePluginConfigsChunking:
    def test_plugins_per_file_chunks_correctly(self, tmp_path: Path) -> None:
        cm = _make_config_manager(_make_settings(plugins_per_file=2))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        plugins = ["a", "b", "c", "d", "e"]

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(plugins, configs_dir)

        assert mock_dump.call_count == 3  # ceil(5/2) = 3
        assert mock_dump.call_args_list[0][0][0]["redteam"]["plugins"] == ["a", "b"]
        assert mock_dump.call_args_list[1][0][0]["redteam"]["plugins"] == ["c", "d"]
        assert mock_dump.call_args_list[2][0][0]["redteam"]["plugins"] == ["e"]

    def test_max_test_files_caps_output(self, tmp_path: Path) -> None:
        cm = _make_config_manager(_make_settings(max_test_files=2))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        plugins = ["a", "b", "c", "d", "e"]

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(plugins, configs_dir)

        assert mock_dump.call_count == 2
        assert mock_dump.call_args_list[0][0][0]["redteam"]["plugins"] == ["a"]
        assert mock_dump.call_args_list[1][0][0]["redteam"]["plugins"] == ["b"]

    def test_plugins_per_file_and_max_test_files_combined(self, tmp_path: Path) -> None:
        cm = _make_config_manager(_make_settings(plugins_per_file=2, max_test_files=1))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        plugins = ["a", "b", "c", "d"]

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(plugins, configs_dir)

        assert mock_dump.call_count == 1
        assert mock_dump.call_args_list[0][0][0]["redteam"]["plugins"] == ["a", "b"]

    def test_max_test_files_none_generates_all(self, tmp_path: Path) -> None:
        cm = _make_config_manager(_make_settings(max_test_files=None))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()
        plugins = ["a", "b", "c"]

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(plugins, configs_dir)

        assert mock_dump.call_count == 3


# ---------------------------------------------------------------------------
# TestWritePluginConfigsMultiturn
# ---------------------------------------------------------------------------


class TestWritePluginConfigsNumTests:
    def test_overrides_num_tests_on_dict_plugins(self, tmp_path: Path) -> None:
        plugins = [
            {"id": "harmful:hate", "numTests": 100},
            {"id": "competitors", "numTests": 100},
        ]
        cm = _make_config_manager(
            _make_settings(plugin_num_tests=50, plugins_per_file=2),
            config={
                **_FAKE_CONFIG,
                "redteam": {**_FAKE_CONFIG["redteam"], "plugins": plugins},
            },
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(plugins, configs_dir)

        # Both plugins land in one file (plugins_per_file=2)
        written_plugins = mock_dump.call_args_list[0][0][0]["redteam"]["plugins"]
        assert written_plugins[0]["numTests"] == 50
        assert written_plugins[1]["numTests"] == 50

    def test_does_not_modify_original_plugin_objects(self, tmp_path: Path) -> None:
        plugin_a = {"id": "harmful:hate", "numTests": 100}
        plugin_b = {"id": "competitors", "numTests": 100}
        plugins = [plugin_a, plugin_b]

        cm = _make_config_manager(
            _make_settings(plugin_num_tests=10),
            config={
                **_FAKE_CONFIG,
                "redteam": {**_FAKE_CONFIG["redteam"], "plugins": plugins},
            },
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch("pentester.auditors.promptfoo.config_manager.yaml.dump"):
            cm.write_plugin_configs(plugins, configs_dir)

        assert plugin_a["numTests"] == 100
        assert plugin_b["numTests"] == 100

    def test_skips_string_plugins_when_overriding(self, tmp_path: Path) -> None:
        cm = _make_config_manager(_make_settings(plugin_num_tests=25))
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(["harmful:hate", "competitors"], configs_dir)

        written_plugins = mock_dump.call_args_list[0][0][0]["redteam"]["plugins"]
        # String plugins are not modified — no numTests key injected
        assert all(isinstance(p, str) for p in written_plugins)

    def test_no_override_when_plugin_num_tests_is_none(self, tmp_path: Path) -> None:
        cm = _make_config_manager(
            _make_settings(plugin_num_tests=None),
            config={
                **_FAKE_CONFIG,
                "redteam": {
                    **_FAKE_CONFIG["redteam"],
                    "plugins": [{"id": "harmful:hate", "numTests": 100}],
                },
            },
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(
                [{"id": "harmful:hate", "numTests": 100}], configs_dir
            )

        written_plugins = mock_dump.call_args_list[0][0][0]["redteam"]["plugins"]
        assert written_plugins[0]["numTests"] == 100


class TestWritePluginConfigsMultiturn:
    def test_generates_multiturn_files_when_enabled(self, tmp_path: Path) -> None:
        cm = _make_config_manager(
            _make_settings(enable_multiturn=True), target_type=TargetType.LLM
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(["harmful:hate"], configs_dir)

        # 1 single-turn + 1 multiturn = 2 dumps
        assert mock_dump.call_count == 2
        mt_config = mock_dump.call_args_list[1][0][0]
        strategy_ids = [s["id"] for s in mt_config["redteam"]["strategies"]]
        assert "crescendo" in strategy_ids

    def test_single_turn_file_has_no_multiturn_strategies(self, tmp_path: Path) -> None:
        cm = _make_config_manager(
            _make_settings(enable_multiturn=True), target_type=TargetType.LLM
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(["harmful:hate"], configs_dir)

        st_config = mock_dump.call_args_list[0][0][0]
        st_ids = {s["id"] for s in st_config["redteam"]["strategies"]}
        assert st_ids.isdisjoint(KNOWN_MULTITURN_STRATEGIES)

    def test_multiturn_file_has_correct_prefix(self, tmp_path: Path) -> None:
        cm = _make_config_manager(
            _make_settings(enable_multiturn=True), target_type=TargetType.LLM
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch("pentester.auditors.promptfoo.config_manager.yaml.dump"):
            cm.write_plugin_configs(["harmful:hate"], configs_dir)

        files = list(configs_dir.glob("*.yaml"))
        names = {f.name for f in files}
        assert "test_1.yaml" in names
        assert "multiturn_test_1.yaml" in names

    def test_no_multiturn_files_when_disabled(self, tmp_path: Path) -> None:
        cm = _make_config_manager(
            _make_settings(enable_multiturn=False), target_type=TargetType.LLM
        )
        configs_dir = tmp_path / "configurations"
        configs_dir.mkdir()

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.write_plugin_configs(["harmful:hate"], configs_dir)

        assert mock_dump.call_count == 1  # single-turn only
        st_config = mock_dump.call_args_list[0][0][0]
        st_ids = {s["id"] for s in st_config["redteam"]["strategies"]}
        assert st_ids.isdisjoint(KNOWN_MULTITURN_STRATEGIES)


# ---------------------------------------------------------------------------
# TestRemoveCloudOnlyTests
# ---------------------------------------------------------------------------


class TestRemoveCloudOnlyTests:
    def test_removes_jailbreak_meta_tests_from_yaml(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager(target_type=TargetType.LLM)
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
            yaml.dump(config_with_mixed, f)

        cm.remove_cloud_only_tests(llm_dir)

        with open(llm_dir / "test_1.yaml") as f:
            result = yaml.safe_load(f)
        assert len(result["tests"]) == 1
        assert result["tests"][0]["vars"]["input"] == "b"

    def test_skips_file_when_no_jailbreak_meta_tests(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager(target_type=TargetType.LLM)
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
        with open(llm_dir / "test_1.yaml", "w") as f:
            yaml.dump(config_no_meta, f)

        with patch(
            "pentester.auditors.promptfoo.config_manager.yaml.dump"
        ) as mock_dump:
            cm.remove_cloud_only_tests(llm_dir)
            mock_dump.assert_not_called()

    def test_handles_tests_without_metadata(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager(target_type=TargetType.LLM)
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
        with open(llm_dir / "test_1.yaml", "w") as f:
            yaml.dump(config, f)

        cm.remove_cloud_only_tests(llm_dir)

        with open(llm_dir / "test_1.yaml") as f:
            result = yaml.safe_load(f)
        assert len(result["tests"]) == 2
        assert result["tests"][0]["vars"]["input"] == "a"
        assert result["tests"][1]["vars"]["input"] == "b"

    def test_logs_removal_count(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager(target_type=TargetType.LLM)
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
        with open(llm_dir / "test_1.yaml", "w") as f:
            yaml.dump(config, f)

        with patch("pentester.auditors.promptfoo.config_manager.logger") as mock_logger:
            cm.remove_cloud_only_tests(llm_dir)

        mock_logger.info.assert_any_call(
            "Removed %d jailbreak:meta test(s) from %s",
            2,
            "test_1.yaml",
        )


# ---------------------------------------------------------------------------
# TestConfigureProviderInTestFiles
# ---------------------------------------------------------------------------


class TestConfigureProviderInTestFiles:
    def test_custom_handler_replaces_providers_in_yaml(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager()
        provider_id = "file://handler.py:H.promptfoo_call_api"
        provider = {"id": provider_id}

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        cm.configure_provider_in_test_files(cfg_dir, provider, provider_id)

        result = yaml.safe_load((cfg_dir / "test_1.yaml").read_text())
        assert result["providers"] == [{"id": provider_id, "label": "target-api"}]

    def test_http_provider_updates_config_in_yaml(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager()
        provider_id = "http"
        provider = {"id": "http", "config": {"url": "http://new.com", "method": "POST"}}

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        cm.configure_provider_in_test_files(cfg_dir, provider, provider_id)

        result = yaml.safe_load((cfg_dir / "test_1.yaml").read_text())
        assert result["providers"][0]["id"] == "http"
        assert result["providers"][0]["label"] == "target-api"
        assert result["providers"][0]["config"]["url"] == "http://new.com"

    def test_http_provider_updates_id_to_https_in_yaml(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager()
        provider_id = "https"
        provider = {
            "id": "https",
            "config": {"url": "https://new.com", "method": "POST"},
        }

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        cm.configure_provider_in_test_files(cfg_dir, provider, provider_id)

        result = yaml.safe_load((cfg_dir / "test_1.yaml").read_text())
        assert result["providers"][0]["id"] == "https"
        assert result["providers"][0]["label"] == "target-api"
        assert result["providers"][0]["config"]["url"] == "https://new.com"

    def test_applies_custom_handler_to_all_yaml_files(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager()
        provider_id = "file://h.py:H.promptfoo_call_api"
        provider = {"id": provider_id}

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        for name in ["test_1.yaml", "test_2.yaml", "multiturn_test_1.yaml"]:
            (cfg_dir / name).write_text(yaml_content)

        cm.configure_provider_in_test_files(cfg_dir, provider, provider_id)

        for name in ["test_1.yaml", "test_2.yaml", "multiturn_test_1.yaml"]:
            result = yaml.safe_load((cfg_dir / name).read_text())
            assert result["providers"] == [{"id": provider_id, "label": "target-api"}]

    def test_custom_target_label_written_to_yaml(self, tmp_path: Path) -> None:
        import yaml

        cm = _make_config_manager(_make_settings(target_label="helpdesk-agent"))
        provider_id = "https"
        provider = {
            "id": "https",
            "config": {"url": "https://api.example.com", "method": "POST"},
        }

        cfg_dir = tmp_path / "configurations"
        cfg_dir.mkdir()
        yaml_content = "providers:\n- id: http\n  config:\n    url: http://old.com\n"
        (cfg_dir / "test_1.yaml").write_text(yaml_content)

        cm.configure_provider_in_test_files(cfg_dir, provider, provider_id)

        result = yaml.safe_load((cfg_dir / "test_1.yaml").read_text())
        assert result["providers"][0]["label"] == "helpdesk-agent"


# ---------------------------------------------------------------------------
# TestBuildAssertionBlock
# ---------------------------------------------------------------------------


class TestBuildAssertionBlock:
    def test_returns_python_when_wrapper_path_set(self) -> None:
        cm = _make_config_manager(
            _make_settings(assertion_wrapper_path="/my/assert.py")
        )
        block = cm._build_assertion_block()
        assert len(block) == 1
        assert block[0]["type"] == "python"
        assert "/my/assert.py" in block[0]["value"]

    def test_returns_javascript_with_stripped_path(self) -> None:
        cm = _make_config_manager(json_dot_target="body.data.valid")
        block = cm._build_assertion_block()
        assert block == [
            {
                "type": "javascript",
                "value": "JSON.parse(output).data.valid === false",
            }
        ]

    def test_returns_default_when_no_wrapper_no_dot_target(self) -> None:
        cm = _make_config_manager()
        block = cm._build_assertion_block()
        assert block == [{"type": "javascript", "value": "JSON.parse(output).passed"}]

    def test_single_segment_dot_target_returns_default(self) -> None:
        cm = _make_config_manager(json_dot_target="body")
        block = cm._build_assertion_block()
        assert block == [{"type": "javascript", "value": "JSON.parse(output).passed"}]

    def test_headers_dot_target_strips_first_segment(self) -> None:
        cm = _make_config_manager(json_dot_target="headers.x-valid")
        block = cm._build_assertion_block()
        assert block == [
            {
                "type": "javascript",
                "value": "JSON.parse(output).x-valid === false",
            }
        ]

    def test_wrapper_path_takes_priority_over_json_dot_target(self) -> None:
        cm = _make_config_manager(
            _make_settings(assertion_wrapper_path="/my/assert.py"),
            json_dot_target="body.data.valid",
        )
        block = cm._build_assertion_block()
        assert len(block) == 1
        assert block[0]["type"] == "python"
        assert "/my/assert.py" in block[0]["value"]

    def test_deep_nested_dot_target(self) -> None:
        cm = _make_config_manager(json_dot_target="body.choices.0.message.content")
        block = cm._build_assertion_block()
        assert block == [
            {
                "type": "javascript",
                "value": "JSON.parse(output).choices.0.message.content === false",
            }
        ]


# ---------------------------------------------------------------------------
# TestCleanConfig
# ---------------------------------------------------------------------------


class TestCleanConfig:
    def test_raises_error_for_llm_target_type(self, tmp_path: Path) -> None:
        cm = _make_config_manager(target_type=TargetType.LLM)
        with pytest.raises(Exception, match="not allowed"):
            cm.clean_config(Path("/test.yaml"), tmp_path / "output")

    def test_cleans_and_writes_config_correctly(self, tmp_path: Path) -> None:
        cm = _make_config_manager(
            _make_settings(assertion_wrapper_path="/my/assert.py")
        )
        output = tmp_path / "output"
        output.mkdir()
        (output / "test.yaml").write_text("old")

        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
            patch("pentester.auditors.promptfoo.config_manager.yaml.dump") as mock_dump,
        ):
            cm.clean_config(Path("/test.yaml"), output)

        assert output.exists()
        written = mock_dump.call_args[0][0]
        for test in written["tests"]:
            assert test["assert"][0]["type"] == "python"
            assert "/my/assert.py" in test["assert"][0]["value"]

    def test_uses_javascript_for_json_dot_target(self, tmp_path: Path) -> None:
        cm = _make_config_manager(json_dot_target="body.data.valid")
        output = tmp_path / "output"
        output.mkdir()

        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
            patch("pentester.auditors.promptfoo.config_manager.yaml.dump") as mock_dump,
        ):
            cm.clean_config(Path("/test.yaml"), output)

        written = mock_dump.call_args[0][0]
        for test in written["tests"]:
            assert test["assert"] == [
                {
                    "type": "javascript",
                    "value": "JSON.parse(output).data.valid === false",
                }
            ]

    def test_uses_default_when_neither_wrapper_nor_dot_target(
        self, tmp_path: Path
    ) -> None:
        cm = _make_config_manager()
        output = tmp_path / "output"
        output.mkdir()

        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
            patch("pentester.auditors.promptfoo.config_manager.yaml.dump") as mock_dump,
        ):
            cm.clean_config(Path("/test.yaml"), output)

        written = mock_dump.call_args[0][0]
        for test in written["tests"]:
            assert test["assert"] == [{"type": "javascript", "value": "JSON.parse(output).passed"}]

    def test_handles_existing_files_based_on_replace_setting(
        self, tmp_path: Path
    ) -> None:
        output = tmp_path / "output"
        output.mkdir()
        (output / "test.yaml").write_text("old")

        # For SEMANTIC_FENCE, clean_config rewrites regardless of replace_existing_file
        cm_no_replace = _make_config_manager(
            _make_settings(replace_existing_file=False)
        )
        with (
            patch("builtins.open", mock_open(read_data="")),
            patch(
                "pentester.auditors.promptfoo.config_manager.yaml.safe_load",
                return_value=copy.deepcopy(_FAKE_CONFIG),
            ),
            patch("pentester.auditors.promptfoo.config_manager.yaml.dump") as mock_dump,
        ):
            cm_no_replace.clean_config(Path("/test.yaml"), output)
            mock_dump.assert_called()


# ---------------------------------------------------------------------------
# TestStripMultiturnStrategies
# ---------------------------------------------------------------------------


class TestStripMultiturnStrategies:
    def test_strips_multiturn_keeps_single_turn(self) -> None:
        result = PromptfooConfigManager._strip_multiturn_strategies(
            copy.deepcopy(_FAKE_CONFIG)
        )
        ids = {s["id"] for s in result["redteam"]["strategies"]}
        assert ids == {"basic", "jailbreak"}

    def test_does_not_mutate_input(self) -> None:
        original = copy.deepcopy(_FAKE_CONFIG)
        original_count = len(original["redteam"]["strategies"])
        PromptfooConfigManager._strip_multiturn_strategies(original)
        assert len(original["redteam"]["strategies"]) == original_count

    def test_handles_empty_strategies_list(self) -> None:
        config = copy.deepcopy(_FAKE_CONFIG)
        config["redteam"]["strategies"] = []
        result = PromptfooConfigManager._strip_multiturn_strategies(config)
        assert result["redteam"]["strategies"] == []


# ---------------------------------------------------------------------------
# TestApplyMultiturnOverrides
# ---------------------------------------------------------------------------


class TestApplyMultiturnOverrides:
    def test_filters_to_allowlist(self) -> None:
        cm = _make_config_manager(
            _make_settings(
                enable_multiturn=True,
                multiturn_strategies=["crescendo", "goat"],
            )
        )
        result = cm._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        mt_ids = {
            s["id"]
            for s in result["redteam"]["strategies"]
            if s["id"] in KNOWN_MULTITURN_STRATEGIES
        }
        assert mt_ids == {"crescendo", "goat"}

    def test_keeps_all_single_turn_strategies(self) -> None:
        cm = _make_config_manager(
            _make_settings(
                enable_multiturn=True,
                multiturn_strategies=["crescendo", "goat", "mischievous-user"],
            )
        )
        result = cm._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        ids = [s["id"] for s in result["redteam"]["strategies"]]
        assert "goat" in ids
        assert "crescendo" in ids

    def test_patches_max_turns(self) -> None:
        cm = _make_config_manager(
            _make_settings(enable_multiturn=True, multiturn_max_turns=10)
        )
        result = cm._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        for s in result["redteam"]["strategies"]:
            if s["id"] in KNOWN_MULTITURN_STRATEGIES:
                assert s["config"]["maxTurns"] == 10

    def test_patches_crescendo_specific_fields(self) -> None:
        cm = _make_config_manager(
            _make_settings(
                enable_multiturn=True,
                multiturn_max_backtracks=3,
                multiturn_stateful=True,
            )
        )
        result = cm._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        crescendo = next(
            s for s in result["redteam"]["strategies"] if s["id"] == "crescendo"
        )
        assert crescendo["config"]["maxBacktracks"] == 3
        assert crescendo["config"]["stateful"] is True
        assert crescendo["config"]["continueAfterSuccess"] is False

    def test_patches_crescendo_continue_after_success_true(self) -> None:
        cm = _make_config_manager(
            _make_settings(
                enable_multiturn=True,
                multiturn_continue_after_success=True,
            )
        )
        result = cm._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        crescendo = next(
            s for s in result["redteam"]["strategies"] if s["id"] == "crescendo"
        )
        assert crescendo["config"]["continueAfterSuccess"] is True

    def test_patches_goat_specific_fields(self) -> None:
        cm = _make_config_manager(
            _make_settings(enable_multiturn=True, multiturn_stateful=True)
        )
        result = cm._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        goat = next(s for s in result["redteam"]["strategies"] if s["id"] == "goat")
        assert goat["config"]["stateful"] is True
        assert goat["config"]["continueAfterSuccess"] is False

    def test_patches_goat_continue_after_success_true(self) -> None:
        cm = _make_config_manager(
            _make_settings(
                enable_multiturn=True,
                multiturn_continue_after_success=True,
            )
        )
        result = cm._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        goat = next(s for s in result["redteam"]["strategies"] if s["id"] == "goat")
        assert goat["config"]["continueAfterSuccess"] is True

    def test_mischievous_user_includes_stateful(self) -> None:
        cm = _make_config_manager(
            _make_settings(enable_multiturn=True, multiturn_stateful=True)
        )
        result = cm._apply_multiturn_overrides(copy.deepcopy(_FAKE_CONFIG))
        mu = next(
            s for s in result["redteam"]["strategies"] if s["id"] == "mischievous-user"
        )
        assert mu["config"]["stateful"] is True
        assert "continueAfterSuccess" not in mu["config"]

    def test_does_not_mutate_input(self) -> None:
        cm = _make_config_manager(
            _make_settings(enable_multiturn=True, multiturn_max_turns=10)
        )
        original = copy.deepcopy(_FAKE_CONFIG)
        crescendo_before = next(
            s for s in original["redteam"]["strategies"] if s["id"] == "crescendo"
        )
        original_max = crescendo_before["config"]["maxTurns"]
        cm._apply_multiturn_overrides(original)
        crescendo_after = next(
            s for s in original["redteam"]["strategies"] if s["id"] == "crescendo"
        )
        assert crescendo_after["config"]["maxTurns"] == original_max
