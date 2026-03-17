import pytest

from pentester.config.scanner import ScannerSettings


class TestDefaults:
    def test_curl_command_defaults_to_none(self) -> None:
        settings = ScannerSettings()
        assert settings.curl_command is None

    def test_curl_file_defaults_to_none(self) -> None:
        settings = ScannerSettings()
        assert settings.curl_file is None

    def test_json_dot_target_defaults_to_none(self) -> None:
        settings = ScannerSettings()
        assert settings.json_dot_target is None


class TestEnvVarOverrides:
    def test_curl_command_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CURL_COMMAND", "curl http://example.com")
        settings = ScannerSettings()
        assert settings.curl_command == "curl http://example.com"

    def test_json_dot_target_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("JSON_DOT_TARGET", "body.choices.0.message.content")
        settings = ScannerSettings()
        assert settings.json_dot_target == "body.choices.0.message.content"


class TestDirectInit:
    def test_set_curl_command(self) -> None:
        settings = ScannerSettings(curl_command="curl http://example.com")
        assert settings.curl_command == "curl http://example.com"

    def test_set_curl_file(self) -> None:
        settings = ScannerSettings(curl_file="/path/to/cmd.curl")
        assert settings.curl_file == "/path/to/cmd.curl"

    def test_set_json_dot_target(self) -> None:
        settings = ScannerSettings(json_dot_target="body.result")
        assert settings.json_dot_target == "body.result"

    def test_both_fields_set(self) -> None:
        settings = ScannerSettings(
            curl_command="curl http://example.com",
            json_dot_target="body.result",
        )
        assert settings.curl_command == "curl http://example.com"
        assert settings.json_dot_target == "body.result"
