import pytest
from pydantic import ValidationError

from pentester.config.llm import LLMProvider, LLMSettings


class TestDefaults:
    def test_default_provider_is_openai(self) -> None:
        assert LLMSettings().provider == LLMProvider.OPENAI

    def test_default_model_is_empty(self) -> None:
        assert LLMSettings().model == ""


class TestEnvVarOverrides:
    def test_provider_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PROVIDER", "anthropic")
        assert LLMSettings().provider == LLMProvider.ANTHROPIC

    def test_model_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MODEL", "gpt-4o")
        assert LLMSettings().model == "gpt-4o"

    def test_invalid_provider_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PROVIDER", "invalid")
        with pytest.raises(ValidationError):
            LLMSettings()


class TestDirectInit:
    def test_set_provider(self) -> None:
        assert LLMSettings(provider=LLMProvider.ANTHROPIC).provider == LLMProvider.ANTHROPIC

    def test_set_model(self) -> None:
        assert LLMSettings(model="claude-3-5-sonnet").model == "claude-3-5-sonnet"

    def test_set_provider_by_string_value(self) -> None:
        assert LLMSettings(provider="gemini").provider == LLMProvider.GEMINI


class TestLLMProviderEnum:
    @pytest.mark.parametrize("member", list(LLMProvider))
    def test_provider_is_string(self, member: LLMProvider) -> None:
        assert isinstance(member, str)

    def test_openai_value(self) -> None:
        assert LLMProvider.OPENAI == "openai"

    def test_anthropic_value(self) -> None:
        assert LLMProvider.ANTHROPIC == "anthropic"

    def test_gemini_value(self) -> None:
        assert LLMProvider.GEMINI == "gemini"
