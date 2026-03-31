import pytest

from pentester.config.auditors.pyrit_settings import PyritSettings


class TestDefaults:
    def test_dataset_names_default(self) -> None:
        assert PyritSettings().dataset_names == []

    def test_max_seeds_default_is_none(self) -> None:
        assert PyritSettings().max_seeds is None

    def test_max_attacks_default_is_none(self) -> None:
        assert PyritSettings().max_attacks is None


class TestDirectInit:
    def test_set_dataset_names(self) -> None:
        settings = PyritSettings(dataset_names=["dataset_a"])
        assert settings.dataset_names == ["dataset_a"]

    def test_set_max_seeds(self) -> None:
        settings = PyritSettings(max_seeds=10)
        assert settings.max_seeds == 10

    def test_set_max_attacks(self) -> None:
        settings = PyritSettings(max_attacks=25)
        assert settings.max_attacks == 25

    def test_max_attacks_none_accepted(self) -> None:
        settings = PyritSettings(max_attacks=None)
        assert settings.max_attacks is None


class TestEnvVarOverrides:
    def test_max_attacks_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_ATTACKS", "50")
        settings = PyritSettings()
        assert settings.max_attacks == 50
