import pytest

from pentester.config.auditors.garak_settings import GarakSettings


class TestDefaults:
    def test_probes_default(self) -> None:
        assert GarakSettings().probes == []

    def test_generations_default(self) -> None:
        assert GarakSettings().generations == 1

    def test_seed_default(self) -> None:
        assert GarakSettings().seed == 42

    def test_max_attacks_default_is_none(self) -> None:
        assert GarakSettings().max_attacks is None


class TestDirectInit:
    def test_set_probes(self) -> None:
        settings = GarakSettings(probes=["probes.dan"])
        assert settings.probes == ["probes.dan"]

    def test_set_generations(self) -> None:
        settings = GarakSettings(generations=3)
        assert settings.generations == 3

    def test_set_seed(self) -> None:
        settings = GarakSettings(seed=0)
        assert settings.seed == 0

    def test_set_max_attacks(self) -> None:
        settings = GarakSettings(max_attacks=50)
        assert settings.max_attacks == 50

    def test_max_attacks_none_accepted(self) -> None:
        settings = GarakSettings(max_attacks=None)
        assert settings.max_attacks is None


class TestEnvVarOverrides:
    def test_max_attacks_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MAX_ATTACKS", "100")
        settings = GarakSettings()
        assert settings.max_attacks == 100
