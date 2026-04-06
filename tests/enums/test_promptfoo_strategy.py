from pentester.enums.promptfoo_strategy import PromptfooMultiturnStrategy


class TestPromptfooMultiturnStrategyValues:
    def test_crescendo_value(self) -> None:
        assert PromptfooMultiturnStrategy.CRESCENDO == "crescendo"

    def test_goat_value(self) -> None:
        assert PromptfooMultiturnStrategy.GOAT == "goat"

    def test_mischievous_user_value(self) -> None:
        assert PromptfooMultiturnStrategy.MISCHIEVOUS_USER == "mischievous-user"

    def test_all_members_present(self) -> None:
        assert len(PromptfooMultiturnStrategy) == 3

    def test_members_are_strings(self) -> None:
        for member in PromptfooMultiturnStrategy:
            assert isinstance(member, str)
