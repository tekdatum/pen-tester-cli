from unittest.mock import MagicMock, patch

from pentester.utils.timer import track_time


class TestTrackTime:
    def test_returns_original_result(self) -> None:
        @track_time
        def add(a: int, b: int) -> int:
            return a + b

        result, _ = add(2, 3)
        assert result == 5

    def test_returns_duration_as_float(self) -> None:
        @track_time
        def noop() -> None:
            pass

        with patch("pentester.utils.timer.logger"):
            _, duration = noop()

        assert isinstance(duration, float)
        assert duration >= 0

    def test_logs_info_for_plain_function(self) -> None:
        mock_logger = MagicMock()

        with patch("pentester.utils.timer.logger", mock_logger):

            @track_time
            def my_func() -> None:
                pass

            my_func()

        mock_logger.info.assert_called_once()
        log_msg = mock_logger.info.call_args[0]
        assert "my_func" in log_msg[0] % (log_msg[1], log_msg[2], log_msg[3])

    def test_logs_class_and_method_name_for_method(self) -> None:
        mock_logger = MagicMock()

        with patch("pentester.utils.timer.logger", mock_logger):

            class MyClass:
                @track_time
                def my_method(self) -> str:
                    return "ok"

            MyClass().my_method()

        mock_logger.info.assert_called_once()
        log_msg = mock_logger.info.call_args[0]
        formatted = log_msg[0] % (log_msg[1], log_msg[2], log_msg[3])
        assert "MyClass.my_method" in formatted

    def test_custom_message_is_logged(self) -> None:
        mock_logger = MagicMock()

        with patch("pentester.utils.timer.logger", mock_logger):

            @track_time(message="custom msg")
            def my_func() -> None:
                pass

            my_func()

        mock_logger.info.assert_called_once()
        log_msg = mock_logger.info.call_args[0]
        formatted = log_msg[0] % (log_msg[1], log_msg[2], log_msg[3])
        assert "custom msg" in formatted

    def test_no_message_logs_empty_suffix(self) -> None:
        mock_logger = MagicMock()

        with patch("pentester.utils.timer.logger", mock_logger):

            @track_time
            def my_func() -> None:
                pass

            my_func()

        log_msg = mock_logger.info.call_args[0]
        assert log_msg[3] == ""

    def test_custom_message_with_method(self) -> None:
        mock_logger = MagicMock()

        with patch("pentester.utils.timer.logger", mock_logger):

            class MyService:
                @track_time(message="heavy step")
                def run(self) -> int:
                    return 1

            MyService().run()

        log_msg = mock_logger.info.call_args[0]
        formatted = log_msg[0] % (log_msg[1], log_msg[2], log_msg[3])
        assert "MyService.run" in formatted
        assert "heavy step" in formatted

    def test_logs_duration_as_float(self) -> None:
        mock_logger = MagicMock()

        with patch("pentester.utils.timer.logger", mock_logger):

            @track_time
            def noop() -> None:
                pass

            noop()

        duration_arg = mock_logger.info.call_args[0][2]
        assert isinstance(duration_arg, float)
        assert duration_arg >= 0

    def test_preserves_function_metadata(self) -> None:
        @track_time
        def documented() -> None:
            """My docstring."""

        assert documented.__name__ == "documented"
        assert documented.__doc__ == "My docstring."

    def test_passes_args_and_kwargs_to_function(self) -> None:
        mock_fn = MagicMock(return_value=42)
        mock_fn.__name__ = "mock_fn"

        with patch("pentester.utils.timer.logger"):
            decorated = track_time(mock_fn)
            result, _ = decorated(1, 2, key="val")

        mock_fn.assert_called_once_with(1, 2, key="val")
        assert result == 42
