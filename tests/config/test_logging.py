import logging

from pentester.config.logging import get_logger, setup_logging


def test_setup_logging_sets_warning_level_by_default() -> None:
    setup_logging()
    logger = logging.getLogger("pentester")
    assert logger.level == logging.WARNING


def test_setup_logging_sets_custom_level() -> None:
    setup_logging(level=logging.DEBUG)
    logger = logging.getLogger("pentester")
    assert logger.level == logging.DEBUG


def test_setup_logging_console_only_by_default() -> None:
    setup_logging()
    logger = logging.getLogger("pentester")
    handler_classes = [type(h) for h in logger.handlers]
    assert logging.StreamHandler in handler_classes
    assert logging.handlers.RotatingFileHandler not in handler_classes  # type: ignore[attr-defined]


def test_setup_logging_adds_file_handler_when_requested() -> None:
    setup_logging(log_file=True)
    logger = logging.getLogger("pentester")
    handler_classes = [type(h) for h in logger.handlers]
    assert any(
        issubclass(cls, logging.handlers.RotatingFileHandler)  # type: ignore[attr-defined]
        for cls in handler_classes
    )


def test_get_logger_returns_logger_instance() -> None:
    logger = get_logger("scanners")
    assert isinstance(logger, logging.Logger)


def test_get_logger_namespaces_under_pentester() -> None:
    logger = get_logger("scanners")
    assert logger.name == "pentester.scanners"


def test_get_logger_does_not_double_prefix() -> None:
    logger = get_logger("pentester.scanners")
    assert logger.name == "pentester.scanners"
