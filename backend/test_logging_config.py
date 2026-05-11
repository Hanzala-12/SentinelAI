"""
Unit tests for logging configuration.
"""

import logging

from backend.logging_config import configure_logging, get_ml_logger


def test_configure_logging():
    """Test that configure_logging sets up basic logging."""
    # Reset root logger to ensure clean state
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    
    configure_logging("DEBUG")
    
    # Verify handlers were added
    assert len(root_logger.handlers) > 0


def test_get_ml_logger():
    """Test that get_ml_logger creates ML-specific loggers."""
    logger = get_ml_logger("test_module")
    
    # Verify logger name has ml prefix
    assert logger.name == "ml.test_module"
    
    # Verify logger has handlers
    assert len(logger.handlers) > 0
    
    # Verify logger doesn't propagate (to avoid duplicate logs)
    assert logger.propagate is False


def test_ml_logger_formatting():
    """Test that ML logger has correct formatting."""
    logger = get_ml_logger("test_formatting")
    
    # Get the handler
    handler = logger.handlers[0]
    
    # Verify formatter includes ML marker
    formatter = handler.formatter
    assert formatter is not None
    assert "ML" in formatter._fmt


def test_multiple_ml_loggers():
    """Test that multiple ML loggers can be created."""
    logger1 = get_ml_logger("module1")
    logger2 = get_ml_logger("module2")
    
    assert logger1.name == "ml.module1"
    assert logger2.name == "ml.module2"
    assert logger1 is not logger2
