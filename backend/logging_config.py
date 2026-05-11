import logging
import sys


def configure_logging(log_level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def get_ml_logger(name: str) -> logging.Logger:
    """Get a logger configured for ML components.
    
    This function creates a logger specifically for ML-related components with
    appropriate formatting and handlers. ML loggers include additional context
    for debugging ML inference issues.
    
    Args:
        name: Logger name (typically __name__ of the calling module)
        
    Returns:
        Configured logger instance
        
    Example:
        >>> logger = get_ml_logger(__name__)
        >>> logger.info("ML inference completed", extra={"latency_ms": 45.2})
    """
    logger = logging.getLogger(f"ml.{name}")
    
    # Add ML-specific handler if not already present
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)s | ML | %(name)s | %(message)s"
            )
        )
        logger.addHandler(handler)
        logger.propagate = False
    
    return logger
