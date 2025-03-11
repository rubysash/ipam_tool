import logging
import config


def setup_logging():
    """
    Configure logging system for the application.

    - Logs messages to a file and console.
    - Uses the log level from config.py.
    """
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)

    # Configure logging to file
    logging.basicConfig(
        filename="ipam.log",
        level=log_level,
        format=log_format,
        filemode="a",
    )

    # Configure logging to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(log_format))

    # Get root logger and add console handler
    logger = logging.getLogger()
    logger.addHandler(console_handler)


def get_logger(name=None):
    """
    Get a properly configured logger.
    
    Args:
        name (str, optional): Logger name, typically __name__ from the calling module.
            If None, returns the root logger.
    
    Returns:
        logging.Logger: Configured logger instance
    """
    if name:
        return logging.getLogger(name)
    return logging.getLogger()


# Initialize logging when the module is imported
setup_logging()
