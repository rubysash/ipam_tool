# main.py
"""
IP Address Management (IPAM) Tool - Main Application Entry Point
"""
import config
from my_logging import get_logger
from db import DatabaseManager
from gui import start_gui


# Get logger for this module
logger = get_logger(__name__)


def main():
    """
    Main application entry point. Initializes the database connection
    and starts the GUI application.
    """
    logger.info("Starting IPAM Tool version %s", config.VERSION)
    
    try:
        # Create database manager without encryption manager (will be set in GUI)
        db_manager = DatabaseManager(config.DATABASE_PATH, None)
        
        # Start the GUI with the database manager
        start_gui(db_manager)
    except Exception as e:
        logger.critical("Fatal error in main application: %s", str(e), exc_info=True)
        raise


if __name__ == "__main__":
    main()