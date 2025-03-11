# main.py
"""
IP Address Management (IPAM) Tool - Main Application Entry Point
"""
import logging
import config
import my_logging
from db import DatabaseManager
from gui import start_gui


def main():
    """
    Main application entry point. Initializes the database connection
    and starts the GUI application.
    """
    logging.info("Starting IPAM Tool version %s", config.VERSION)
    
    try:
        # Create database manager without encryption manager (will be set in GUI)
        db_manager = DatabaseManager(config.DATABASE_PATH, None)
        
        # Start the GUI with the database manager
        start_gui(db_manager)
    except Exception as e:
        logging.critical("Fatal error in main application: %s", str(e), exc_info=True)
        raise


if __name__ == "__main__":
    main()