from gui import start_gui
from db import DatabaseManager
import config

def main():
    """Initialize the application and launch GUI."""
    db_manager = DatabaseManager(config.DATABASE_PATH, None)  # EncryptionManager initialized in GUI
    start_gui(db_manager)

if __name__ == "__main__":
    main()