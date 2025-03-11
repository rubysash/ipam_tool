# search.py
import threading
import time
import config


class SearchHandler:
    """ Implements a delayed search mechanism """

    def __init__(self, callback_function):
        """
        Initialize search delay logic.

        Args:
            callback_function (callable): Function to execute after the delay.
        """
        self.callback_function = callback_function
        self.search_thread = None
        self.search_query = ""
        self.lock = threading.Lock()

    def schedule_search(self, query):
        """
        Start a timer for search execution.

        Args:
            query (str): Search query input.
        """
        with self.lock:
            self.search_query = query

        if self.search_thread and self.search_thread.is_alive():
            return  # Avoid creating multiple threads

        self.search_thread = threading.Thread(target=self.execute_delayed_search, daemon=True)
        self.search_thread.start()

    def execute_delayed_search(self):
        """
        Execute the actual search when timer expires.
        Ensures only the latest query is executed.
        """
        time.sleep(config.SEARCH_DELAY)  # Wait for the debounce delay

        with self.lock:
            latest_query = self.search_query

        self.callback_function(latest_query)  # Execute the search callback
