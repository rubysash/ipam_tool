import sqlite3


class DatabaseManager:
    """ Handles all database interactions for IPAM """

    def __init__(self, db_path):
        """ Initialize database connection """
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.initialize_db()

    def initialize_db(self):
        """ Create necessary tables if they don't exist """
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS subnets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cidr TEXT UNIQUE NOT NULL,
                    note TEXT NOT NULL
                )
            """)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during initialization: {e}")

    def add_subnet(self, cidr, note):
        """ Add a subnet with a note """
        try:
            self.cursor.execute(
                "INSERT INTO subnets (cidr, note) VALUES (?, ?)", (cidr, note)
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            print(f"Error: Subnet {cidr} already exists.")
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    def delete_subnet(self, subnet_id):
        """ Delete a subnet by its ID instead of CIDR """
        try:
            self.cursor.execute("DELETE FROM subnets WHERE id = ?", (subnet_id,))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")


    def update_subnet(self, subnet_id, cidr, note):
        """ Update subnet details (CIDR, note) """
        try:
            self.cursor.execute(
                "UPDATE subnets SET cidr = ?, note = ? WHERE id = ?", (cidr, note, subnet_id)
            )
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    def search_subnets(self, query):
        """ Search for subnets by CIDR or note """
        try:
            self.cursor.execute(
                "SELECT id, cidr, note FROM subnets WHERE cidr LIKE ? OR note LIKE ?",
                (f"%{query}%", f"%{query}%"),
            )
            return [{"id": row[0], "cidr": row[1], "note": row[2]} for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []

    def get_all_subnets(self):
        """ Retrieve all subnets from the database """
        try:
            self.cursor.execute("SELECT id, cidr, note FROM subnets")
            return [{"id": row[0], "cidr": row[1], "note": row[2]} for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []

    def close(self):
        """ Close the database connection """
        self.conn.close()
