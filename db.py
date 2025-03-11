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
        """ Create necessary tables if they don't exist and add new columns if missing. """
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS subnets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cidr TEXT UNIQUE NOT NULL,
                    note TEXT NOT NULL,
                    cust TEXT,
                    cust_email TEXT,
                    dev_type TEXT,
                    dev_ip TEXT,
                    dev_user TEXT,
                    dev_pass TEXT,
                    cgw_ip TEXT,
                    vpn1_psk TEXT,
                    vpn2_psk TEXT
                )
            """)
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during initialization: {e}")

    def add_subnet(self, cidr, note, cust=None, cust_email=None, dev_type=None,
                dev_ip=None, dev_user=None, dev_pass=None, cgw_ip=None, vpn1_psk=None, vpn2_psk=None):
        """ Add a subnet with all fields """
        try:
            self.cursor.execute("""
                INSERT INTO subnets (cidr, note, cust, cust_email, dev_type, dev_ip, 
                                    dev_user, dev_pass, cgw_ip, vpn1_psk, vpn2_psk) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cidr, note, cust, cust_email, dev_type, dev_ip, dev_user, dev_pass, cgw_ip, vpn1_psk, vpn2_psk))
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

    def update_subnet(self, subnet_id, cidr, note, cust, cust_email, dev_type,
                    dev_ip, dev_user, dev_pass, cgw_ip, vpn1_psk, vpn2_psk):
        """ Update subnet details """
        try:
            self.cursor.execute("""
                UPDATE subnets SET cidr = ?, note = ?, cust = ?, cust_email = ?, dev_type = ?, 
                dev_ip = ?, dev_user = ?, dev_pass = ?, cgw_ip = ?, vpn1_psk = ?, vpn2_psk = ? 
                WHERE id = ?
            """, (cidr, note, cust, cust_email, dev_type, dev_ip, dev_user, dev_pass, cgw_ip, vpn1_psk, vpn2_psk, subnet_id))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    def search_subnets(self, query):
        """ Search for subnets by relevant displayed fields """
        try:
            self.cursor.execute(
                """SELECT id, cidr, note, cust, cust_email, dev_type, cgw_ip 
                FROM subnets 
                WHERE cidr LIKE ? OR note LIKE ? OR cust LIKE ? OR cust_email LIKE ? 
                OR dev_type LIKE ? OR cgw_ip LIKE ?""",
                (f"%{query}%",) * 6,
            )
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []

    def get_all_subnets(self):
        """ Retrieve all subnets with new fields """
        try:
            self.cursor.execute("SELECT * FROM subnets")
            columns = [desc[0] for desc in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []

    def close(self):
        """ Close the database connection """
        self.conn.close()
