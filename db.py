import sqlite3
from encryption import EncryptionManager 

class DatabaseManager:
    """ Handles all database interactions for IPAM """

    def __init__(self, db_path, encryption_manager):
        """ Initialize database connection """
        self.db_path = db_path
        self.enc = encryption_manager
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.initialize_db()

    def initialize_db(self):
        """ Create necessary tables if they don't exist. """
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

    def delete_subnet(self, subnet_id):
        """ Delete a subnet by its ID """
        try:
            self.cursor.execute("DELETE FROM subnets WHERE id = ?", (subnet_id,))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    def add_subnet(self, cidr, note, cust, cust_email, dev_type, dev_ip, dev_user, dev_pass, cgw_ip, vpn1_psk, vpn2_psk):
        """Encrypt and add a subnet."""
        try:
            self.cursor.execute("""
                INSERT INTO subnets (cidr, note, cust, cust_email, dev_type, dev_ip, dev_user, dev_pass, cgw_ip, vpn1_psk, vpn2_psk) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.enc.encrypt(cidr), self.enc.encrypt(note), self.enc.encrypt(cust), self.enc.encrypt(cust_email),
                self.enc.encrypt(dev_type), self.enc.encrypt(dev_ip), self.enc.encrypt(dev_user), self.enc.encrypt(dev_pass),
                self.enc.encrypt(cgw_ip), self.enc.encrypt(vpn1_psk), self.enc.encrypt(vpn2_psk)
            ))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    def update_subnet(self, subnet_id, cidr, note, cust, cust_email, dev_type, dev_ip, dev_user, dev_pass, cgw_ip, vpn1_psk, vpn2_psk):
        """Encrypt and update subnet details."""
        try:
            self.cursor.execute("""
                UPDATE subnets SET cidr = ?, note = ?, cust = ?, cust_email = ?, dev_type = ?, 
                dev_ip = ?, dev_user = ?, dev_pass = ?, cgw_ip = ?, vpn1_psk = ?, vpn2_psk = ? 
                WHERE id = ?
            """, (
                self.enc.encrypt(cidr), self.enc.encrypt(note), self.enc.encrypt(cust), self.enc.encrypt(cust_email),
                self.enc.encrypt(dev_type), self.enc.encrypt(dev_ip), self.enc.encrypt(dev_user), self.enc.encrypt(dev_pass),
                self.enc.encrypt(cgw_ip), self.enc.encrypt(vpn1_psk), self.enc.encrypt(vpn2_psk), subnet_id
            ))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    def get_all_subnets(self):
        """Retrieve all subnets and decrypt fields before returning."""
        try:
            self.cursor.execute("SELECT * FROM subnets")
            columns = [desc[0] for desc in self.cursor.description]
            decrypted_subnets = []

            for row in self.cursor.fetchall():
                try:
                    decrypted_entry = {
                        col: self.enc.decrypt(row[i])
                        if col not in ["id"] and row[i] is not None else row[i]
                        for i, col in enumerate(columns)
                    }
                    decrypted_subnets.append(decrypted_entry)
                except Exception as e:
                    print(f"Decryption error: {e}")

            return decrypted_subnets
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []

    def search_subnets(self, query):
        """Retrieve subnets and search locally after decrypting."""
        try:
            all_subnets = self.get_all_subnets()
            return [subnet for subnet in all_subnets if query.lower() in str(subnet.values()).lower()]
        except Exception as e:
            print(f"Search error: {e}")
            return []

    def close(self):
        """ Close the database connection """
        self.conn.close()
