import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import config


class EncryptionManager:
    """Handles AES-256-GCM encryption and decryption with PBKDF2 key derivation"""

    def __init__(self, master_password: str):
        """
        Initialize encryption with a derived key from the master password.
        The key is stored in memory only for the session.
        """
        self.master_password = master_password
        self.salt = self._load_salt()
        self.key = self._derive_key()

    def _load_salt(self):
        """Loads or generates a salt for key derivation"""
        salt_file = config.PASSWORD_FILE
        if os.path.exists(salt_file):
            with open(salt_file, "rb") as f:
                stored_data = f.read()
                return base64.b64decode(stored_data)[:16]  # Extract first 16 bytes as salt

        # If no salt exists, generate a new one and store it
        new_salt = os.urandom(16)
        self._store_salt(new_salt)
        return new_salt

    def _store_salt(self, salt):
        """Store the salt in the password file"""
        with open(config.PASSWORD_FILE, "wb") as f:
            f.write(base64.b64encode(salt))  # Only store the salt for key derivation

    def _derive_key(self):
        """Derives a strong AES-256 key from the master password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=200000,
            backend=default_backend(),
        )
        return kdf.derive(self.master_password.encode())

    def encrypt(self, plaintext: str) -> str:
        """Encrypts a string using AES-256-GCM."""
        if not plaintext:
            return ""

        iv = os.urandom(12)  # 12-byte IV for GCM mode
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def decrypt(self, encrypted_text: str) -> str:
        """Decrypts a string using AES-256-GCM."""
        if not encrypted_text:
            return ""

        try:
            raw_data = base64.b64decode(encrypted_text)
            iv, tag, ciphertext = raw_data[:12], raw_data[12:28], raw_data[28:]
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            # Properly decode bytes to string
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return "DECRYPTION_ERROR"  # Prevent revealing partial data

    @staticmethod
    def store_password_hash(password):
        """Securely store the hashed password with a random salt."""
        salt = os.urandom(16)  # Generate a new random salt
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
        
        # Store salt + hash together
        stored_value = base64.b64encode(salt + hashed_password).decode()
        with open(config.PASSWORD_FILE, "w") as f:
            f.write(stored_value)

    @staticmethod
    def verify_password(password):
        """Verify entered password against stored hash."""
        if not os.path.exists(config.PASSWORD_FILE):
            return False  # No password exists yet

        with open(config.PASSWORD_FILE, "r") as f:
            stored_data = base64.b64decode(f.read().strip())

        salt = stored_data[:16]  # Extract stored salt
        stored_hash = stored_data[16:]  # Extract stored hash

        # Compute hash with extracted salt
        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)

        return computed_hash == stored_hash
