import base64
import hashlib
from typing import Optional
from security.encryption import generate_salt, derive_key, PBKDF2_ITERATIONS
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def hash_master_password(password: str, salt: bytes) -> str:
    """
    Generate a secure authentication hash of the master password using PBKDF2-HMAC-SHA256.
    This hash is stored in the database solely to verify master password at login.
    """
    # Use a domain separation suffix to ensure auth hash differs from encryption key
    auth_input = (password + "::auth_verification::").encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_hash = kdf.derive(auth_input)
    return base64.b64encode(raw_hash).decode('utf-8')


def verify_master_password(password: str, stored_hash: str, salt: bytes) -> bool:
    """
    Verify if the provided password matches the stored authentication hash.
    """
    computed_hash = hash_master_password(password, salt)
    return hmac_compare(computed_hash, stored_hash)


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hashlib.sha256(a.encode('utf-8')).digest() == hashlib.sha256(b.encode('utf-8')).digest()


class SessionManager:
    """
    Singleton session manager to securely hold active session encryption key in RAM.
    Wipes key upon session lock or exit.
    """
    _instance = None
    _encryption_key: Optional[bytes] = None
    _is_authenticated: bool = False

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def login(self, master_password: str, salt: bytes) -> None:
        """Derive encryption key and set session as active."""
        self._encryption_key = derive_key(master_password, salt)
        self._is_authenticated = True

    def lock(self) -> None:
        """Wipe session key and lock vault."""
        self._encryption_key = None
        self._is_authenticated = False

    def is_unlocked(self) -> bool:
        return self._is_authenticated and self._encryption_key is not None

    def get_key(self) -> bytes:
        if not self.is_unlocked() or self._encryption_key is None:
            raise PermissionError("Vault is locked. Access denied.")
        return self._encryption_key
