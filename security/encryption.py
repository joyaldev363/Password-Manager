import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# OWASP Recommended Iterations for PBKDF2HMAC-SHA256 (600,000)
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16  # 16 bytes = 128 bits


def generate_salt() -> bytes:
    """Generate a cryptographically secure random 16-byte salt."""
    return os.urandom(SALT_SIZE)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from the master password and salt using PBKDF2-HMAC-SHA256.
    Returns a url-safe base64-encoded key suitable for Fernet encryption.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(master_password.encode('utf-8'))
    return base64.urlsafe_b64encode(raw_key)


def encrypt_password(plaintext: str, fer_key: bytes) -> str:
    """
    Encrypt a plaintext string using Fernet (AES-128-CBC + HMAC-SHA256).
    Returns base64-encoded string representation of ciphertext.
    """
    if not plaintext:
        return ""
    fernet = Fernet(fer_key)
    ciphertext_bytes = fernet.encrypt(plaintext.encode('utf-8'))
    return ciphertext_bytes.decode('utf-8')


def decrypt_password(ciphertext: str, fer_key: bytes) -> str:
    """
    Decrypt a Fernet-encrypted ciphertext string.
    Raises InvalidToken if key is incorrect or data is tampered.
    """
    if not ciphertext:
        return ""
    try:
        fernet = Fernet(fer_key)
        decrypted_bytes = fernet.decrypt(ciphertext.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except (InvalidToken, Exception) as e:
        raise ValueError("Decryption failed. Incorrect key or corrupted data.") from e
