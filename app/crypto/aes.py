"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from app.common.utils import b64e, b64d


def encrypt(key: bytes, plaintext: bytes) -> str:
    """
    Encrypt plaintext using AES-128 ECB mode with PKCS#7 padding.
    
    Args:
        key: 16-byte AES key
        plaintext: Plaintext bytes to encrypt
        
    Returns:
        Base64-encoded ciphertext string
    """
    if len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # Encrypt with AES-128 ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return b64e(ciphertext)


def decrypt(key: bytes, ciphertext_b64: str) -> bytes:
    """
    Decrypt ciphertext using AES-128 ECB mode and remove PKCS#7 padding.
    
    Args:
        key: 16-byte AES key
        ciphertext_b64: Base64-encoded ciphertext string
        
    Returns:
        Decrypted plaintext bytes
    """
    if len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    
    # Decode base64
    ciphertext = b64d(ciphertext_b64)
    
    # Decrypt with AES-128 ECB
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    return plaintext
