"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from app.common.utils import b64e, b64d


def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> str:
    """
    Sign data using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        private_key: RSA private key
        data: Data bytes to sign
        
    Returns:
        Base64-encoded signature string
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return b64e(signature)


def verify_signature(
    public_key: rsa.RSAPublicKey,
    data: bytes,
    signature_b64: str
) -> bool:
    """
    Verify RSA PKCS#1 v1.5 SHA-256 signature.
    
    Args:
        public_key: RSA public key
        data: Original data bytes
        signature_b64: Base64-encoded signature
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        signature = b64d(signature_b64)
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def sign_with_cert_private_key(
    cert: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
    data: bytes
) -> str:
    """
    Sign data using private key associated with certificate.
    Verifies that the private key matches the certificate's public key.
    
    Args:
        cert: X.509 certificate
        private_key: RSA private key
        data: Data bytes to sign
        
    Returns:
        Base64-encoded signature string
    """
    # Verify that private key matches certificate
    cert_public_key = cert.public_key()
    private_public_key = private_key.public_key()
    
    # Compare public key numbers
    if (cert_public_key.public_numbers() != private_public_key.public_numbers()):
        raise ValueError("Private key does not match certificate")
    
    return sign_data(private_key, data)


def verify_with_cert(
    cert: x509.Certificate,
    data: bytes,
    signature_b64: str
) -> bool:
    """
    Verify signature using public key from certificate.
    
    Args:
        cert: X.509 certificate containing public key
        data: Original data bytes
        signature_b64: Base64-encoded signature
        
    Returns:
        True if signature is valid, False otherwise
    """
    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    
    return verify_signature(public_key, data, signature_b64)
