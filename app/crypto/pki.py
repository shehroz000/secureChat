"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timezone
from typing import Optional


def load_certificate(cert_path: str) -> x509.Certificate:
    """
    Load X.509 certificate from PEM file.
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        X.509 certificate object
    """
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    return x509.load_pem_x509_certificate(cert_data)


def load_certificate_from_pem(pem_data: str) -> x509.Certificate:
    """
    Load X.509 certificate from PEM string.
    
    Args:
        pem_data: PEM-encoded certificate string
        
    Returns:
        X.509 certificate object
    """
    return x509.load_pem_x509_certificate(pem_data.encode('utf-8'))


def load_private_key(key_path: str):
    """
    Load RSA private key from PEM file.
    
    Args:
        key_path: Path to private key file
        
    Returns:
        Private key object
    """
    with open(key_path, 'rb') as f:
        key_data = f.read()
    return serialization.load_pem_private_key(key_data, password=None)


def validate_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: Optional[str] = None
) -> tuple[bool, Optional[str]]:
    """
    Validate X.509 certificate against CA.
    
    Checks:
    1. Signature chain validity (signed by CA)
    2. Expiry date and validity period
    3. Common Name (CN) match if provided
    
    Args:
        cert: Certificate to validate
        ca_cert: Root CA certificate
        expected_cn: Expected Common Name (optional)
        
    Returns:
        Tuple of (is_valid, error_message)
        If valid, returns (True, None)
        If invalid, returns (False, error_code like "BAD_CERT")
    """
    # Check 1: Verify signature (cert is signed by CA)
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        ca_public_key = ca_cert.public_key()
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            # Verify the certificate signature
            # Use the certificate's signature algorithm
            if cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256:
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            else:
                # Try with the certificate's hash algorithm
                hash_alg = cert.signature_hash_algorithm
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hash_alg
                )
        else:
            return (False, "BAD_CERT: CA public key is not RSA")
    except Exception as e:
        return (False, f"BAD_CERT: Certificate not signed by trusted CA: {str(e)}")
    
    # Check 2: Verify validity period
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        return (False, "BAD_CERT: Certificate not yet valid")
    if cert.not_valid_after_utc < now:
        return (False, "BAD_CERT: Certificate expired")
    
    # Check 3: Verify Common Name if provided
    if expected_cn:
        try:
            # Extract CN from subject
            cn = None
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    cn = attribute.value
                    break
            
            if cn is None:
                return (False, "BAD_CERT: No Common Name in certificate")
            
            if cn != expected_cn:
                return (False, f"BAD_CERT: CN mismatch. Expected {expected_cn}, got {cn}")
        except Exception as e:
            return (False, f"BAD_CERT: Error checking CN: {str(e)}")
    
    return (True, None)


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """
    Get SHA-256 fingerprint of certificate.
    
    Args:
        cert: X.509 certificate
        
    Returns:
        Hex-encoded SHA-256 fingerprint
    """
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()


def get_certificate_cn(cert: x509.Certificate) -> Optional[str]:
    """
    Extract Common Name from certificate.
    
    Args:
        cert: X.509 certificate
        
    Returns:
        Common Name string or None
    """
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return None
