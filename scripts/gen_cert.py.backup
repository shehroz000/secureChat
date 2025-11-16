"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
from app.crypto.pki import load_certificate, load_private_key


def generate_certificate(
    cn: str,
    ca_cert_path: str,
    ca_key_path: str,
    output_prefix: str,
    output_dir: str = "certs"
):
    """
    Generate a certificate signed by the root CA.
    
    Args:
        cn: Common Name (e.g., "server.local" or "client.local")
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
        output_prefix: Prefix for output files (e.g., "server" or "client")
        output_dir: Output directory
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Load CA certificate and key
    ca_cert = load_certificate(ca_cert_path)
    ca_key = load_private_key(ca_key_path)
    
    # Generate RSA private key for the entity
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Certificate valid for 1 year
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn)
        ]),
        critical=False,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=False,
    ).sign(ca_key, hashes.SHA256())
    
    # Save private key
    key_path = os.path.join(output_dir, f"{output_prefix}.key")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Private key saved to: {key_path}")
    
    # Save certificate
    cert_path = os.path.join(output_dir, f"{output_prefix}.crt")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Certificate saved to: {cert_path}")
    
    print(f"\nCertificate for '{cn}' generated successfully!")
    print(f"Certificate fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate certificate signed by Root CA")
    parser.add_argument("--cn", required=True, help="Common Name (e.g., 'server.local')")
    parser.add_argument("--ca-cert", default="certs/ca.crt", help="Path to CA certificate")
    parser.add_argument("--ca-key", default="certs/ca.key", help="Path to CA private key")
    parser.add_argument("--out", default="certs", help="Output directory (default: certs)")
    parser.add_argument("--output-prefix", dest="prefix", help="Output file prefix (default: derived from CN)")
    
    args = parser.parse_args()
    
    # Determine output prefix
    if args.prefix:
        output_prefix = args.prefix
    else:
        # Extract prefix from CN (e.g., "server.local" -> "server")
        output_prefix = args.cn.split('.')[0]
    
    generate_certificate(
        args.cn,
        args.ca_cert,
        args.ca_key,
        output_prefix,
        args.out
    )
