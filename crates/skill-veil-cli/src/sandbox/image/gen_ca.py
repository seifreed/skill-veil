#!/usr/bin/env python3
"""Generate the sandbox's throwaway MITM certificate authority at image
build time.

The CA private key is baked into the image so the recording proxy can mint
per-host leaf certificates on the fly and decrypt the sandbox's outbound
HTTPS. This is safe precisely because the CA is ephemeral and image-local:
it is trusted ONLY inside the skill-veil-sandbox image (added to that
image's trust store at build), never on the host, and the sandbox runs
fully isolated. A new build mints a new CA.
"""
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

CA_DIR = "/sv-ca"


def main():
    os.makedirs(CA_DIR, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "skill-veil sandbox MITM CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    with open(os.path.join(CA_DIR, "ca.key"), "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open(os.path.join(CA_DIR, "ca.crt"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    main()
