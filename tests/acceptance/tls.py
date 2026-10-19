"""A throwaway certificate authority, so fake providers can serve real HTTPS."""

from __future__ import annotations

import datetime
import ipaddress
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class ProviderCA:
    ca_file: Path
    cert_file: Path
    key_file: Path
    ca_key_file: Path | None = None  # to issue more certificates (issue_cert)

    def client_context(self) -> ssl.SSLContext:
        """Trusts this CA only, with full hostname checking."""
        return ssl.create_default_context(cafile=str(self.ca_file))


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_ca(directory: Path) -> ProviderCA:
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("ZoeyMCP test CA"))
        .issuer_name(_name("ZoeyMCP test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_key_file = directory / "ca.key"
    ca_key_file.write_bytes(_pem_key(ca_key))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_file = directory / "ca.pem"
    cert_file = directory / "server.pem"
    key_file = directory / "server.key"
    ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(_pem_key(key))
    return ProviderCA(ca_file, cert_file, key_file, ca_key_file)


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def issue_cert(ca: ProviderCA, name: str, directory: Path) -> tuple[Path, Path]:
    """A server certificate from ``ca`` for ``name`` only: (certificate, key) files."""
    if ca.ca_key_file is None:
        raise ValueError("this CA kept no key")
    ca_key = serialization.load_pem_private_key(ca.ca_key_file.read_bytes(), password=None)
    assert isinstance(ca_key, ec.EllipticCurvePrivateKey)
    ca_cert = x509.load_pem_x509_certificate(ca.ca_file.read_bytes())
    now = datetime.datetime.now(datetime.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_file = directory / f"{name}.pem"
    key_file = directory / f"{name}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(_pem_key(key))
    return cert_file, key_file
