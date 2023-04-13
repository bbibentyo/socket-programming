from typing import Tuple
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _certificate_subject() -> x509.Name:
    """Create certificate subject"""
    return x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "CA"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Manitoba"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Winnipeg"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Company Inc."),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "company.com"),
    ])


def _certificate_subject_alternative_name() -> x509.SubjectAlternativeName:
    """Create certificate subject alternative name"""
    return x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ])


def generate_certificate_signing_request(signing_key) -> x509.CertificateSigningRequest:
    """Generate a certificate signing request for our public key"""
    # Create the builder and set the parameters.
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        _certificate_subject()
    ).add_extension(
        _certificate_subject_alternative_name(),
        critical=False,
    )

    # Sign the CSR with our private key.
    return builder.sign(signing_key, hashes.SHA256())


def generate_certificate(csr, signing_key) -> x509.Certificate:
    """Generate a self-signed certificate for our public key"""
    # Create the builder and set the parameters.
    # For self-signed certificates the issuer and subject are always the same.
    builder = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        csr.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        _certificate_subject_alternative_name(),
        critical=False,
    )
    # Sign the certificate with our private key
    return builder.sign(signing_key, hashes.SHA256())


def write_csr_to_file(csr, filename, path=None) -> None:
    """Save our certificate signing request to disk for safe keeping"""
    if path:
        filename = os.path.join(path, filename)

    with open(filename, 'wb') as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def load_csr_from_file(file_path) -> x509.CertificateSigningRequest:
    """Load the certificate signing request from disk"""
    with open(file_path, 'rb') as f:
        return x509.load_pem_x509_csr(f.read())


def write_certificate_to_file(certificate, filename, path=None) -> None:
    """Save our certificate to disk for safe keeping"""
    if path:
        filename = os.path.join(path, filename)

    with open(filename, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))


def load_certificate_from_file(file_path) -> x509.Certificate:
    """Load the certificate from disk"""
    with open(file_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read())


def generate_RSA_key_pair(passphrase: str, bits=4086) -> Tuple[rsa.RSAPrivateKey, bytes, bytes]:
    """Generate an RSA keypair with an exponent of 65537 in PEM format"""
    new_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    public_key_pem = new_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_key_pem = new_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    return new_key, private_key_pem, public_key_pem


def write_key_to_file(key, filename, path=None) -> None:
    """Save our key to disk for safe keeping"""
    if path:
        filename = os.path.join(path, filename)

    with open(filename, 'wb') as f:
        f.write(key)


def read_private_key_from_file(file_path: str, passphrase: str = None) -> rsa.RSAPrivateKey:
    """Load the private key from disk"""
    with open(file_path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=passphrase.encode() if passphrase else None
        )


def read_public_key_from_file(file_path) -> rsa.RSAPublicKey:
    """Load the public key from disk"""
    with open(file_path, 'rb') as f:
        return serialization.load_pem_public_key(
            f.read()
        )


def encrypt_RSA(message: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """We encrypt the message with the public key"""
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_RSA(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """We decrypt the message with the private key"""
    return private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def create_PKCS12_file(
    name: str, key: rsa.RSAPrivateKey, cert: x509.Certificate, passphrase: str
) -> bytes:
    """Convert a private key and certificate from PEM to P12"""
    return serialization.pkcs12.serialize_key_and_certificates(
        name=name.encode(),
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )
    


private_key_filename = 'localhost_private_key.pem'
public_key_filename = 'localhost_public_key.pem'
csr_filename = 'localhost_csr.pem'
certificate_filename = 'localhost_certificate.pem'
pkcs12_filename = 'localhost.p12'


if __name__ == "__main__":
    ## Generate a new private key
    ## prompt user for password and confirm it twice to make sure there are no typos
    import getpass
    password = getpass.getpass('Enter private key password: ')
    password_confirm = getpass.getpass('Confirm your password: ')
    if password != password_confirm:
        raise ValueError('Passwords do not match')
    private_key, private_key_pem, public_key_pem = generate_RSA_key_pair(password)
    ## Save our private key for safe keeping
    # write_key_to_file(private_key_pem, private_key_filename)
    ## Save our public key for safe keeping
    # write_key_to_file(public_key_pem, public_key_filename)
    ## Load our private key
    # private_key = read_private_key_from_file(private_key_filename, 'password')
    ## Load our public key
    # public_key = read_public_key_from_file(public_key_filename)
    ## Generate a certificate signing request
    csr = generate_certificate_signing_request(private_key)
    ## Save our certificate signing request for safe keeping
    # write_csr_to_file(csr, csr_filename)
    ## Load our certificate signing request
    # csr = load_csr_from_file(csr_filename)
    ## Generate a certificate
    certificate = generate_certificate(csr, private_key)
    ## Save our certificate for safe keeping
    # write_certificate_to_file(certificate, certificate_filename)
    # Load our certificate
    # certificate = load_certificate_from_file(certificate_filename)
    # Encrypt a message with our public key
    original_message = b"Hello World"
    encrypted_message = encrypt_RSA(original_message, private_key.public_key())
    # Decrypt a message with our private key
    decrypted_message = decrypt_RSA(encrypted_message, private_key)
    print(f"{encrypted_message} => {decrypted_message.decode()}")
    print(f"are they equal? {original_message == decrypted_message}")
