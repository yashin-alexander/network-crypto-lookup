from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from secrets import token_bytes


class DiffieHellman:
    def __init__(self):
        self.diffie_hellman = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self._public_key = self.diffie_hellman.public_key()
        self.IV = None

    @property
    def pem_pubkey(self):
        pem = self._public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return pem

    def encrypt(self, opposite_public_key, secret):
        self.IV = token_bytes(16)
        shared_key = self.diffie_hellman.exchange(ec.ECDH(), opposite_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(self.IV), backend=default_backend())
        encryptor = aes.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(secret.encode()) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, opposite_public_key, secret, iv):
        shared_key = self.diffie_hellman.exchange(ec.ECDH(), opposite_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        aes = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
        decryptor = aes.decryptor()
        decrypted_data = decryptor.update(secret) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()


def load_pem_pubkey(pem):
    return load_pem_public_key(pem, default_backend())
