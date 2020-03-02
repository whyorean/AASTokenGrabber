import struct
from base64 import b64decode, urlsafe_b64encode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key

import constants


def read_int(byte_array, start):
    return struct.unpack("!L", byte_array[start:][0:4])[0]


def to_big_int(byte_array):
    array = byte_array[::-1]
    out = 0
    for key, value in enumerate(array):
        if constants.VERSION == 3:
            decoded = struct.unpack("B", bytes([value]))[0]
        else:
            decoded = struct.unpack("B", value)[0]
        out = out | decoded << key * 8
    return out


def encrypt_password(email, password):
    binary_key = b64decode(constants.GOOGLE_PUBKEY)
    i = read_int(binary_key, 0)
    modulus = to_big_int(binary_key[4:][0:i])
    j = read_int(binary_key, i + 4)
    exponent = to_big_int(binary_key[i + 8:][0:j])

    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(binary_key)
    h = b'\x00' + digest.finalize()[0:4]

    der_data = encode_dss_signature(modulus, exponent)
    public_key = load_der_public_key(der_data, backend=default_backend())

    to_be_encrypted = email.encode() + b'\x00' + password.encode()
    cipher_text = public_key.encrypt(
        to_be_encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return urlsafe_b64encode(h + cipher_text)
