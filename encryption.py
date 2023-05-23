import base64
import os
import pickle

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_new_salt() -> bytes:
    return os.urandom(16)

def generate_key(passcode: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passcode.encode()))
    return key

def encrypt_str(data: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(data.encode())

def decrypt_str(encrypted_data: bytes, key: bytes) -> str:
    return Fernet(key).decrypt(encrypted_data).decode()

def encrypt_dict(obj: dict, key: bytes) -> bytes:
   return Fernet(key).encrypt(pickle.dumps(obj, pickle.HIGHEST_PROTOCOL))

def decrypt_dict(encrypted_obj: bytes, key: bytes) -> dict:
    return pickle.loads(Fernet(key).decrypt(encrypted_obj))