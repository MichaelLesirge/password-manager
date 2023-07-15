import base64
import os
import pickle

from cryptography import fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class WrongPasscodeException(fernet.InvalidToken): pass

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
    return base64.urlsafe_b64encode(Fernet(key).encrypt(data.encode()))


def decrypt_str(encrypted_data: bytes, key: bytes) -> str:
    return Fernet(key).decrypt(base64.urlsafe_b64decode(encrypted_data)).decode()


def encrypt_dict(obj: dict, key: bytes) -> bytes:
    return Fernet(key).encrypt(pickle.dumps(obj, pickle.HIGHEST_PROTOCOL))


def decrypt_dict(encrypted_obj: bytes, key: bytes) -> dict:
    return pickle.loads(Fernet(key).decrypt(encrypted_obj))


def main():
    salt = get_new_salt()
    key = generate_key("encryption passcode", salt)

    in_string = "Super secret code"

    encrypted_string = encrypt_str(in_string, key)
    out_string = decrypt_str(encrypted_string, key)

    assert in_string == out_string, f"In and out strings not equal, {in_string=}, {out_string=}"

    print(f"{in_string} => {encrypted_string} =>{out_string}")


if __name__ == "__main__":
    main()
