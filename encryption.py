import os
import pickle

from aes import encrypt, decrypt

class WrongPasscodeException(Exception): pass

def get_new_salt() -> bytes:
    return os.urandom(16)

def generate_key(passcode: str, salt: bytes) -> bytes:
    return passcode.encode() + salt


def encrypt_str(data: str, key: bytes) -> bytes:
    return encrypt(key, data.encode())


def decrypt_str(encrypted_data: bytes, key: bytes) -> str:
    return decrypt(key, encrypted_data).decode()


def encrypt_dict(obj: dict, key: bytes) -> bytes:
    return encrypt(key, pickle.dumps(obj))


def decrypt_dict(encrypted_obj: bytes, key: bytes) -> dict:
    return pickle.loads(decrypt(key, encrypted_obj))


def main():
    salt = get_new_salt()
    key = generate_key("encryption passcode", salt)

    in_string = "Super secret code"

    encrypted_string = encrypt_str(in_string, key)
    out_string = decrypt_str(encrypted_string, key)

    assert in_string == out_string, f"In and out strings not equal, {in_string=}, {out_string=}"

    print(f"{in_string} => {encrypted_string} => {out_string}")


if __name__ == "__main__":
    main()
