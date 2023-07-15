import random

from encryption import decrypt_str, encrypt_str

def char_range(start_char: str, end_char: str) -> str:
    return "".join(chr(i) for i in range(ord(start_char), ord(end_char)+1))

class ItemExistsError(Exception):
    def __init__(self, message="Item already exists", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        
class ItemDoesNotExistsError(Exception):
    def __init__(self, message="Item does not exist", *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        
class PasscodeManager:
    def __init__(self, passcode_data: dict, key: bytes, saver: callable) -> None:
        if passcode_data is None:
            passcode_data = {}

        self.passcode_data = passcode_data

        self.has_unsaved_data = False
        self.has_updated_data = False

        self.key = key

        self.saver = saver

    def save(self) -> bool:
        if not self.has_unsaved_data:
            return
        self.saver()
        self.has_unsaved_data = False

    def _get(self, item_name: str) -> tuple[str, str]:
        try:
            username, encrypted_passcode = self.passcode_data[item_name]
        except KeyError as ex:
            raise ItemDoesNotExistsError
        return username, decrypt_str(encrypted_passcode, self.key)

    def _set(self, item_name: str, username: str, passcode: str) -> None:
        self.passcode_data[item_name] = (username, encrypt_str(passcode, self.key))
        self.has_unsaved_data = self.has_updated_data = True

    def has_item(self, item_name: str) -> bool:
        return item_name in self.passcode_data

    def create(self, item_name: str, username: str, passcode: str) -> bool:
        if self.has_item(item_name): raise ItemExistsError()
        self._set(item_name, username, passcode)

    def read(self, item_name: str) -> tuple[str, str]:
        return self._get(item_name)

    def update(self, item_name: str, username: str, passcode: str) -> bool:
        old_username, old_password = self.read(item_name)
        if username is None:
            username = old_username
        if passcode is None:
            passcode = old_password
        self._set(item_name, username, passcode)

    def delete(self, item_name: str) -> None:
        del self.passcode_data[item_name]
        self.has_unsaved_data = self.has_updated_data = True

    def get_item_names(self) -> list[str]:
        return list(self.passcode_data.keys())

    def generate_random_password(self, length=16, length_variation=0):
        length += random.randint(-length_variation, +length_variation)
        chars = char_range("a", "z") + char_range("A", "Z") + char_range("0", "9") + "!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'"
        password = ''.join(random.choice(chars) for _ in range(length))
        return password
