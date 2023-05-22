import base64
import os
from cryptography import fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import datetime
import json
import getpass
import random
import string

# Todo: hide bin data in image file

class Config:
    FILENAME = "pry-pass-bin.bin"
    DATE_FORMAT = '%a %b %d %Y at %I:%M:%S %p'
    PASSWORD_GUESS_MAX_ATTEMPTS = 3
    
    GENORATED_PASSWORD_LENGTH = 21
    GENORATED_PASSWORD_LENGTH_VARIATION = 3
    MAX_SESSION_LENGTH = datetime.timedelta(minutes=2)

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

def encrypt_json(obj: dict, key: bytes) -> bytes:
   return encrypt_str(json.dumps(obj), key)

def decrypt_json(encrypted_obj: bytes, key: bytes) -> dict:
    return json.loads(decrypt_str(encrypted_obj, key))

def sinput(prompt = "", trail = ": ") -> str:
    return input(prompt + trail).strip()

def sprint(text = "", trail = ".") -> str:
    if text: text = text[0].upper() + text[1:]
    print(text + trail if len(text) > 1 else "")

def bool_input(prompt = "") -> bool:
    return sinput(prompt + " [y/n]").lower() == "y"

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
        if not self.has_unsaved_data: return
        self.saver()
        self.has_unsaved_data = False

    def _get(self, item_name: str) -> tuple[str, str]:
        username, encrypted_passcode = self.passcode_data[item_name]
        return username, decrypt_str(base64.urlsafe_b64decode(encrypted_passcode), self.key)
    
    def _set(self, item_name: str, username: str, passcode: str) -> None:
        self.passcode_data[item_name] = (username, base64.urlsafe_b64encode(encrypt_str(passcode, self.key)).decode())
        self.has_unsaved_data = self.has_updated_data = True

    def has_item(self, item_name: str) -> bool:
        return item_name in self.passcode_data
    
    def create(self, item_name: str, username: str, passcode: str) -> bool:     
        self._set(item_name, username, passcode)
    
    def read(self, item_name: str) -> tuple[str, str]:
        return self._get(item_name)
    
    def update(self, item_name: str, username: str, passcode: str) -> bool:
        old_username, old_password = self.read(item_name)
        if username is None: username = old_username
        if passcode is None: passcode = old_password
        self._set(item_name, username, passcode)
    
    def delete(self, item_name: str) -> None:
        del self.passcode_data[item_name]
        self.has_unsaved_data = self.has_updated_data = True
    
    def get_item_names(self) -> list[str]:
        return list(self.passcode_data.keys())
    
    def genorate_random_password(self, length = 16):
        actionacters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(actionacters) for _ in range(length))
        return password
                
def main(): 
    # file_salt = get_new_salt()
    file_salt = b'\xbeZ/\xa0S\xed\xf97\xc8\xf1e\xa32_\xbc|'
    passcode_salt = b'\xbeZ/\xa0S\xed\xf97\xc8\xf1e\xa32_\xbc|'
    
    try:
        with open(Config.FILENAME, "rb") as file:
            encrypted_file_contents = file.read()
    except FileNotFoundError:
        encrypted_file_contents = None

    wrong_count = 0
    
    decrypted_data = None
    while decrypted_data is None and wrong_count <= Config.PASSWORD_GUESS_MAX_ATTEMPTS:
        try:
            passcode = getpass.getpass()
            file_key = generate_key(passcode, file_salt)
            passcode_key = generate_key(passcode, passcode_salt)
            decrypted_data = {} if encrypted_file_contents is None else decrypt_json(encrypted_file_contents, file_key)
        except fernet.InvalidToken:
            sprint("incorrect Password")
            wrong_count += 1
            
    if decrypted_data is None:
        sprint("failed to enter correct password too many times")
        return
            
    proggram_start_time = datetime.datetime.now()
    
    last_access = datetime.datetime.fromtimestamp(decrypted_data.setdefault("last-access", 0))
    sprint(f"last access started at {last_access.strftime(Config.DATE_FORMAT)}")
    
    last_write = datetime.datetime.fromtimestamp(decrypted_data.setdefault("last-write", 0))
    sprint(f"last write started at {last_write.strftime(Config.DATE_FORMAT)}")

    passcode_data: dict[str: tuple[str, bytes]] = decrypted_data.setdefault("password-data", {})   
    
    going = True
    # session_exspire_time = proggram_start_time + Config.MAX_SESSION_LENGTH_SECONDS
    
    def save_data():
        decrypted_data["last-write"] = proggram_start_time.timestamp()
        with open(Config.FILENAME, "wb") as file:
            file.write(encrypt_json(decrypted_data, file_key))
        
    passcode_manager = PasscodeManager(passcode_data, passcode_key, save_data)
    
    decrypted_data["last-access"] = proggram_start_time.timestamp()

    end_time = proggram_start_time + Config.MAX_SESSION_LENGTH
    
    sprint()
    # Todo, make more like CLI than choose your own adventure
    while going:
        action = sinput("Action").lower()
        
        if datetime.datetime.now() > end_time:
            sprint("session has exspired")
            action = "q"
        
        if action == "s":
            if passcode_manager.has_unsaved_data:
                try:
                    passcode_manager.save()
                except Exception:
                    sprint("could not save due to an error")
                else:
                    sprint("successfully saved data")
                    
            else:     
                sprint(f"no data{' new' if passcode_manager.has_updated_data else ''} to save")
            
        elif action == "q":
            if passcode_manager.has_unsaved_data and not bool_input("You have unsaved data, would you like to save it before you quit"):
                try:
                    passcode_manager.save()
                except Exception:
                    sprint("could not save due to an Error")
                else:
                    sprint("successfully saved data")
                    
                
            sprint("quitting")
            going = False
                
        elif action == "m":
            passcode_length = Config.GENORATED_PASSWORD_LENGTH + random.randint(-Config.GENORATED_PASSWORD_LENGTH_VARIATION, Config.GENORATED_PASSWORD_LENGTH_VARIATION)
            sprint(passcode_manager.genorate_random_password(passcode_length))
            
        elif action == "l":
            sprint(f"saved item names: {', '.join(passcode_manager.get_item_names())}")
            
        elif action == "c":
            title = sinput("Item name")
            if not passcode_manager.has_item(title):
                username = sinput("Username")
                passcode = sinput("passcode")
                passcode_manager.create(title, username, passcode)
                sprint("added new item")
            else:
                sprint("item already exist")
                                    
        elif action == "r":
            title = sinput("Item name")
            if passcode_manager.has_item(title):
                username, passcode = passcode_manager.read(title)
                sprint(f"username: {username}")
                sprint(f"password: {passcode}")
            else:
                sprint("item does not exist")
                            
        elif action == "u":
            title = sinput("Item name")
            if passcode_manager.has_item(title):
                username = sinput("Username") or None
                passcode = sinput("passcode") or None
                passcode_manager.update(title, username, passcode)
                sprint("updated item")
            else:
                sprint("item does not exist")
                
        elif action == "d":
            if passcode_manager.has_item(title):
                title = sinput("Item name")
                passcode_manager.delete(title)
            else:
                sprint("item does not exist")            
        
        else:
            sprint(f"{action} is not a valid action")
            
        sprint()
    
if __name__ == "__main__":
    main()