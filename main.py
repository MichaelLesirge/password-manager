import datetime
import getpass

from cryptography import fernet

from encryption import decrypt_dict, encrypt_dict, generate_key
from password_manager import PasscodeManager

# Todo: hide bin data in image file

class Config:
    FILENAME = "pry-pass-bin.bin"
    DATE_FORMAT = '%a %b %d %Y at %I:%M:%S %p'
    PASSWORD_GUESS_MAX_ATTEMPTS = 3
    
    GENORATED_PASSWORD_LENGTH_VARIATION = 3
    GENORATED_PASSWORD_LENGTH = 21
    
    MAX_SESSION_LENGTH = datetime.timedelta(minutes=2)

def sinput(prompt = "", trail = ": ") -> str:
    return input(prompt + trail).strip()

def sprint(text = "", trail = ".") -> str:
    if text: text = text[0].upper() + text[1:]
    print(text + trail if len(text) > 1 else "")

def bool_input(prompt = "") -> bool:
    return sinput(prompt + " [y/n]").lower() == "y"

                
def main(): 
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
            decrypted_data = {} if encrypted_file_contents is None else decrypt_dict(encrypted_file_contents, file_key)
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
            file.write(encrypt_dict(decrypted_data, file_key))
        
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
                passcode_manager.save()         
            else:     
                sprint(f"no data{' new' if passcode_manager.has_updated_data else ''} to save")
            
        elif action == "q":
            if passcode_manager.has_unsaved_data and not bool_input("You have unsaved data, would you like to save it before you quit"):
                passcode_manager.save()         
                
            sprint("quitting")
            going = False
                
        elif action == "m":
            sprint(passcode_manager.genorate_random_password(Config.GENORATED_PASSWORD_LENGTH, Config.GENORATED_PASSWORD_LENGTH_VARIATION))
            
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