
class Config:
    STOP_CODE = b'#####'

def to_binary(data: bytes | int) -> str:
    if isinstance(data, int):
        return format(data, "08b")
    return "".join(to_binary(i) for i in data)

def encode(image: bytes, secret_data: bytes) -> bytes:
    new_image = bytearray(image)
    secret_data += Config.STOP_CODE
    
    if len(secret_data) > len(new_image) / 8:
        raise Exception(f"The {len(secret_data)} bytes of data could not fit in the {len(new_image) / 8} byte avialble bytes of the {len(new_image)} byte image. Need bigger image.")
        
    binary_secret_data = to_binary(secret_data)
 
    for i, bit in enumerate(binary_secret_data):
        i += 171
        new_byte = int(to_binary(new_image[i])[:-1] + bit, base=2)
        print(bit, to_binary(image[i]), to_binary(new_byte))
        new_image[i] = new_byte
    
    return bytes(new_image)

with open("image.png", "rb") as file:
    image = file.read()

new_image = encode(image, b'Hello World')

with open("image2.png", "wb") as file:
    file.write(new_image)