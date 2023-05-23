# thanks Computerphile. https://youtu.be/TWEXCYQKyDc

class Config:
    STOP_CODE = b'\0'

def to_binary(data: bytes | int) -> str:
    return "".join(format(i, "08b") for i in data)

def get_png_body_position(image: bytes) -> tuple[int, int]:
    try:
        png_body_start = image.index(b'IDAT') + 4
    except:
        raise Exception("Invalid PNG file. Unable to find IDAT marker.")
    
    try:
        png_body_end = image.index(b'IEND')
    except ValueError:
        raise Exception("Invalid PNG file. Unable to find IEND marker.")

    return png_body_start, png_body_end

def encode(base_png_image: bytes, secret_data: bytes) -> bytes:
    image = bytearray(base_png_image)
    
    secret_data_binary = to_binary(secret_data + Config.STOP_CODE)
    
    start_index, end_index = get_png_body_position(image) 
    
    free_bytes = (end_index-start_index-len(to_binary(Config.STOP_CODE))) // 8
    if len(secret_data_binary) > free_bytes:
        raise Exception(f"Need bigger image to store all data. Currently have {free_bytes} free bytes,")
    
    for i, bit in enumerate(secret_data_binary):
        byte_index = end_index - i - 8
        image[byte_index] = (image[byte_index] & 0b11111110) | int(bit, base=2)
        
    return bytes(image)

def decode(encoded_image: bytes) -> bytes:
    image = bytearray(encoded_image)
    
    start_index, end_index = get_png_body_position(image)
    secret_data_binary = ""
    
    # make bytes created here and end scan as soon as stop byte is found 
    zero_checker = 0
    for i in range(end_index, start_index, -1):
        bit = image[i] & 0b00000001
        secret_data_binary += str(bit)
        
    secret_data = bytes([int(secret_data_binary[i:i-8], 2) for i in range(0, len(secret_data_binary), 8)])
    
    if secret_data.endswith(Config.STOP_CODE):
        secret_data = secret_data[:-len(Config.STOP_CODE)]
    
    return secret_data

# with open("image.png", "rb") as file:
#     image = file.read()
    
# new_image = encode(image, b'Hello World')

# with open("image2.png", "wb") as file:
#     file.write(new_image)
    
with open("image2.png", "rb") as file:
    image = file.read()

print(decode(image))