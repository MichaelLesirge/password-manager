# thanks Computerphile. https://youtu.be/TWEXCYQKyDc

class Config:
    STOP_CODE = b'[\0THIS\0IS\0THE\0END\0]'

def to_binary(data: bytes) -> str:
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
    byte_array = bytearray()
    stop_code = bytearray(Config.STOP_CODE)
    
    # make bytes created here and end scan as soon as stop byte is found 
    for byte_index in range(end_index, start_index, -8):
        byte = 0 
        for bit_index in range(byte_index, byte_index-8, -1):
            bit = image[bit_index] & 0b00000001
            byte = (byte << 1) | bit
        if byte_array[-len(stop_code):] == stop_code: break
        byte_array.append(byte)
    else:
        raise Exception("No stop byte found")
    
    return bytes(byte_array)[1:-len(stop_code)]
 
def main() -> None:        
    with open("image.png", "rb") as file:
        image = file.read()
     
    new_image = encode(image, b'Super secret code')

    with open("image2.png", "wb") as file:
        file.write(new_image)
        
    with open("image2.png", "rb") as file:
        image = file.read()

    print(decode(image))

if __name__ == "__main__":
    main()