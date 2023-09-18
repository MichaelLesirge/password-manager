# Thanks Computerphile. https://youtu.be/TWEXCYQKyDc

class Constants:
    STOP_CODE = b'\x98\xc7\x9f\x83\xd2\xa8D\x88\xf0\xfd\xcd\xb3\r\xb5\x96\xf9'

def to_binary(data: bytes) -> str:
    return "".join(format(i, "08b") for i in data)


class InvalidPNGFile(ValueError):
    pass


def get_png_body_position(image: bytes) -> tuple[int, int]:
    """Get stand and end indexes of png body"""
    try:
        png_body_start = image.index(b'IDAT') + 4
        png_body_end = image.index(b'IEND')
    except ValueError as e:
        raise InvalidPNGFile("Invalid PNG file. Unable to find marker.") from e

    return png_body_start, png_body_end


def encode_image(base_png_image: bytes, secret_data: bytes, stop_code: bytes = b"###STOP###") -> bytes:
    """Store secret data in png image. End secret data with stop code"""
    
    # TODO check file for any stop codes that might appear in it and change them or change stop code
    
    image = bytearray(base_png_image)

    secret_data_binary = to_binary(secret_data + stop_code)

    start_index, end_index = get_png_body_position(image)

    free_bytes = (end_index-start_index-len(to_binary(stop_code))) // 8
    if len(secret_data_binary) > free_bytes:
        raise ValueError(
            f"Need bigger image to store all data. Currently have {free_bytes} free bytes,")

    for i, bit in enumerate(secret_data_binary):
        byte_index = end_index - i - 8
        # set last bit of byte to bit by setting last bit of image byte to zero then doing OR with the bit
        image[byte_index] = (image[byte_index] & 0b11111110) | int(bit, base=2)

    return bytes(image)


def decode_image(encoded_png_image: bytes, stop_code: bytes = b"###STOP###") -> bytes:
    """read secret data from encoded image until stop code is reached"""
    
    image = bytearray(encoded_png_image)

    start_index, end_index = get_png_body_position(image)
    byte_array = bytearray()
    stop_code_array = bytearray(stop_code)

    for byte_index in range(end_index, start_index, -8):
        byte = 0
        for bit_index in range(byte_index, byte_index-8, -1):
            # get last bit of byte by setting all other values to zero except last tone
            bit = image[bit_index] & 0b00000001
            # shift found byte left by one to make room for new bit on end. works since only end bit could be on in "bit"
            byte = (byte << 1) | bit
        if byte_array[-len(stop_code_array):] == stop_code_array:
            break
        byte_array.append(byte)
    else:
        raise Exception("No stop byte found")

    return bytes(byte_array)[1:-len(stop_code_array)]


def main() -> None:
    # TODO add subtracted image difference (Like shown in video)

    with open("steganography_base_images/mountains.png", "rb") as file:
        image = file.read()

    in_string = "Super secret code"
    encoded_image = encode_image(image, in_string.encode(), Constants.STOP_CODE)

    out_string = decode_image(encoded_image, Constants.STOP_CODE).decode()

    assert in_string == out_string, f"In and out strings not equal, {in_string=}, {out_string=}"

    print(repr(out_string))


if __name__ == "__main__":
    main()
