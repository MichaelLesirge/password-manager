"""AES Encryption with 0 imports and only essential lookup tables"""

BOX_SIDE = 4
BOX_AREA = BOX_SIDE ** 2

ROUNDS = 10

"""
DONE:
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

Use:
https://en.wikipedia.org/wiki/Authenticated_encryption
https://en.wikipedia.org/wiki/Padding_(cryptography)
https://en.wikipedia.org/wiki/Initialization_vector

Extra:
Try to calculate https://en.wikipedia.org/wiki/Rijndael_S-box
"""

def make_grid(s: bytes, should_pad: bool = True) -> list[list[int]]:
    """Turn bytes into 4x4 grid"""
    if should_pad: s += type(s)([0] * (BOX_AREA - len(s)))
    return [[s[i + j*BOX_SIDE] for j in range(BOX_SIDE)] for i in range(BOX_SIDE)]
    

def break_into_grids(s: bytes, should_pad: bool = True) -> list[list[list[int]]]:
    """Turn bytes into list of 4x4 grids in column major order"""
    return [make_grid(s[i:i+BOX_AREA], should_pad) for i in range(0, len(s), BOX_AREA)]

# TODO figure out how to calculate S_BOX https://en.wikipedia.org/wiki/Rijndael_S-box
AES_S_BOX = [
    # 0     01    02    03    04    05    06    07    08    09    0a    0b    0c    0d    0e    0f
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],  # 00
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],  # 10
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],  # 20
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],  # 30
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],  # 40
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],  # 50
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],  # 60
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],  # 70
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],  # 80
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],  # 90
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],  # a0
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],  # b0
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],  # c0
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],  # d0
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],  # e0
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],  # f0
]

REVERSE_AES_S_BOX = [
    # 00    01    02    03    04    05    06    07    08    09    0a    0b    0c    0d    0e    0f
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],  # 00
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],  # 10
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],  # 20
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],  # 30
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],  # 40
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],  # 50
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],  # 60
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],  # 70
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],  # 80
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],  # 90
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],  # a0
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],  # b0
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],  # c0
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],  # d0
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],  # e0
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],  # f0
]

def s_box_lookup(byte: int, s_box: list[list[int]] = AES_S_BOX) -> int:
    """Look up byte in specified substitution box"""
    
    # shift first 4 bits of byte over, leaving us with just the first 4 bytes
    row = byte >> 4
    
    # set the first 4 bytes to 0 by and-ing them with 0, leaving just the last 4 bytes
    col = byte & 0x0F # 0b00001111
    
    return s_box[row][col]

def make_round_constant(total_rounds: int) -> list[list[int]]:
    """
    Make round constant values based on the total number of rounds.
    Should follow this pattern (in hex): 01, 02, 04, 08, 10, 20, 40, 80, 1B, 36
    """
    rcon = [1]
    for i in range(total_rounds):
        rcon.append(gf_multiply(rcon[-1], 2))
    return rcon
        
def expand_key(key: bytes, total_rounds: int) -> list[list[int]]:
    rcon = make_round_constant(total_rounds)
    
    key_grid = make_grid(key)

    for round in range(total_rounds):
        last_column = [row[-1] for row in key_grid]
        last_column = rotate_row_left(last_column) # rotate row step
        last_column = [s_box_lookup(b) for b in last_column] # substitution step
        last_column[0] ^= rcon[round] # rcon step
        
        for column_value, row in zip(last_column, key_grid):
            row.append(column_value ^ row[round*BOX_SIDE])

        for row in key_grid:
            row.extend([row[round * BOX_SIDE + j] ^ row[round * (BOX_SIDE + 1) + j] for j in range(BOX_SIDE)])
            
    return key_grid

def rotate_row_left(row: list, n: int = 1) -> list:
    """shift rows to the left by n, values that are shifted off wrap around"""
    return row[n:] + row[:n]

def gf_add(a: int, b: int) -> int:
    """Addition in the finite field GF(2^8). It is just the bitwise XOR (exclusive or) operator"""
    
    # 0 ^ 0 = 0
    # 0 ^ 1 = 1
    # 1 ^ 0 = 1
    # 1 ^ 1 = 0
    return a ^ b

def gf_sum(nums: list[int]) -> int:
    """Sum list of numbers in the finite field GF(2^8)"""
    total = 0
    for num in nums: total ^= num
    return total

def gf_multiply(a: int, b: int) -> int:
    """Multiplication in the finite field GF(2^8)"""
        
    result = 0
    
    for i in range(8):
        # If the B's LSB (least significant bit, farthest bit to the right) is set then we XOR the result with A.
        # This is the same as B & 0b00000001.
        # This adds A to the final result anytime the final bit of B is 1.
        if b & 1: result ^= a
        
        # Keep track of whether the MSB (most significant bit, farthest bit to the left) is set to 1.
        # This is the same as B & 0b10000000.
        # If it is that means we will overflow the field when will shift the bits to the left.
        will_overflow = a & 128 # 2**7 
        
        # Shift the A's bits to the left.
        # This is the same as multiplying A by 2.
        # This means next time a is added to be it is twice as much 
        a <<= 1
        
        # If it overflows subtract a "reducing polynomial"
        if will_overflow: a ^= 0x11b
        
        # Shift B down in order to look at the next LSB.
        # This is the same as dividing B by 2
        # This is worth twice as much in the multiplication
        b >>= 1
                
    return result

MIX_COLUMN_MATRIX_MULTIPLIER = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]

def mix_column(column: list[int]) -> list[int]:
    """Mix one column"""
    return [gf_sum(gf_multiply(column[j], MIX_COLUMN_MATRIX_MULTIPLIER[i][j]) for j in range(BOX_SIDE)) for i in range(BOX_SIDE)]

def mix_columns(grid: list[list[int]]) -> list[list[int]]:
    new_grid = [[] for i in range(BOX_SIDE)]
    
    for i in range(BOX_SIDE):
        col = [grid[j][i] for j in range(BOX_SIDE)]
        
        col = mix_column(col)
        
        for j in range(BOX_SIDE):
            new_grid[j].append(col[j])
            
    return new_grid
 
def add_sub_key(block_grid: list[list[int]], key_grid: list[list[int]]) -> list[list[int]]:
    return [[block_grid[i][j] ^ key_grid[i][j] for j in range(BOX_SIDE)] for i in range(BOX_SIDE)]
            
def extract_key_for_round(expanded_key: list[list[int]], round: int) -> list[list[int]]:
    col_index = round * BOX_SIDE
    return [row[col_index : col_index + BOX_SIDE] for row in expanded_key]

def encrypt_grid_round(round_key: list[list[int]], grid: list[list[int]], final = False) -> list[list[int]]:
    grid = [[s_box_lookup(val) for val in row] for row in grid] # SubBytes
    grid = [rotate_row_left(grid[i], i) for i in range(BOX_SIDE)] # ShiftRows
    if not final: grid = mix_columns(grid) # MixColumns
    grid = add_sub_key(grid, round_key) # AddRoundKey
    
    return grid


def encrypt(key: bytes, data: bytes) -> bytes:    
    grids = break_into_grids(data, should_pad=True)

    expanded_key = expand_key(key, ROUNDS+1)

    round_key = extract_key_for_round(expanded_key, 0)
    grids = [add_sub_key(grid, round_key) for grid in grids]

    for round in range(1, ROUNDS+1):      
        round_key = extract_key_for_round(expanded_key, round)
        grids = [encrypt_grid_round(round_key, grid, final = (round == ROUNDS)) for grid in grids]

    int_stream = [
        grid[row][column] for grid in grids for column in range(BOX_SIDE) for row in range(BOX_SIDE)
    ]
    
    return bytes(int_stream)

def decrypt_grid_round(round_key: list[list[int]], grid: list[list[int]], final = False) -> list[list[int]]:
    
    grid = add_sub_key(grid, round_key) # AddRoundKey
    for i in range((not final) and 3): grid = mix_columns(grid) # MixColumns
    grid = [rotate_row_left(grid[i], -1 * i) for i in range(BOX_SIDE)] # ShiftRows
    grid = [[s_box_lookup(val, REVERSE_AES_S_BOX) for val in row] for row in grid] # SubBytes
    
    return grid

def decrypt(key: bytes, data: bytes) -> bytes:
    grids = break_into_grids(data, should_pad=True)
    
    expanded_key = expand_key(key, ROUNDS+1)

    for round in range(ROUNDS, 0, -1):
        round_key = extract_key_for_round(expanded_key, round)  
        grids = [decrypt_grid_round(round_key, grid, final=(round == ROUNDS)) for grid in grids]
        
    round_key = extract_key_for_round(expanded_key, 0)
    grids = [add_sub_key(grid, round_key) for grid in grids]
    
    int_stream = [
        grid[row][column] for grid in grids for column in range(BOX_SIDE) for row in range(BOX_SIDE)
    ]

    return bytes(int_stream)

# --- MAIN ---

def main() -> None:
    going = True
    
    leave_codes = ["q", "exit"]
    
    
    print("""
         █████  ███████ ███████     ███████ ███    ██  ██████ ██████  ██    ██ ██████  ████████ 
        ██   ██ ██      ██          ██      ████   ██ ██      ██   ██  ██  ██  ██   ██    ██    
        ███████ █████   ███████     █████   ██ ██  ██ ██      ██████    ████   ██████     ██    
        ██   ██ ██           ██     ██      ██  ██ ██ ██      ██   ██    ██    ██         ██    
        ██   ██ ███████ ███████     ███████ ██   ████  ██████ ██   ██    ██    ██         ██                                                                                    
        """)
    
    print("\033[0;32m")
    
    example_password = "my password"
    example_message = "a secret message"
    
    print(f'AES> encrypt "{example_password}" "{example_message}"')
    example_encrypted = encrypt( b"my password", b"a secret message")
    print(bytes_to_str(example_encrypted))
    
    print()
    
    example_decrypted = decrypt(str_to_bytes(example_password), example_encrypted)
    print(f'AES> decrypt "{example_password}" {bytes_to_str(example_encrypted)}')
    print(bytes_to_str(example_decrypted))
    
    assert bytes_to_str(example_decrypted) == example_message, "Test failed"
    
    while going:
        print()
        user_input = input("AES> ").lower().strip()
        
        if user_input in leave_codes: return
        
        split_input = split_string_with_quotes(user_input)
        
        if len(split_input) != 3:
            print("Error: Please enter mode, key, and data")
            continue
            
        mode, key, text = split_input
        
        key = str_to_bytes(key)
        text = str_to_bytes(text)
                
        if mode[0] == "e":
            output = encrypt(key, text)
        elif mode[0] == "d":
            output = decrypt(key, text)
        else:
            print("Error: please choose either encrypt or decrypt for the mode")
            continue
        
        print([key, text, output])
    
        print(bytes_to_str(output))

def str_to_bytes(s: str) -> bytes:
    return eval("b'" + s + "'")

def bytes_to_str(b: bytes) -> str:
    return str(b).lstrip("b'").rstrip("'")

def split_string_with_quotes(input_string: str, sep = " ") -> list[str]:
    result = []
    current_token = ""
    inside_quotes = False

    for char in input_string:
        if char == sep and not inside_quotes:
            if current_token:
                result.append(current_token)
                current_token = ""
        elif ord(char) in [39, 34]:
            inside_quotes = not inside_quotes
        else:
            current_token += char

    if current_token:
        result.append(current_token)

    return result     
            
if __name__ == "__main__":
    main()