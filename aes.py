
BOX_SIDE = 4
BOX_AREA = BOX_SIDE ** 2

def make_grid(s: bytes, should_pad: bool = True) -> list[list[int]]:
    s += type(s)([0] * (BOX_AREA - len(s)))
    return [[s[i + j*BOX_SIDE] for j in range(BOX_SIDE)] for i in range(BOX_SIDE)]
    

def break_in_grids_of_16(s: bytes, should_pad: bool = True) -> list[list[list[int]]]:
    return [make_grid(s[i:i+BOX_AREA], should_pad) for i in range(0, len(s), BOX_AREA)]

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
    x = byte >> 4
    y = byte & 15
    return s_box[x][y]

def expand_key(key: bytes, rounds: int) -> list[list[int]]:
    
    r_con = []
    r_con_value = 1

    for i in range(rounds):

        r_con.append([r_con_value] + [0] * (BOX_SIDE-1))
        
        r_con_value *= 2
        
        if r_con_value > 0x80:
            r_con_value ^= 0x11b
    
    key_grid = break_in_grids_of_16(key)[0]

    for round in range(rounds):
        last_column = [row[-1] for row in key_grid]
        last_column_rotate_step = rotate_row_left(last_column)
        last_column_sbox_step = [s_box_lookup(b) for b in last_column_rotate_step]
        last_column_rcon_step = [last_column_sbox_step[i] ^ r_con[round][i] for i in range(len(last_column_rotate_step))]

        for r in range(BOX_SIDE):
            key_grid[r] += bytes([last_column_rcon_step[r] ^ key_grid[r][round*BOX_SIDE]])

        for i, grid in enumerate(key_grid):
            for j in range(BOX_SIDE):
                row_start_index = round*BOX_SIDE + j
                key_grid[i] += bytes([grid[row_start_index] ^ grid[row_start_index + BOX_SIDE]])

    return key_grid

def rotate_row_left(row: list, n: int = 1) -> list:
    return row[n:] + row[:n]

def add(*args: int) -> int:
    result = 0
    for arg in args: result ^= arg
    return result

def multiply(a: int, b: int) -> int:    
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

def mix_columns(grid: list[list[int]]) -> list[list[int]]:
    new_grid = [[] for i in range(BOX_SIDE)]
    
    for i in range(4):
        col = [grid[j][i] for j in range(BOX_SIDE)]
        
        col = mix_column(col)
        
        for j in range(BOX_SIDE):
            new_grid[j].append(col[j])
            
    return new_grid


def mix_column(column: list[int]) -> list[int]:
    return [
        multiply(column[0], 2) ^ multiply(column[1], 3) ^ column[2] ^ column[3],
        multiply(column[1], 2) ^ multiply(column[2], 3) ^ column[3] ^ column[0],
        multiply(column[2], 2) ^ multiply(column[3], 3) ^ column[0] ^ column[1],
        multiply(column[3], 2) ^ multiply(column[0], 3) ^ column[1] ^ column[2],
    ]

def add_sub_key(block_grid: list[list[int]], key_grid: list[list[int]]) -> list[list[int]]:
    return [[block_grid[i][j] ^ key_grid[i][j] for j in range(BOX_SIDE)] for i in range(BOX_SIDE)]
            
def extract_key_for_round(expanded_key: list[list[int]], round: int):
    row_index = round * BOX_SIDE
    return [row[row_index : row_index + BOX_SIDE] for row in expanded_key]

def encrypt(key: bytes, data: bytes) -> bytes:    
    grids = break_in_grids_of_16(data, should_pad=True)

    expanded_key = expand_key(key, 11)

    round_key = extract_key_for_round(expanded_key, 0)

    grids = [add_sub_key(grid, round_key) for grid in grids]

    for round in range(1, 10):
        temp_grids = []
        
        round_key = extract_key_for_round(expanded_key, round)
        for grid in grids:
            
            sub_bytes_step = [[s_box_lookup(val) for val in row] for row in grid]
            shift_rows_step = [rotate_row_left(sub_bytes_step[i], i) for i in range(BOX_SIDE)]
            mix_column_step = mix_columns(shift_rows_step)
                   
            add_sub_key_step = add_sub_key(mix_column_step, round_key)
            temp_grids.append(add_sub_key_step)

        grids = temp_grids

    temp_grids = []
    round_key = extract_key_for_round(expanded_key, 10)

    for grid in grids:
        sub_bytes_step = [[s_box_lookup(val) for val in row] for row in grid]
        shift_rows_step = [rotate_row_left(sub_bytes_step[i], i) for i in range(BOX_SIDE)]
        add_sub_key_step = add_sub_key(shift_rows_step, round_key)
        temp_grids.append(add_sub_key_step)

    grids = temp_grids

    int_stream = [
        grid[row][column] for grid in grids for column in range(BOX_SIDE) for row in range(BOX_SIDE)
    ]
    
    return bytes(int_stream)

def decrypt(key: bytes, data: bytes) -> bytes:

    grids = break_in_grids_of_16(data)
    expanded_key = expand_key(key, 11)
    round_key = extract_key_for_round(expanded_key, 10)

    temp_grids = []

    for grid in grids:

        add_sub_key_step = add_sub_key(grid, round_key)
        shift_rows_step = [rotate_row_left(add_sub_key_step[i], -i) for i in range(BOX_SIDE)]
        sub_bytes_step = [[s_box_lookup(val, REVERSE_AES_S_BOX) for val in row] for row in shift_rows_step]
        temp_grids.append(sub_bytes_step)

    grids = temp_grids

    for round in range(9, 0, -1):
        temp_grids = []

        round_key = extract_key_for_round(expanded_key, round)
        for grid in grids:
            add_sub_key_step = add_sub_key(grid, round_key)

            mix_column_step = mix_columns(add_sub_key_step)
            mix_column_step = mix_columns(mix_column_step)
            mix_column_step = mix_columns(mix_column_step)
            shift_rows_step = [rotate_row_left(mix_column_step[i], -1 * i) for i in range(BOX_SIDE)]
            sub_bytes_step = [[s_box_lookup(val, REVERSE_AES_S_BOX) for val in row] for row in shift_rows_step]
            temp_grids.append(sub_bytes_step)

        grids = temp_grids
    
    temp_grids = []

    round_key = extract_key_for_round(expanded_key, 0)

    grids = [add_sub_key(grid, round_key) for grid in grids]
    
    int_stream = [
        grid[row][column] for grid in grids for column in range(BOX_SIDE) for row in range(BOX_SIDE)
    ]

    return bytes(int_stream)

data = encrypt("code".encode(), "Secret message shhhhh 123".encode())
print(data)
output = decrypt("code".encode(), data).decode()
print(output)