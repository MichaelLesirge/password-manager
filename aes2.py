# TODO this file is incomplete, I wanted to do it again with actually no lookup tables.

# --- CREATION OF SBOX ---

def rotate_8b(x, shift):
    """left bitwise circular shift"""
    return (x << shift) | (x >> (8-shift))

def create_sbox():
    p = 1
    q = 1

    sbox = []

    while True:
        pass



# --- MATHEMATICAL OPERATIONS IN THE FINITE FIELD GF(2^8) ---

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