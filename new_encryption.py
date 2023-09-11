# Thanks Computerphile. https://youtu.be/O4xNJsjtN6E

import os
import math

class AESConstants:
    GRID_SIZE = 16

def get_new_salt() -> bytes:
    return os.urandom(16)

def create_grid(data, grid_size):
    grid_dimension = int(math.sqrt(grid_size))
    if grid_dimension ** 2 == grid_size: raise ValueError("grid_size must be perfect square")
    
    for block_index in range(0, len(data), 16):
        block = data[block_index : block_index + grid_size]
        grid = [[] for i in range(grid_dimension)]