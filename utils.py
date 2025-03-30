# utils.py
#
# Helper functions for AES block operations and printing.

from typing import List

def string_to_blocks(s: str, block_size: int = 16) -> List[List[int]]:
    """Convert a string into a list of 16-byte blocks with zero padding."""
    data = list(s.encode('utf-8'))
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) < block_size:
            block += [0x00] * (block_size - len(block))
        blocks.append(block)
    return blocks

def blocks_to_string(blocks: List[List[int]]) -> str:
    """Convert a list of 16-byte blocks back into a UTF-8 string."""
    data = []
    for block in blocks:
        data.extend(block)
    return bytes(data).rstrip(b'\x00').decode('utf-8', errors='ignore')

def print_blocks(label: str, blocks: List[List[int]]):
    """Print a label and a list of 16-byte blocks in aligned format."""
    if not blocks:
        return
    prefix = f"{label}: "
    for i, block in enumerate(blocks):
        block_str = ' '.join(f"{byte:02x}" for byte in block)
        if i == 0:
            print(f"{prefix}{block_str}")
        else:
            print(f"{' ' * len(prefix)}{block_str}")
