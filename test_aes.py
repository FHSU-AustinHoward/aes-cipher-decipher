# test_aes.py
#
# Basic demo to validate AES encryption/decryption functionality

from aes_cipher import AESCipher
from utils import string_to_blocks, blocks_to_string, print_blocks

key = [0x2b, 0x7e, 0x15, 0x16,
       0x28, 0xae, 0xd2, 0xa6,
       0xab, 0xf7, 0x15, 0x88,
       0x09, 0xcf, 0x4f, 0x3c]

cipher = AESCipher(key)

# Test strings
test_strings = [
    "hello world",
    "AES is cool!",
    "this is a longer message that spans multiple blocks."
]

for idx, message in enumerate(test_strings, 1):
    print(f"=== AES Test #{idx} ===")
    print("Original:", message)

    blocks = string_to_blocks(message)
    encrypted = [cipher.encrypt_block(b) for b in blocks]
    decrypted = [cipher.decrypt_block(b) for b in encrypted]
    recovered = blocks_to_string(decrypted)

    print_blocks("Encrypted", encrypted)
    print_blocks("Decrypted", decrypted)
    print("Recovered:", recovered)
    print("[ MATCH ]" if message == recovered else "[ MISMATCH ]", "\n")
