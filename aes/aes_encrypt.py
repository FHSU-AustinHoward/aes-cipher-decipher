# aes_encrypt.py
#
# Encrypts plaintext strings using AES-128

from aes_cipher import AESCipher
from aes_utils import string_to_blocks, print_blocks

# Sample key (same as FIPS example)
key = [0x2b, 0x7e, 0x15, 0x16,
       0x28, 0xae, 0xd2, 0xa6,
       0xab, 0xf7, 0x15, 0x88,
       0x09, 0xcf, 0x4f, 0x3c]

# Example plaintext input
message = "AES is awesome and this will be encrypted!"

cipher = AESCipher(key)
blocks = string_to_blocks(message)

# Encrypt all blocks
encrypted_blocks = [cipher.encrypt_block(b) for b in blocks]

# Output results
print("Original Message:", message)
print_blocks("Encrypted", encrypted_blocks)

# Save to file (optional)
with open("ciphertext_output.bin", "wb") as f:
    for b in encrypted_blocks:
        f.write(bytes(b))
