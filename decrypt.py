# decrypt.py
#
# Decrypts AES-128 ciphertext back into plaintext

from aes_cipher import AESCipher
from utils import blocks_to_string, print_blocks

# Sample key (same one used in encryption)
key = [0x2b, 0x7e, 0x15, 0x16,
       0x28, 0xae, 0xd2, 0xa6,
       0xab, 0xf7, 0x15, 0x88,
       0x09, 0xcf, 0x4f, 0x3c]

# Load ciphertext from file
with open("ciphertext_output.bin", "rb") as f:
    raw = f.read()

# Break into 16-byte blocks
blocks = [list(raw[i:i+16]) for i in range(0, len(raw), 16)]

cipher = AESCipher(key)
decrypted_blocks = [cipher.decrypt_block(b) for b in blocks]

# Output results
print_blocks("Decrypted", decrypted_blocks)
print("Recovered String:", blocks_to_string(decrypted_blocks))
