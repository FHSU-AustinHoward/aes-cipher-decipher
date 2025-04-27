# rsa_decrypt.py
#
# Decrypts the ciphertext of "rsa" using the RSA private key {d, n}

from rsa_utils import map_numbers_to_text
from rsa_keygen import d, n  # Import private key component

# Load ciphertext
with open("ciphertext_rsa.txt", "r") as f:
    ciphertext_numbers = list(map(int, f.read().strip().split()))

# RSA Decryption: m = c^d mod n
decrypted_numbers = [pow(c, d, n) for c in ciphertext_numbers]
recovered_text = map_numbers_to_text(decrypted_numbers)

# Output results
print("Encrypted ciphertext values:", ciphertext_numbers)
print("Decrypted numbers:", decrypted_numbers)
print("Recovered plaintext:", recovered_text)