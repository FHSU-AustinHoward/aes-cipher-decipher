# rsa_encrypt.py
#
# Encrypts the string "rsa" using the RSA public key {e, n}

from rsa_utils import map_text_to_numbers
from rsa_keygen import E, n  # Import the public key components

# Message to encrypt
message = "rsa"
plaintext_numbers = map_text_to_numbers(message)

# RSA Encryption: c = m^e mod n
ciphertext_numbers = [pow(m, E, n) for m in plaintext_numbers]

# Output results
print("Original Message:", message)
print("Plaintext as numbers:", plaintext_numbers)
print("Encrypted ciphertext values:", ciphertext_numbers)

# Optionally write to file
with open("ciphertext_rsa.txt", "w") as f:
    f.write(" ".join(map(str, ciphertext_numbers)))
