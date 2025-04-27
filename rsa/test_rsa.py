# test_rsa.py
#
# End-to-end test of the RSA system: keygen → encrypt → decrypt → verify

from rsa_keygen import p, q, n, E, d
from rsa_utils import map_text_to_numbers, map_numbers_to_text

# Message setup
message = "rsa"
plaintext_numbers = map_text_to_numbers(message)

# Encrypt
ciphertext_numbers = [pow(m, E, n) for m in plaintext_numbers]

# Decrypt
decrypted_numbers = [pow(c, d, n) for c in ciphertext_numbers]
recovered_message = map_numbers_to_text(decrypted_numbers)

# Output results
print("=== RSA FULL TEST ===")
print(f"Message:          {message}")
print(f"Plaintext nums:   {plaintext_numbers}")
print(f"Ciphertext nums:  {ciphertext_numbers}")
print(f"Decrypted nums:   {decrypted_numbers}")
print(f"Recovered text:   {recovered_message}")
print("[ MATCH ]" if recovered_message == message else "[ MISMATCH ]")