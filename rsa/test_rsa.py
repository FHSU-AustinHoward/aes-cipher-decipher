# test_rsa.py
#
# End-to-end test of the RSA system: keygen → encrypt → decrypt → verify

from rsa_keygen import p, q, n, E, d
from rsa_utils import map_text_to_numbers, map_numbers_to_text
import time

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

# Attacker simulation
print("\n=== ATTACKER SIMULATION (EXHAUSTIVE SEARCH) ===")
start_time = time.time()
recovered_d = None

for guess_d in range(2, n):
    if pow(ciphertext_numbers[0], guess_d, n) == plaintext_numbers[0]:
        recovered_d = guess_d
        break

elapsed = time.time() - start_time

if recovered_d:
    print(f"[*] Recovered d: {recovered_d}")
    print(f"[*] Elapsed time: {elapsed:.4f} seconds")
    print("[ MATCH ]" if recovered_d == d else "[ MISMATCH ]")
else:
    print("[!] Failed to recover d via brute-force")
