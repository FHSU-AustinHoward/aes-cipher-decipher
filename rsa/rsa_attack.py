# rsa_attack.py
#
# Simulates an attacker recovering the private key d via brute-force

# Public key
E = 65537
n = 1185137

# Known ciphertext of "rsa" encrypted with e and n
ciphertext = [665120, 1081927, 0]  # encrypted values of 'r', 's', 'a'
expected_plaintext = [17, 18, 0]   # letter-to-number mapping

import time

start = time.time()
recovered_d = None

# Try all possible d values
for guess_d in range(2, n):
    decrypted = [pow(c, guess_d, n) for c in ciphertext]
    if decrypted == expected_plaintext:
        recovered_d = guess_d
        break

elapsed = time.time() - start

if recovered_d:
    print("[*] Recovered private key d:", recovered_d)
    print(f"[*] Elapsed time: {elapsed:.4f} seconds")
else:
    print("[!] Failed to recover d")
