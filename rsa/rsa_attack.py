# rsa_attack.py
#
# Brute-force recovery of d given only public key {e, n}

import time

# Public key
e = 65537
n = 1185137  # use actual n from your keygen script

# Ciphertext for "r" encrypted: assume c = m^e mod n with m = 17
target_plaintext = 17
ciphertext = 665120  # known ciphertext for 'r' using the above n and e

start = time.time()
recovered_d = None

for guess_d in range(2, n):
    if pow(ciphertext, guess_d, n) == target_plaintext:
        recovered_d = guess_d
        break

elapsed = time.time() - start

if recovered_d:
    print("[*] Recovered d:", recovered_d)
    print(f"[*] Elapsed time: {elapsed:.4f} seconds")
else:
    print("[!] Failed to recover d")