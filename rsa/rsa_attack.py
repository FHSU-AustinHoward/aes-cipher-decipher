# rsa_attack.py
#
# Simulates an adversary recovering the private key d using exhaustive search.

import time
from rsa_keygen import E, n, d  # For comparison only (d is not known to adversary)
from rsa_utils import egcd

# Brute-force search for d
def brute_force_d(e, n):
    print("[*] Starting brute-force search for d...")
    start_time = time.time()
    phi_guess = None

    for guess_d in range(2, n):
        # Check if (e * guess_d) % phi == 1 (only works if we magically knew phi)
        # Instead, find valid guess_d using: e * d ≡ 1 mod x
        # So we reverse engineer phi by solving e * d mod x == 1
        # Try every possible x
        g, x, y = egcd(e, guess_d)
        if (e * guess_d) % g == 1:
            if pow(2, e * guess_d, n) == pow(2, 1, n):
                elapsed = time.time() - start_time
                print("[*] Recovered d ≈", guess_d)
                print(f"[*] Elapsed time: {elapsed:.4f} seconds")
                return guess_d

    print("[!] Failed to recover d via exhaustive search")
    return None

# Run attack and compare
recovered_d = brute_force_d(E, n)
print("Known correct d:", d)
print("Match:", recovered_d == d)