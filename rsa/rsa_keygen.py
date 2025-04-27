# rsa_keygen.py
#
# Generates RSA public/private key pairs
# Uses the 10th and 19th primes between 1000–10000 as p and q

import math

# Primality check
def is_prime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

# Get nth prime in range
def get_nth_prime_in_range(start, end, n):
    count = 0
    for i in range(start, end + 1):
        if is_prime(i):
            count += 1
            if count == n:
                return i
    return None

# Extended Euclidean Algorithm
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

# Modular inverse
def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m

# Parameters
START = 1000
END = 10000
P_INDEX = 10
Q_INDEX = 19
E = 65537 # A common exponent for RSA (0x10001)

# Generate primes
p = get_nth_prime_in_range(START, END, P_INDEX)
q = get_nth_prime_in_range(START, END, Q_INDEX)

if p is None or q is None:
    raise ValueError("Could not find primes with specified indices.")

n = p * q                   # Modulus for public and private keys
phi = (p - 1) * (q - 1)     # Euler's totient function
d = modinv(E, phi)          # Private exponent such that (e * d) % phi == 1

# Output keys
print("RSA Key Generation Complete:")
print(f"10th Prime:               p = {p}")
print(f"19th Prime:               q = {q}")
print(f"Modulus:                  n = {n}")
print(f"Euler's Totient:        phi = {phi}")
print(f"Public Key:            e, n = ({E}, {n})")
print(f"Private Key:        d, p, q = ({d}, {p}, {q})")
