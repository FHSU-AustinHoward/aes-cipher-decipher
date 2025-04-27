# rsa_keygen.py
#
# Generates RSA public/private key pairs
# Uses the 10th and 19th primes between 1000–10000 as p and q

from rsa_utils import is_prime, get_nth_prime_in_range, modinv

# Parameters
START = 1000
END = 10000
P_INDEX = 10
Q_INDEX = 19
E = 65537  # Common public exponent

# Generate primes
p = get_nth_prime_in_range(START, END, P_INDEX)
q = get_nth_prime_in_range(START, END, Q_INDEX)

if p is None or q is None:
    raise ValueError("Could not find primes with specified indices.")

# Calculate RSA components
n = p * q
phi = (p - 1) * (q - 1)

d = modinv(E, phi)

# Display Keys
print("RSA Key Generation Complete:")
print(f"p = {p}")
print(f"q = {q}")
print(f"n = {n}")
print(f"phi = {phi}")
print(f"Public Key (e, n) = ({E}, {n})")
print(f"Private Key (d, p, q) = ({d}, {p}, {q})")
