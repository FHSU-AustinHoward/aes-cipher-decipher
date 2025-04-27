# rsa_crypto.py
#
# Encrypts and decrypts the message "rsa" using RSA.

# Primality check
import math

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

# Get nth prime in a range
def get_nth_prime_in_range(start, end, n):
    count = 0
    for i in range(start, end + 1):
        if is_prime(i):
            count += 1
            if count == n:
                return i
    return None

# Extended greatest common divisor
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

# Map text to numbers a=0, b=1, ..., z=25
def map_text_to_numbers(text):
    return [ord(c) - ord('a') for c in text if c.isalpha()]

def map_numbers_to_text(numbers):
    return ''.join(chr(n + ord('a')) for n in numbers)

# Generate RSA keys
p = get_nth_prime_in_range(1000, 10000, 10)
q = get_nth_prime_in_range(1000, 10000, 19)
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
d = modinv(e, phi)

# Message and encryption
message = "rsa"
plaintext = map_text_to_numbers(message)
ciphertext = [pow(m, e, n) for m in plaintext]

# Decryption
decrypted = [pow(c, d, n) for c in ciphertext]
recovered = map_numbers_to_text(decrypted)

# Output
print("RSA Encryption/Decryption")
print("Message:", message)
print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext)
print("Decrypted:", decrypted)
print("Recovered:", recovered)
print("[ MATCH ]" if recovered == message else "[ MISMATCH ]")
