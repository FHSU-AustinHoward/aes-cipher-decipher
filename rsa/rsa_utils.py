# rsa_utils.py
#
# Utility functions for RSA

import math

# Check if number is prime
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

# Determine extended greatest common divisor
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

# Determine modular inverse
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

# Letter-to-number mappings for "rsa"
def map_text_to_numbers(text):
    """Map lowercase text to numbers: a=0, b=1, ..., z=25"""
    return [ord(c) - ord('a') for c in text if c.isalpha()]

def map_numbers_to_text(numbers):
    """Map list of numbers back to lowercase letters."""
    return ''.join(chr(n + ord('a')) for n in numbers)
