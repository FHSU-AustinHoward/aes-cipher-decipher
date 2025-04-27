# check_prime.py
#
# Checks if a user-input number is prime.

import math

# Primality check function
def is_prime(n):
    # Handle base cases
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # Check odd divisors up to sqrt(n)
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True

# Ask user for prime number check
try:
    number = int(input("Enter a number to check if it's prime: "))
    if is_prime(number):
        print(f"{number} is a prime number.")
    else:
        print(f"{number} is not a prime number.")
except ValueError:
    print("Invalid input. Please enter an integer.")
