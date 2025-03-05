
import re
import math

# Password Strength Check using Regex
def check_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'[a-z]', password): score += 1
    if re.search(r'\d', password): score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 1
    return score

# Entropy Calculation
def calculate_entropy(password):
    character_sets = [
        (r'[a-z]', 26),    # Lowercase letters
        (r'[A-Z]', 26),    # Uppercase letters
        (r'\d', 10),       # Digits
        (r'[!@#$%^&*(),.?":{}|<>]', 32)  # Special characters
    ]

    N = sum(char_set[1] for char_set in character_sets if re.search(char_set[0], password))
    L = len(password)

    if N == 0:
        return 0  # Avoid log(0) error

    entropy = L * math.log2(N)
    return entropy

# Run the script
if __name__ == "__main__":
    password = input("Enter your password: ")
    print("\nPassword Strength Score (out of 5):", check_strength(password))
    print("Password Entropy:", calculate_entropy(password))

