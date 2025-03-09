import re
import math

def calculate_entropy(password):
    char_sets = [
        (r'[a-z]', 26),  # Lowercase letters
        (r'[A-Z]', 26),  # Uppercase letters
        (r'\d', 10),     # Digits
        (r'[!@#$%^&*(),.?":{}|<>]', 32)  # Special characters
    ]

    # Determine character set size (N)
    N = sum(size for pattern, size in char_sets if re.search(pattern, password))
    
    # Calculate entropy (L * log2(N))
    entropy = len(password) * math.log2(N) if N else 0

    # Map entropy to percentage (0-100%)
    strength_percentage = min((entropy / 100) * 100, 100)  # Normalize to max 100%

    return round(strength_percentage)

