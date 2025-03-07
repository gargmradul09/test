import re
import math

def check_strength(password):
    score = 1 if len(password) >= 8 else 0
    score += 1 if re.search(r'[A-Z]', password) else 0
    score += 1 if re.search(r'[a-z]', password) else 0
    score += 1 if re.search(r'\d', password) else 0
    score += 1 if re.search(r'[!@#$%^&*(),.?":{}|<>]', password) else 0
    return min(score, 5)

def calculate_entropy(password):
    char_sets = [(r'[a-z]', 26), (r'[A-Z]', 26), (r'\d', 10), (r'[!@#$%^&*(),.?":{}|<>]', 32)]
    N = sum(size for pattern, size in char_sets if re.search(pattern, password))
    return len(password) * math.log2(N) if N else 0

