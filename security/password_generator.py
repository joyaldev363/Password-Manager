import math
import secrets
import string
from typing import Dict, Any


def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True
) -> str:
    """
    Generate a cryptographically secure random password using Python's secrets module.
    Ensures at least one character from each selected category is included.
    """
    if length < 4:
        length = 4

    character_pools = []
    required_chars = []

    if uppercase:
        character_pools.append(string.ascii_uppercase)
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if lowercase:
        character_pools.append(string.ascii_lowercase)
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if numbers:
        character_pools.append(string.digits)
        required_chars.append(secrets.choice(string.digits))
    if symbols:
        symbols_pool = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        character_pools.append(symbols_pool)
        required_chars.append(secrets.choice(symbols_pool))

    # Fallback to lowercase if no character sets are selected
    if not character_pools:
        character_pools.append(string.ascii_lowercase)
        required_chars.append(secrets.choice(string.ascii_lowercase))

    all_characters = "".join(character_pools)

    # Fill the remainder of the password length
    remaining_length = length - len(required_chars)
    remaining_chars = [secrets.choice(all_characters) for _ in range(remaining_length)]

    # Combine and shuffle securely
    combined = required_chars + remaining_chars
    # Perform Fisher-Yates shuffle using secrets.randbelow
    for i in range(len(combined) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combined[i], combined[j] = combined[j], combined[i]

    return "".join(combined)


def calculate_entropy(password: str) -> float:
    """Calculate the information entropy (in bits) of a given password."""
    if not password:
        return 0.0

    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c not in (string.ascii_letters + string.digits) for c in password):
        pool_size += 32

    if pool_size == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 1)


def assess_password_strength(password: str) -> Dict[str, Any]:
    """
    Assess password security strength and return score (0-100), label, color hex, and feedback.
    """
    if not password:
        return {
            "score": 0,
            "label": "Empty",
            "color": "#6c757d",
            "entropy": 0.0,
            "feedback": ["Password cannot be empty."]
        }

    entropy = calculate_entropy(password)
    length = len(password)
    feedback = []

    if length < 8:
        feedback.append("Password is too short (less than 8 characters).")
    elif length < 12:
        feedback.append("Consider using at least 12-16 characters.")

    if not any(c.isupper() for c in password):
        feedback.append("Add uppercase letters.")
    if not any(c.islower() for c in password):
        feedback.append("Add lowercase letters.")
    if not any(c.isdigit() for c in password):
        feedback.append("Add numbers.")
    if not any(c not in (string.ascii_letters + string.digits) for c in password):
        feedback.append("Add special symbols (!@#$%^&*).")

    # Score calculation (0 to 100)
    score = min(100, int((entropy / 80.0) * 100))

    if score < 30:
        label = "Very Weak"
        color = "#e63946"  # Red
    elif score < 50:
        label = "Weak"
        color = "#f4a261"  # Orange
    elif score < 70:
        label = "Moderate"
        color = "#e9c46a"  # Yellow
    elif score < 90:
        label = "Strong"
        color = "#2a9d8f"  # Teal/Green
    else:
        label = "Very Strong"
        color = "#2b9348"  # Dark Green

    if not feedback:
        feedback.append("Great! This password is very secure.")

    return {
        "score": score,
        "label": label,
        "color": color,
        "entropy": entropy,
        "feedback": feedback
    }
