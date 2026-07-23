"""
Cryptographically secure password generator.

Generates strong passwords using Python's `secrets` module for CSPRNG.
Allows customization of length, character types, and exclusions.
"""

import secrets
import string


# Character sets
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
# Remove easily confused characters: Il1O0
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

# Default character set without confusing chars
LOWERCASE_SAFE = "abcdefghjkmnpqrstuvwxyz"
UPPERCASE_SAFE = "ABCDEFGHJKMNPQRSTUVWXYZ"
DIGITS_SAFE = "23456789"
SPECIAL_SAFE = "!@#$%^&*()-_=+[]{}|;:,.<>?"


def generate_password(
    length: int = 20,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    exclude_confusing: bool = True,
    min_lowercase: int = 1,
    min_uppercase: int = 1,
    min_digits: int = 1,
    min_special: int = 1,
    exclude_chars: str = "",
) -> str:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Total length of the password (default: 20)
        use_lowercase: Include lowercase letters
        use_uppercase: Include uppercase letters
        use_digits: Include digits
        use_special: Include special characters
        exclude_confusing: Exclude easily confused chars (Il1O0)
        min_lowercase: Minimum number of lowercase characters
        min_uppercase: Minimum number of uppercase characters
        min_digits: Minimum number of digit characters
        min_special: Minimum number of special characters
        exclude_chars: Additional characters to exclude

    Returns:
        A cryptographically secure random password string
    """
    # Validate length
    min_required = min_lowercase + min_uppercase + min_digits + min_special
    if length < min_required:
        length = min_required
    if length < 8:
        length = 8
    if length > 128:
        length = 128

    # Build character pool
    pool = ""
    mandatory_pools = []

    if exclude_confusing:
        lower_pool = LOWERCASE_SAFE
        upper_pool = UPPERCASE_SAFE
        digit_pool = DIGITS_SAFE
        special_pool = SPECIAL_SAFE
    else:
        lower_pool = LOWERCASE
        upper_pool = UPPERCASE
        digit_pool = DIGITS
        special_pool = SPECIAL_CHARS

    if use_lowercase:
        pool += lower_pool
        mandatory_pools.append((lower_pool, min_lowercase))
    if use_uppercase:
        pool += upper_pool
        mandatory_pools.append((upper_pool, min_uppercase))
    if use_digits:
        pool += digit_pool
        mandatory_pools.append((digit_pool, min_digits))
    if use_special:
        pool += special_pool
        mandatory_pools.append((special_pool, min_special))

    # If no character types selected, default to lowercase + digits
    if not pool:
        pool = lower_pool + digit_pool
        mandatory_pools = [(lower_pool, 1), (digit_pool, 1)]

    # Remove excluded characters
    for ch in exclude_chars:
        pool = pool.replace(ch, "")

    if not pool:
        raise ValueError("Character pool is empty after exclusions.")

    # Ensure we have at least one character from each mandatory pool (for minimums)
    password_chars = []
    for char_pool, count in mandatory_pools:
        # Filter out excluded chars from each pool
        clean_pool = char_pool
        for ch in exclude_chars:
            clean_pool = clean_pool.replace(ch, "")
        if clean_pool:
            for _ in range(count):
                password_chars.append(secrets.choice(clean_pool))

    # Fill the rest randomly
    remaining = length - len(password_chars)
    for _ in range(remaining):
        password_chars.append(secrets.choice(pool))

    # Shuffle to avoid predictable patterns from mandatory placements
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def generate_pin(length: int = 6) -> str:
    """Generate a numeric PIN code."""
    if length < 4:
        length = 4
    if length > 32:
        length = 32
    return "".join(secrets.choice(DIGITS) for _ in range(length))


def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True,
) -> str:
    """
    Generate a memorable passphrase using common words.

    This is a simple implementation. For production use, integrate with
    a dedicated word list like the EFF large wordlist.
    """
    # A small list of common, easy-to-remember words
    words = [
        "correct", "horse", "battery", "staple", "trout", "cloud",
        "river", "mountain", "ocean", "forest", "desert", "island",
        "sunset", "dawn", "eagle", "falcon", "tiger", "panda",
        "coral", "amber", "crystal", "silver", "golden", "bronze",
        "echo", "delta", "alpha", "omega", "nova", "stellar",
        "bridge", "castle", "pencil", "rocket", "planet", "garden",
        "winter", "summer", "autumn", "spring", "copper", "velvet",
        "thunder", "blizzard", "tempest", "cascade", "meadow", "harbor",
    ]

    if word_count < 3:
        word_count = 3
    if word_count > 12:
        word_count = 12

    selected = [secrets.choice(words) for _ in range(word_count)]

    if capitalize:
        selected = [w.capitalize() for w in selected]

    passphrase = separator.join(selected)

    if add_number:
        passphrase += str(secrets.randbelow(100))

    return passphrase


def generate_password_with_entropy(
    min_entropy: float = 60.0,
    prefer_length: int = 20,
) -> str:
    """
    Generate a password that meets a minimum entropy threshold.
    Uses the primary generator and validates with entropy estimation.
    """
    from vaults.utils.password_strength import estimate_entropy

    max_attempts = 10
    for attempt in range(max_attempts):
        pwd = generate_password(length=prefer_length)
        entropy = estimate_entropy(pwd)
        if entropy >= min_entropy:
            return pwd
        # Increase length if we couldn't meet entropy
        prefer_length += 4

    # Final fallback with maximum length
    return generate_password(length=prefer_length)