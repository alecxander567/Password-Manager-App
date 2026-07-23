"""
Password strength evaluation utilities.

Provides a server-side password strength checker that evaluates:
- Length
- Character variety (uppercase, lowercase, digits, special characters)
- Common patterns (sequences, repeated characters)
- Common passwords (based on known weak passwords)
"""

import re
import math

# -------------------------------------------------------------------
#  Common weak passwords (top 200 most common)
# -------------------------------------------------------------------
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael",
    "654321", "pussy", "superman", "1qaz2wsx", "7777777",
    "fuckyou", "121212", "000000", "qazwsx", "123qwe",
    "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley",
    "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "fuckme", "2000", "charlie", "robert", "thomas",
    "hockey", "ranger", "daniel", "starwars", "klaster",
    "112233", "george", "asshole", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass",
    "fuck", "maggie", "159753", "aaaaaa", "ginger",
    "princess", "joshua", "cheese", "amanda", "summer",
    "love", "ashley", "6969", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix",
    "wilbur", "william", "corvette", "hello", "martin",
    "heather", "secret", "fucker", "merlin", "diamond",
    "1234", "steelers", "joseph", "hannibal", "blowme",
    "shitface", "boston", "test123", "fender", "midnight",
    "ass", "qwerty123", "steven", "dick", "butthead",
    "bigdaddy", "12345678910", "victoria", "asdf", "999999",
    "aaaaaaaa", "abcd1234", "1q2w3e4r", "fuckyou123", "admin",
    "lovely", "flower", "samantha", "andrea", "butterfly",
    "success", "death", "slayer", "hello123", "boomer",
    "james", "0987654321", "hotdog", "mother", "nature",
    "shit", "zxcvbnm123", "123456789a", "zaq12wsx", "qwe123",
    "111", "brandon", "international", "password1", "nothing",
    "banana", "loveme", "killer123", "098765", "1q2w3e",
    "trust", "chocolate", "liverpool", "cheese123", "london",
    "cowboy", "password123", "123456789q", "qwerty12345", "password12345",
    "test", "guest", "123", "qwerty1", "changeme",
    "temp", "temp123", "pass123", "passw0rd", "p@ssword",
    "P@ssw0rd", "Passw0rd", "Pass1234", "default", "welcome",
    "letmein123", "welcome1", "passwd", "pwd", "iloveu",
    "1212", "2020", "2021", "2022", "2023",
    "2024", "2025", "2026", "admin123", "root",
    "toor", "qwerty123456", "asdfgh123", "zxcvbn123", "1qaz2wsx3edc",
}


# -------------------------------------------------------------------
#  Character set scoring
# -------------------------------------------------------------------
LOWERCASE_RE = re.compile(r"[a-z]")
UPPERCASE_RE = re.compile(r"[A-Z]")
DIGIT_RE = re.compile(r"[0-9]")
SPECIAL_RE = re.compile(r'[^a-zA-Z0-9\s]')
SEQUENCE_RE = re.compile(
    r"(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|"
    r"012|123|234|345|456|567|678|789|890|"
    r"987|876|765|654|543|432|321|210|"
    r"qaz|wsx|edc|rfv|tgb|yhn|ujm|ik,|ol.|"
    r"zaq|xsw|cde|vfr|bgt|nhy|mju|,ki|.lo)",
    re.IGNORECASE,
)
REPEATED_RE = re.compile(r"(.)\1{2,}")  # 3+ repeated characters


def estimate_entropy(password: str) -> float:
    """
    Estimate the entropy of a password based on character set size and length.
    This provides a mathematical measure of password strength.
    """
    if not password:
        return 0.0

    char_sets_size = 0
    if LOWERCASE_RE.search(password):
        char_sets_size += 26
    if UPPERCASE_RE.search(password):
        char_sets_size += 26
    if DIGIT_RE.search(password):
        char_sets_size += 10
    if SPECIAL_RE.search(password):
        char_sets_size += 32  # Common special chars

    if char_sets_size == 0:
        return 0.0

    # Basic entropy: L * log2(N)
    entropy = len(password) * math.log2(char_sets_size)
    return entropy


def check_password_strength(password: str) -> dict:
    """
    Evaluate the strength of a password and return a detailed report.

    Returns:
        dict with keys:
            - score: int (0-100)
            - strength: str ("very_weak", "weak", "moderate", "strong", "very_strong")
            - feedback: list[str] (suggestions for improvement)
            - entropy: float
    """
    result = {
        "score": 0,
        "strength": "very_weak",
        "feedback": [],
        "entropy": 0.0,
    }

    if not password:
        result["feedback"] = ["Password cannot be empty."]
        return result

    feedback = []
    score = 0

    # 1. Check against common passwords
    password_lower = password.lower()
    if password_lower in COMMON_PASSWORDS:
        feedback.append("This password is too common and easily guessable.")
        # Max score for common passwords is 20
        score = min(score, 20)
        result["score"] = score
        result["strength"] = "very_weak"
        result["feedback"] = feedback
        result["entropy"] = estimate_entropy(password)
        return result

    # 2. Length scoring (up to 35 points)
    length = len(password)
    if length < 6:
        score += length * 2  # 0-10
        feedback.append("Password is too short. Use at least 8 characters.")
    elif length < 8:
        score += 10
        feedback.append("Consider using at least 12 characters for better security.")
    elif length < 10:
        score += 18
    elif length < 12:
        score += 22
    elif length < 14:
        score += 26
    elif length < 16:
        score += 30
        feedback.append("Good length.")
    else:
        score += 35
        feedback.append("Excellent length.")

    # 3. Character variety scoring (up to 35 points)
    variety_score = 0
    char_types = []

    if LOWERCASE_RE.search(password):
        variety_score += 7
        char_types.append("lowercase")
    if UPPERCASE_RE.search(password):
        variety_score += 9
        char_types.append("uppercase")
    if DIGIT_RE.search(password):
        variety_score += 8
        char_types.append("digits")
    if SPECIAL_RE.search(password):
        variety_score += 11
        char_types.append("special characters")

    score += variety_score

    if len(char_types) < 3:
        feedback.append(
            "Use a mix of uppercase letters, lowercase letters, digits, and special characters."
        )

    # 4. Pattern detection penalties (up to -20 points)
    # 4a. Sequential characters
    sequences = SEQUENCE_RE.findall(password)
    if sequences:
        penalty = min(len(sequences) * 5, 15)
        score -= penalty
        if penalty > 5:
            feedback.append("Avoid sequential characters like 'abc' or '123'.")

    # 4b. Repeated characters
    repeats = REPEATED_RE.findall(password)
    if repeats:
        penalty = min(len(repeats) * 5, 10)
        score -= penalty
        if penalty > 5:
            feedback.append("Avoid repeated characters like 'aaa'.")

    # 4c. Keyboard patterns
    keyboard_patterns = [
        "qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty",
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
    ]
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            score -= 10
            feedback.append("Avoid keyboard sequences like 'qwerty'.")
            break

    # 5. Entropy calculation
    entropy = estimate_entropy(password)
    result["entropy"] = round(entropy, 2)

    # Bonus for high entropy (up to 15 points)
    if entropy >= 100:
        score += 15
    elif entropy >= 80:
        score += 10
    elif entropy >= 60:
        score += 5
    elif entropy >= 40:
        score += 2

    # Clamp score to 0-100
    score = max(0, min(100, score))

    # 6. Determine strength label
    if score < 25:
        strength = "very_weak"
    elif score < 50:
        strength = "weak"
    elif score < 70:
        strength = "moderate"
    elif score < 90:
        strength = "strong"
    else:
        strength = "very_strong"

    result["score"] = score
    result["strength"] = strength
    result["feedback"] = feedback

    return result


def get_strength_label(score: int) -> str:
    """Convert a numeric score to a strength label."""
    if score < 25:
        return "very_weak"
    elif score < 50:
        return "weak"
    elif score < 70:
        return "moderate"
    elif score < 90:
        return "strong"
    else:
        return "very_strong"


def get_strength_color(strength: str) -> str:
    """Get a color representation for the strength level."""
    colors = {
        "very_weak": "#e74c3c",   # Red
        "weak": "#e67e22",        # Orange
        "moderate": "#f1c40f",    # Yellow
        "strong": "#2ecc71",      # Green
        "very_strong": "#27ae60",  # Dark Green
    }
    return colors.get(strength, "#95a5a6")