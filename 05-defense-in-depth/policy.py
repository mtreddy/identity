"""
policy.py — password policy (Feature 11).

Keeps password rules in one place. The guidance here follows NIST SP 800-63B:
favor LENGTH over arbitrary composition rules, and reject known-bad passwords
(previously breached or trivially common) rather than forcing symbol/case
gymnastics.

For a real deployment, replace/augment `_COMMON_PASSWORDS` with a check against
the Have I Been Pwned "Pwned Passwords" range API, which uses k-anonymity so you
never send the full password or its full hash. It's an online call, so this
self-contained example ships a tiny local blocklist instead.
"""

MIN_LENGTH = 12
MAX_LENGTH = 128  # bound it so a huge input can't be used to burn CPU

# A stand-in for a real breached-password corpus.
_COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "123456789",
    "qwerty", "letmein", "iloveyou", "admin", "welcome",
    "hunter2", "correct-horse-battery-staple", "changeme",
}


def validate_password(password: str) -> list[str]:
    """Return a list of human-readable problems. Empty list == acceptable."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"must be at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        problems.append(f"must be at most {MAX_LENGTH} characters")
    if password.lower() in _COMMON_PASSWORDS:
        problems.append("is too common / has appeared in breaches")
    return problems
