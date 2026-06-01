import re
import math

def calculate_entropy(password):
    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26

    if re.search(r"[A-Z]", password):
        charset_size += 26

    if re.search(r"\d", password):
        charset_size += 10

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset_size += 32

    if charset_size == 0:
        return 0

    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)


def check_common_password(password):
    try:
        with open("common_passwords.txt", "r") as file:
            common_passwords = file.read().splitlines()

        return password.lower() in common_passwords

    except FileNotFoundError:
        return False


def password_strength(password):
    score = 0
    suggestions = []

    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add lowercase letters")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Add numbers")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        suggestions.append("Add special characters")

    if check_common_password(password):
        return {
            "strength": "Very Weak",
            "score": 0,
            "entropy": 0,
            "suggestions": ["Password found in common password list"]
        }

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return {
        "strength": strength,
        "score": score,
        "entropy": calculate_entropy(password),
        "suggestions": suggestions
    }


def main():
    print("=" * 40)
    print("PASSWORD STRENGTH CHECKER")
    print("=" * 40)

    password = input("Enter Password: ")

    result = password_strength(password)

    print("\nResults")
    print("-" * 20)
    print("Strength :", result["strength"])
    print("Score    :", result["score"], "/ 5")
    print("Entropy  :", result["entropy"], "bits")

    if result["suggestions"]:
        print("\nSuggestions:")
        for suggestion in result["suggestions"]:
            print("-", suggestion)


if __name__ == "__main__":
    main()
