import re


def check_password_strength(password):
    # criteria definitions
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[ !@#$%^&*()_+=]", password) is None

    # Evaluate password
    password_ok = not (
        length_error
        or digit_error
        or uppercase_error
        or lowercase_error
        or symbol_error
    )

    if password_ok:
        return "strong password"
    else:
        remarks = []
        if length_error:
            remarks.append("at least 8 characters")
        if digit_error:
            remarks.append("one digit")
        if uppercase_error:
            remarks.append("one uppercase letter")
        if lowercase_error:
            remarks.append("one lowercase letter")
        if symbol_error:
            remarks.append("one special charater")

        return "weak password. need :" + ", ".join(remarks)


password = input("Enter a password to check :")
print(check_password_strength(password))

