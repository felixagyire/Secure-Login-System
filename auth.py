import re

import bcrypt

from database import get_connection


USERNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9_]{3,30}$"
)

EMAIL_PATTERN = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


def validate_username(username):
    if not username:
        return False, "Username is required."

    if not USERNAME_PATTERN.fullmatch(username):
        return False, (
            "Username must contain only letters, numbers, "
            "and underscores, and must be 3 to 30 characters."
        )

    return True, ""


def validate_email(email):
    if not email:
        return False, "Email address is required."

    if not EMAIL_PATTERN.fullmatch(email):
        return False, "Please enter a valid email address."

    return True, ""


def validate_password(password):
    if not password:
        return False, "Password is required."

    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    if not re.search(r"[A-Z]", password):
        return False, (
            "Password must contain at least one uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        return False, (
            "Password must contain at least one lowercase letter."
        )

    if not re.search(r"\d", password):
        return False, (
            "Password must contain at least one number."
        )

    return True, ""


def hash_password(password):
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")


def verify_password(password, password_hash):
    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8")
    )


def register_user(username, email, password):
    username = username.strip()
    email = email.strip().lower()

    valid, message = validate_username(username)

    if not valid:
        return False, message

    valid, message = validate_email(email)

    if not valid:
        return False, message

    valid, message = validate_password(password)

    if not valid:
        return False, message

    password_hash = hash_password(password)

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users (
                username,
                email,
                password_hash
            )
            VALUES (?, ?, ?)
            """,
            (
                username,
                email,
                password_hash
            )
        )

        connection.commit()

        return True, "Registration successful. You can now log in."

    except Exception as error:
        if "UNIQUE constraint failed: users.username" in str(error):
            return False, "That username is already registered."

        if "UNIQUE constraint failed: users.email" in str(error):
            return False, "That email address is already registered."

        return False, "Registration failed. Please try again."

    finally:
        connection.close()


def authenticate_user(username, password):
    username = username.strip()

    if not username or not password:
        return None

    connection = get_connection()

    user = connection.execute(
        """
        SELECT id, username, email, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    connection.close()

    if user is None:
        return None

    if verify_password(
        password,
        user["password_hash"]
    ):
        return user

    return None