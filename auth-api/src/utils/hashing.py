import bcrypt


def hash_password(password: str) -> str:
    """
    Hashes a password with a salt.

    Args:
    password (str): The plaintext password to hash.

    Returns:
    str: The hashed and salted password.
    """
    password_bytes = password.encode("utf-8")

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    return hashed_password.decode("utf-8")


def verify_password(submitted_password: str, stored_hash: str) -> bool:
    """
    Verifies a submitted password against a stored hash.

    Args:
    submitted_password (str): The plaintext password submitted by the user.
    stored_hash (str): The stored hash against which to verify the password.

    Returns:
    bool: True if the password matches the hash, False otherwise.
    """
    submitted_password_bytes = submitted_password.encode("utf-8")
    stored_hash_bytes = stored_hash.encode("utf-8")
    return bcrypt.checkpw(submitted_password_bytes, stored_hash_bytes)
