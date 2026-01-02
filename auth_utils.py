import re
import hashlib
import sqlite3

DB_NAME = "secure_file_sharing.db"


# ==================================================
# Hash Password
# ==================================================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ==================================================
# Verify Password (Login)
# ==================================================
def verify_password(stored_hash: str, password: str) -> bool:
    return stored_hash == hash_password(password)


# ==================================================
# Password Strength Check
# ==================================================
def is_password_strong(password: str):
    rules = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
    }
    return rules, all(rules.values())


# ==================================================
# Check if Email Exists
# ==================================================
def email_exists(email: str) -> bool:
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    )
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


# ==================================================
# Create New User
# ==================================================
def create_user(email: str, password: str):
    password_hash = hash_password(password)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (email.split("@")[0], email, password_hash),
    )
    conn.commit()
    conn.close()


# ==================================================
# Get User By Email (For Login)
# ==================================================
def get_user_by_email(email: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, email, password_hash FROM users WHERE email = ?",
        (email,)
    )
    user = cursor.fetchone()
    conn.close()
    return user

