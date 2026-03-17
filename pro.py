# I have created Sign Up(Authority system) in which, I am stroing Username, Password in hash form
import os
import hashlib
import hmac

SALT_LENGTH = 16
HASH_ITERATIONS = 100_000
HASH_LENGTH = 32
DB_FILE = "secure_db.txt"


# Generate cryptographically secure random salt
def generate_salt(length=SALT_LENGTH):
    return os.urandom(length)


# Hash password using PBKDF2-HMAC-SHA256
def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        HASH_ITERATIONS,
        dklen=HASH_LENGTH
    )


# Check if username already exists
def username_exists(username: str) -> bool:
    if not os.path.exists(DB_FILE):
        return False

    with open(DB_FILE, "r") as f:
        for line in f:
            u, _, _ = line.strip().split()
            if u == username:
                return True
    return False


# SIGNUP
def signup(username: str, password: str):
    if username_exists(username):
        print("Username already exists!")
        return

    salt = generate_salt()
    password_hash = hash_password(password, salt)

    with open(DB_FILE, "a") as f:
        f.write(
            f"{username} {salt.hex()} {password_hash.hex()}\n"
        )

    print("User registered securely!")


# LOGIN
def login(username: str, password: str) -> bool:
    if not os.path.exists(DB_FILE):
        print("Database not found!")
        return False

    with open(DB_FILE, "r") as f:
        for line in f:
            u, salt_hex, hash_hex = line.strip().split()

            if u == username:
                salt = bytes.fromhex(salt_hex)
                stored_hash = bytes.fromhex(hash_hex)

                check_hash = hash_password(password, salt)

                # constant-time comparison
                return hmac.compare_digest(check_hash, stored_hash)

    return False


def main():
    print("1. Signup")
    print("2. Login")

    choice = input("Choose: ").strip()

    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    if choice == "1":
        signup(username, password)
    elif choice == "2":
        if login(username, password):
            print("Login successful")
        else:
            print("Login failed")
    else:
        print("Invalid choice")

    # Clear password (best effort in Python)
    password = "\0" * len(password)


if __name__ == "__main__":
    main()
