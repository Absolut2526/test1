import hashlib

SESSION_KEY = "logged_in_user"

def hash_password(password):
    password_bytes = password.encode('utf-8')
    sha256_hash = hashlib.sha256(password_bytes)
    hashed_password = sha256_hash.hexdigest()
    return hashed_password