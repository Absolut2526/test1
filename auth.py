# auth.py
import hashlib

# Ключ для зберігання імені користувача в сховищі клієнта (для сесії)
SESSION_KEY = "logged_in_user"

def hash_password(password):
    """Хешує наданий пароль за допомогою алгоритму SHA-256."""
    password_bytes = password.encode('utf-8')
    sha256_hash = hashlib.sha256(password_bytes)
    hashed_password = sha256_hash.hexdigest()
    return hashed_password

# В майбутньому тут можна додати функції для перевірки токенів, сесій тощо.