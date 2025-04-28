# database.py
import sqlite3
import os
import time

# Шлях до файлу бази даних (у тій же папці, що і цей файл)
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'users.db'))

def setup_database():
    """Створює файл БД та таблицю 'users', якщо вони ще не існують."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        # Можна додати інші таблиці тут у майбутньому
        conn.commit()
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Перевірка/створення таблиці 'users' виконано.")
    except sqlite3.Error as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка під час початкового налаштування БД: {e}")
        raise # Перевикидаємо помилку, щоб її можна було обробити вище, якщо потрібно
    finally:
        if conn:
            conn.close()

def check_user_exists(username):
    """Перевіряє, чи існує користувач з таким ім'ям (регістронезалежно)."""
    conn = None
    exists = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # COLLATE NOCASE робить порівняння нечутливим до регістру
        cursor.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,))
        if cursor.fetchone():
            exists = True
    except sqlite3.Error as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при перевірці користувача '{username}': {e}")
    finally:
        if conn:
            conn.close()
    return exists

def get_user_hash(username):
    """Повертає хеш пароля для користувача або None, якщо користувача немає."""
    conn = None
    result_hash = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Важливо вибрати користувача точно за ім'ям (можливо, з урахуванням регістру, якщо логін чутливий)
        cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        if result:
            result_hash = result[0]
    except sqlite3.Error as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при отриманні хешу для '{username}': {e}")
    finally:
        if conn:
            conn.close()
    return result_hash

def add_user(username, hashed_password):
    """Додає нового користувача до бази даних."""
    conn = None
    success = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        # Це може статися, якщо ім'я користувача вже існує (хоча ми перевіряємо це раніше)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка: Спроба додати існуючого користувача '{username}'.")
    except sqlite3.Error as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при додаванні користувача '{username}': {e}")
    finally:
        if conn:
            conn.close()
    return success

def find_user_by_username(username_query):
    """Шукає користувача за ім'ям (регістронезалежно) і повертає точне ім'я або None."""
    conn = None
    found_username = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username=? COLLATE NOCASE", (username_query,))
        result = cursor.fetchone()
        if result:
            found_username = result[0]
    except sqlite3.Error as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при пошуку користувача '{username_query}': {e}")
    finally:
        if conn:
            conn.close()
    return found_username