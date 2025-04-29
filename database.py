# database.py
import sqlite3
import os
import time
import datetime # Потрібно для мітки часу

db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'users.db'))

def setup_database():
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS friendships (
                user_a TEXT NOT NULL,
                user_b TEXT NOT NULL,
                FOREIGN KEY (user_a) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (user_b) REFERENCES users(username) ON DELETE CASCADE,
                PRIMARY KEY (user_a, user_b)
            )
        ''')
        # --- НОВА ТАБЛИЦЯ ДЛЯ ЗАПИТІВ В ДРУЗІ ---
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS friend_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_username TEXT NOT NULL,
                recipient_username TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'accepted', 'rejected'
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_username) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (recipient_username) REFERENCES users(username) ON DELETE CASCADE,
                UNIQUE (sender_username, recipient_username) -- Унікальна пара відправник-отримувач
            )
        ''')
        # Індекс для швидкого пошуку запитів для отримувача
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_recipient_status
            ON friend_requests (recipient_username, status);
        ''')
        # --- КІНЕЦЬ НОВОЇ ТАБЛИЦІ ---
        conn.commit()
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Перевірка/створення таблиць (включно з friend_requests) виконано.")
    except sqlite3.Error as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка під час налаштування БД: {e}")
        raise
    finally:
        if conn:
            conn.close()

# --- Функції для користувачів (залишаються без змін) ---
def check_user_exists(username):
    # ... (код без змін)
    conn = None; exists = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,))
        if cursor.fetchone(): exists = True
    except sqlite3.Error as e: print(f"[DB_ERR] Check user '{username}': {e}")
    finally:
        if conn: conn.close()
    return exists

def get_user_hash(username):
    # ... (код без змін)
    conn = None; result_hash = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        if result: result_hash = result[0]
    except sqlite3.Error as e: print(f"[DB_ERR] Get hash '{username}': {e}")
    finally:
        if conn: conn.close()
    return result_hash

def add_user(username, hashed_password):
    # ... (код без змін, який був у вашому файлі)
    conn = None; success = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit(); success = True
    # Цей блок except тут недоречний, він має бути в add_pending_request
    # except sqlite3.IntegrityError:
    #    print(f"[DB_ERR] Add user integrity '{username}'.") # Ця помилка виникне, якщо користувач вже існує
    except sqlite3.Error as e:
         print(f"[DB_ERR] Add user '{username}': {e}")
         # Можливо, варто перевірити, чи помилка - це UNIQUE constraint
         if "UNIQUE constraint failed" in str(e):
             print(f"[DB_WARN] Спроба додати існуючого користувача: {username}")
         # Не повертаємо True у випадку помилки
    finally:
        if conn: conn.close()
    return success


def find_user_by_username(username_query):
    # ... (код без змін)
    conn = None; found_username = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Повертаємо точне ім'я користувача (з урахуванням регістру), яке зберігається в БД
        cursor.execute("SELECT username FROM users WHERE username=? COLLATE NOCASE", (username_query,))
        result = cursor.fetchone()
        if result: found_username = result[0]
    except sqlite3.Error as e: print(f"[DB_ERR] Find user '{username_query}': {e}")
    finally:
        if conn: conn.close()
    return found_username

# --- Функції для дружби ---
def get_friends(username):
    # ... (код без змін)
    conn = None
    friends = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Запити для user_a і user_b залишаються, бо friendships зберігає вже встановлену дружбу
        cursor.execute("SELECT user_b FROM friendships WHERE user_a=?", (username,))
        friends.extend([row[0] for row in cursor.fetchall()])
        cursor.execute("SELECT user_a FROM friendships WHERE user_b=?", (username,))
        friends.extend([row[0] for row in cursor.fetchall()])
    except sqlite3.Error as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при отриманні друзів для '{username}': {e}")
    finally:
        if conn:
            conn.close()
    return sorted(list(set(friends))) # Унікальні та відсортовані

def add_friendship(user1, user2):
    # Ця функція тепер викликається ПІСЛЯ прийняття запиту
    if user1 == user2: return False
    # Забезпечуємо послідовність для уникнення дублікатів (a,b) vs (b,a)
    user_a = min(user1, user2)
    user_b = max(user1, user2)
    conn = None; success = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO friendships (user_a, user_b) VALUES (?, ?)", (user_a, user_b))
        conn.commit(); success = True
        print(f"[DB] Дружбу між {user_a} та {user_b} додано до таблиці friendships.")
    except sqlite3.IntegrityError:
         # Дружба вже існує, це очікувана ситуація після прийняття запиту
         print(f"[DB] Дружба між {user_a} та {user_b} вже існує в таблиці friendships.")
         success = True # Вважаємо успіхом, бо мета досягнута
    except sqlite3.Error as e: print(f"[DB_ERR] Add friendship {user_a}-{user_b}: {e}")
    finally:
        if conn: conn.close()
    return success

def check_friendship_exists(user1, user2):
    """Перевіряє, чи існує дружба між двома користувачами."""
    user_a = min(user1, user2)
    user_b = max(user1, user2)
    conn = None
    exists = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM friendships WHERE user_a=? AND user_b=?", (user_a, user_b))
        if cursor.fetchone():
            exists = True
    except sqlite3.Error as e:
        print(f"[DB_ERR] Check friendship exists {user_a}-{user_b}: {e}")
    finally:
        if conn: conn.close()
    return exists

# --- НОВІ ФУНКЦІЇ ДЛЯ ЗАПИТІВ В ДРУЗІ ---

# ================================================================
# ===== ПОЧАТОК ВИПРАВЛЕНОЇ ФУНКЦІЇ add_pending_request =====
# ================================================================
def add_pending_request(sender, recipient):
    """Додає новий запит в друзі зі статусом 'pending'."""
    if sender == recipient:
        print(f"[DB_WARN] Спроба надіслати запит самому собі: {sender}")
        return False, "cannot_request_self" # Спеціальний код помилки

    conn = None
    success = False
    error_code = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Перевірка, чи вони вже друзі
        if check_friendship_exists(sender, recipient):
             print(f"[DB] Користувачі '{sender}' та '{recipient}' вже друзі. Запит не створено.")
             return False, "already_friends"

        # Перевірка, чи існує зворотній запит (recipient -> sender)
        cursor.execute("""
            SELECT status FROM friend_requests
            WHERE sender_username = ? AND recipient_username = ?
        """, (recipient, sender))
        reverse_request_row = cursor.fetchone()
        reverse_status = reverse_request_row[0] if reverse_request_row else None

        if reverse_status == 'pending':
            # Якщо є зворотній запит, автоматично приймаємо його і створюємо дружбу
            print(f"[DB] Знайдено зворотній запит від '{recipient}' до '{sender}'. Автоматичне прийняття.")
            # Починаємо транзакцію для оновлення запиту та додавання дружби
            conn.execute("BEGIN")
            try:
                cursor.execute("""
                    UPDATE friend_requests
                    SET status = 'accepted'
                    WHERE sender_username = ? AND recipient_username = ? AND status = 'pending'
                """, (recipient, sender))
                # Перевіряємо, чи оновлення було успішним
                if cursor.rowcount > 0:
                    # Додаємо дружбу (використовуючи той самий conn в транзакції)
                    if add_friendship_internal(conn, sender, recipient):
                        conn.commit() # Фіксуємо тільки якщо все успішно
                        return True, "accepted_reverse" # Повертаємо спеціальний статус
                    else:
                        print(f"[DB_ERR] Не вдалося додати дружбу {sender}-{recipient} після авто-прийняття. Відкат.")
                        conn.rollback()
                        return False, "database_error"
                else:
                    # Малоймовірно, але запит міг змінити статус між SELECT та UPDATE
                    print(f"[DB_WARN] Зворотній запит {recipient}->{sender} змінив статус перед авто-прийняттям. Відкат.")
                    conn.rollback()
                    # Продовжуємо до створення нового запиту нижче
            except sqlite3.Error as tx_err:
                 print(f"[DB_ERR] Помилка транзакції при авто-прийнятті запиту {recipient}->{sender}: {tx_err}")
                 conn.rollback()
                 return False, "database_error"


        # Якщо немає зворотнього PENDING запиту, створюємо новий запит
        print(f"[DB] Спроба створити новий запит {sender} -> {recipient}")
        cursor.execute("""
            INSERT INTO friend_requests (sender_username, recipient_username, status)
            VALUES (?, ?, 'pending')
        """, (sender, recipient))
        conn.commit()
        success = True
        print(f"[DB] Запит в друзі від '{sender}' до '{recipient}' успішно додано зі статусом 'pending'.")

    except sqlite3.IntegrityError:
        # Це може статися, якщо запит від sender до recipient вже існує (UNIQUE constraint)
        # Перевіряємо статус існуючого запису
        print(f"[DB] IntegrityError при INSERT {sender}->{recipient}. Перевірка існуючого запису.")
        # Важливо виконати SELECT в тій самій транзакції, якщо можливо, або хоча б з тим самим conn
        cursor.execute("SELECT status FROM friend_requests WHERE sender_username=? AND recipient_username=?", (sender, recipient))
        existing_status_row = cursor.fetchone()
        existing_status = existing_status_row[0] if existing_status_row else None # Отримати статус або None
        print(f"[DB] Існуючий статус для {sender}->{recipient}: {existing_status}")

        if existing_status == 'pending':
             print(f"[DB] Запит від '{sender}' до '{recipient}' вже існує зі статусом 'pending'.")
             error_code = "request_already_pending"
        # --- ВИПРАВЛЕНА ОБРОБКА 'accepted' та 'rejected' ---
        elif existing_status == 'rejected' or existing_status == 'accepted':
             status_text = "відхилений" if existing_status == 'rejected' else "прийнятий"
             print(f"[DB] Попередній запит від '{sender}' до '{recipient}' був {status_text}. Дозволяємо новий запит (оновлюємо існуючий).")
             # Оновлюємо статус і час для існуючого запису
             try:
                 # Переконуємося, що conn все ще відкритий перед UPDATE
                 if not conn: # Малоймовірно, але для безпеки
                     conn = sqlite3.connect(db_path)
                     cursor = conn.cursor()

                 cursor.execute("""
                     UPDATE friend_requests
                     SET status = 'pending', timestamp = CURRENT_TIMESTAMP
                     WHERE sender_username = ? AND recipient_username = ?
                 """, (sender, recipient))
                 conn.commit() # Потрібно закоммітити UPDATE
                 if cursor.rowcount > 0:
                     success = True # Вважаємо це успіхом, бо запит тепер pending
                     print(f"[DB] Існуючий '{status_text}' запит від '{sender}' до '{recipient}' оновлено на 'pending'.")
                 else:
                      print(f"[DB_WARN] Не вдалося оновити існуючий '{status_text}' запит {sender}->{recipient} (можливо, вже видалений?).")
                      error_code = "database_error" # Або інший код помилки
             except sqlite3.Error as update_err:
                  print(f"[DB_ERR] Помилка при оновленні існуючого '{status_text}' запиту {sender}->{recipient}: {update_err}")
                  error_code = "database_error"
                  if conn: conn.rollback() # Відкат при помилці оновлення
        # --- КІНЕЦЬ ВИПРАВЛЕНЬ ---
        else:
             # Якщо статус не pending, не rejected і не accepted, або запису немає (що дивно при IntegrityError)
             print(f"[DB_ERR] Неочікувана IntegrityError при додаванні запиту: {sender} -> {recipient}. Існуючий статус: {existing_status}")
             error_code = "unknown_integrity_error"

    except sqlite3.Error as e:
        print(f"[DB_ERR] Add pending request {sender}->{recipient}: {e}")
        error_code = "database_error"
        # Важливо відкотити транзакцію, якщо вона була розпочата для авто-прийняття
        # Але тут ми не знаємо напевно, чи була вона розпочата.
        # Краще обробляти rollback всередині блоку try для auto-accept.

    finally:
        if conn:
             conn.close()

    return success, error_code
# ================================================================
# ===== КІНЕЦЬ ВИПРАВЛЕНОЇ ФУНКЦІЇ add_pending_request =====
# ================================================================


def get_pending_requests(username):
    """Повертає список запитів в друзі, надісланих цьому користувачеві."""
    conn = None
    requests = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT sender_username, timestamp FROM friend_requests
            WHERE recipient_username = ? AND status = 'pending'
            ORDER BY timestamp DESC
        """, (username,))
        requests = [{"sender": row[0], "timestamp": row[1]} for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"[DB_ERR] Get pending requests for '{username}': {e}")
    finally:
        if conn: conn.close()
    return requests

def update_request_status(sender, recipient, new_status):
    """Оновлює статус конкретного запиту в друзі."""
    conn = None
    success = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Перевіряємо, чи запит існує і чи він 'pending'
        cursor.execute("""
            SELECT 1 FROM friend_requests
            WHERE sender_username = ? AND recipient_username = ? AND status = 'pending'
        """, (sender, recipient))
        if not cursor.fetchone():
            print(f"[DB_WARN] Спроба оновити неіснуючий або вже оброблений запит: {sender} -> {recipient}")
            return False # Запит не знайдено або вже не 'pending'

        cursor.execute("""
            UPDATE friend_requests
            SET status = ?
            WHERE sender_username = ? AND recipient_username = ? AND status = 'pending'
        """, (new_status, sender, recipient))
        conn.commit()
        success = cursor.rowcount > 0 # Перевіряємо, чи був оновлений хоча б один рядок
        if success:
             print(f"[DB] Статус запиту {sender} -> {recipient} оновлено на '{new_status}'.")
        else:
             # Це не повинно статися через попередню перевірку, але для безпеки
             print(f"[DB_WARN] Не вдалося оновити статус запиту (можливо, стан змінився): {sender} -> {recipient}")

    except sqlite3.Error as e:
        print(f"[DB_ERR] Update request status {sender}->{recipient} to {new_status}: {e}")
    finally:
        if conn: conn.close()
    return success

# Допоміжна внутрішня функція для використання в транзакціях
def add_friendship_internal(conn, user1, user2):
    user_a = min(user1, user2)
    user_b = max(user1, user2)
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO friendships (user_a, user_b) VALUES (?, ?)", (user_a, user_b))
        print(f"[DB_INTERNAL] Дружбу між {user_a} та {user_b} додано до friendships.")
        return True
    except sqlite3.IntegrityError:
        print(f"[DB_INTERNAL] Дружба між {user_a} та {user_b} вже існує.")
        return True # Вже існує, вважаємо успіхом
    except sqlite3.Error as e:
        print(f"[DB_INTERNAL_ERR] Add friendship {user_a}-{user_b}: {e}")
        return False

# --- Функції прийняття/відхилення, які викликатиме сервер ---

def accept_friend_request(sender, recipient):
    """Приймає запит: оновлює статус та додає дружбу."""
    conn = None
    success = False
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("BEGIN") # Починаємо транзакцію

        # 1. Оновлюємо статус запиту на 'accepted'
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE friend_requests
            SET status = 'accepted'
            WHERE sender_username = ? AND recipient_username = ? AND status = 'pending'
        """, (sender, recipient))

        if cursor.rowcount == 0:
            print(f"[DB_WARN] Не знайдено 'pending' запит для прийняття: {sender} -> {recipient}")
            conn.rollback() # Відкочуємо транзакцію
            return False # Запит не знайдено або вже оброблено

        # 2. Додаємо дружбу
        if add_friendship_internal(conn, sender, recipient):
            conn.commit() # Фіксуємо транзакцію
            success = True
            print(f"[DB] Запит {sender} -> {recipient} прийнято. Дружбу додано/підтверджено.")
        else:
            print(f"[DB_ERR] Не вдалося додати дружбу після оновлення статусу запиту. Відкат.")
            conn.rollback() # Відкочуємо транзакцію

    except sqlite3.Error as e:
        print(f"[DB_ERR] Accept friend request transaction {sender}->{recipient}: {e}")
        if conn: conn.rollback() # Відкочуємо при будь-якій помилці
    finally:
        if conn: conn.close()
    return success

def reject_friend_request(sender, recipient):
    """Відхиляє запит: оновлює статус на 'rejected'."""
    # Просто використовуємо загальну функцію оновлення статусу
    print(f"[DB] Спроба відхилити запит: {sender} -> {recipient}")
    return update_request_status(sender, recipient, 'rejected')

# --- Функція видалення дружби ---

def remove_friendship(user1, user2):
    """Видаляє запис про дружбу між двома користувачами."""
    if user1 == user2: return False # Не можна видалити дружбу з самим собою

    # Визначаємо user_a та user_b, як вони зберігаються в БД
    user_a = min(user1, user2)
    user_b = max(user1, user2)

    conn = None
    success = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM friendships WHERE user_a = ? AND user_b = ?", (user_a, user_b))
        conn.commit()
        # Перевіряємо, чи був видалений рядок
        if cursor.rowcount > 0:
            success = True
            print(f"[DB] Дружбу між {user_a} та {user_b} видалено.")
        else:
            # Це може статися, якщо вони вже не були друзями
            print(f"[DB_WARN] Спроба видалити неіснуючу дружбу: {user_a} - {user_b}.")
            success = True # Вважаємо успіхом, бо мета (відсутність дружби) досягнута

    except sqlite3.Error as e:
        print(f"[DB_ERR] Remove friendship {user_a}-{user_b}: {e}")
    finally:
        if conn: conn.close()
    return success