# backend/server.py
import flask
import os
import sys
import time # Додано для логування часу

# Додаємо батьківську директорію до шляху Python
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

try:
    import database # Тепер має імпортуватися коректно
    import auth     # <-- ДОДАНО ІМПОРТ AUTH
except ImportError as e:
    print(f"Помилка імпорту модулів database або auth: {e}")
    sys.exit(1)

app = flask.Flask(__name__)

# --- Функція для логування ---
def log_info(message):
    """Логує інформаційне повідомлення сервера."""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [SERVER] {message}")

def log_error(message):
    """Логує повідомлення про помилку сервера."""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [SERVER_ERR] {message}")

# === НОВІ ЕНДПОІНТИ ===

@app.route('/api/register', methods=['POST'])
def handle_register():
    """Обробляє реєстрацію нового користувача."""
    data = flask.request.get_json()
    if not data:
        return flask.jsonify({"error": "Відсутні дані в запиті (очікується JSON)"}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return flask.jsonify({"error": "Необхідно вказати 'username' та 'password'"}), 400

    log_info(f"Спроба реєстрації користувача: '{username}'")

    # Перевірка існування (без урахування регістру)
    if database.check_user_exists(username):
        log_info(f"Реєстрація не вдалася: користувач '{username}' вже існує.")
        return flask.jsonify({"error": f"Користувач '{username}' вже існує."}), 409 # Conflict

    # Реєстрація (з урахуванням регістру)
    hashed_pw = auth.hash_password(password)
    if database.add_user(username, hashed_pw):
        log_info(f"Користувач '{username}' успішно зареєстрований.")
        return flask.jsonify({"message": "Реєстрація успішна."}), 201 # Created
    else:
        log_error(f"Помилка БД при спробі додати користувача '{username}'.")
        return flask.jsonify({"error": "Помилка сервера під час реєстрації."}), 500

@app.route('/api/login', methods=['POST'])
def handle_login():
    """Обробляє вхід користувача."""
    data = flask.request.get_json()
    if not data:
        return flask.jsonify({"error": "Відсутні дані в запиті (очікується JSON)"}), 400

    username_input = data.get('username')
    password = data.get('password')

    if not username_input or not password:
        return flask.jsonify({"error": "Необхідно вказати 'username' та 'password'"}), 400

    log_info(f"Спроба входу користувача: '{username_input}'")

    # Шукаємо користувача без урахування регістру, щоб отримати правильний регістр
    actual_username = database.find_user_by_username(username_input)
    if not actual_username:
        log_info(f"Вхід не вдався: користувача '{username_input}' не знайдено.")
        # Не кажемо конкретно, що не так (ім'я чи пароль) з міркувань безпеки
        return flask.jsonify({"error": "Неправильне ім'я користувача або пароль."}), 401 # Unauthorized

    stored_hash = database.get_user_hash(actual_username) # Використовуємо ім'я з БД
    if not stored_hash:
        log_error(f"Не вдалося отримати хеш для існуючого користувача '{actual_username}'.")
        return flask.jsonify({"error": "Помилка сервера при вході."}), 500

    # Перевіряємо хеш пароля
    if stored_hash == auth.hash_password(password):
        log_info(f"Користувач '{actual_username}' успішно увійшов.")
        # Повертаємо фактичне ім'я користувача (з правильним регістром) для збереження в клієнтському сховищі
        return flask.jsonify({"message": "Вхід успішний.", "username": actual_username}), 200
    else:
        log_info(f"Вхід не вдався для користувача '{actual_username}': неправильний пароль.")
        return flask.jsonify({"error": "Неправильне ім'я користувача або пароль."}), 401 # Unauthorized

@app.route('/api/search_user', methods=['GET'])
def handle_search_user():
    """Шукає користувача за іменем (параметр 'query')."""
    query = flask.request.args.get('query')
    if not query:
        return flask.jsonify({"error": "Параметр 'query' є обов'язковим"}), 400

    log_info(f"Пошук користувача за запитом: '{query}'")
    found_username = database.find_user_by_username(query) # Пошук без урахування регістру

    if found_username:
        log_info(f"Знайдено користувача: '{found_username}'")
        # Повертаємо знайдене ім'я з правильним регістром
        return flask.jsonify({"found": True, "username": found_username}), 200
    else:
        log_info(f"Користувача за запитом '{query}' не знайдено.")
        return flask.jsonify({"found": False}), 404 # Not Found

@app.route('/api/friends/<username>', methods=['GET'])
def handle_get_friends(username):
    """Повертає список друзів для вказаного користувача."""
    # ВАЖЛИВО: В реальному додатку тут потрібна перевірка авторизації:
    # чи має запитувач право бачити список друзів для <username>?
    # Наприклад, чи є запитувач == <username>?
    log_info(f"Запит списку друзів для користувача '{username}'")

    # Перевіряємо, чи існує такий користувач взагалі
    if not database.check_user_exists(username):
         log_info(f"Користувача '{username}' не знайдено для отримання списку друзів.")
         return flask.jsonify({"error": "Користувача не знайдено"}), 404

    friends = database.get_friends(username)
    log_info(f"Знайдено {len(friends)} друзів для '{username}'.")
    return flask.jsonify({"friends": friends}), 200

# === ЕНДПОІНТИ ДЛЯ ДРУЖБИ (з доповненим логуванням та обробкою помилок) ===

@app.route('/api/friend_request', methods=['POST'])
def handle_friend_request():
    """Обробляє надсилання запиту в друзі."""
    data = flask.request.get_json()
    if not data: return flask.jsonify({"error": "Відсутні дані в запиті (очікується JSON)"}), 400
    sender = data.get('sender_username'); recipient = data.get('recipient_username')
    if not sender or not recipient: return flask.jsonify({"error": "Необхідно вказати 'sender_username' та 'recipient_username'"}), 400

    log_info(f"Отримано запит в друзі від '{sender}' до '{recipient}'")

    # Перевірка існування користувачів
    if not database.check_user_exists(sender):
        log_error(f"Відправник '{sender}' не знайдений.")
        # Не повідомляємо клієнту, хто саме не знайдений з міркувань безпеки
        return flask.jsonify({"error": "Не вдалося обробити запит (відправник)."}), 400
    if not database.check_user_exists(recipient):
        log_info(f"Отримувач '{recipient}' не знайдений для запиту в друзі.")
        # Тут можна повідомити, бо клієнт сам вказав отримувача
        return flask.jsonify({"error": f"Користувача '{recipient}' не знайдено."}), 404

    # Спроба додати PENDING запит або автоматично прийняти зворотній
    success, reason = database.add_pending_request(sender, recipient)

    if success:
        if reason == "accepted_reverse":
            log_info(f"Запит від '{sender}' до '{recipient}' автоматично прийнято (був зворотній запит).")
            return flask.jsonify({"message": f"Ви тепер друзі з '{recipient}' (зустрічний запит)."}), 200 # OK
        else: # Стандартний успішний запит
            log_info(f"Запит від '{sender}' до '{recipient}' успішно створено.")
            # Тут можна додати push-сповіщення для recipient
            return flask.jsonify({"message": f"Запит в друзі до '{recipient}' надіслано."}), 201 # Created
    else:
        # Обробка відомих причин помилок
        error_message, status_code = {
            "cannot_request_self": ("Ви не можете надіслати запит самому собі.", 400),
            "already_friends": (f"Ви вже друзі з '{recipient}'.", 409), # Conflict
            "request_already_pending": (f"Запит до '{recipient}' вже очікує розгляду.", 409), # Conflict
            "unknown_integrity_error": ("Внутрішня помилка сервера при обробці запиту.", 500),
            "database_error": ("Внутрішня помилка сервера при обробці запиту.", 500)
            # Додайте інші коди помилок з add_pending_request, якщо потрібно
        }.get(reason, ("Не вдалося обробити запит (невідома причина).", 500)) # За замовчуванням

        log_error(f"Не вдалося створити запит: {sender} -> {recipient}, Причина: {reason}")
        return flask.jsonify({"error": error_message}), status_code

@app.route('/api/notifications/<username>', methods=['GET'])
def get_notifications(username):
    """Повертає список очікуючих запитів в друзі для користувача."""
    # ВАЖЛИВО: Додати перевірку авторизації (чи запитувач == username?)
    log_info(f"Запит сповіщень для користувача '{username}'.")
    if not database.check_user_exists(username):
        log_info(f"Користувача '{username}' не знайдено для отримання сповіщень.")
        return flask.jsonify({"error": "Користувача не знайдено"}), 404

    pending_requests = database.get_pending_requests(username)
    log_info(f"Знайдено {len(pending_requests)} запитів для '{username}'.")
    # В майбутньому можна додати інші типи сповіщень сюди
    return flask.jsonify({"pending_friend_requests": pending_requests}), 200


@app.route('/api/friend_request/accept', methods=['POST'])
def accept_request():
    """Приймає запит в друзі."""
    data = flask.request.get_json()
    if not data: return flask.jsonify({"error": "Відсутні дані"}), 400
    sender = data.get('sender_username'); recipient = data.get('recipient_username')
    if not sender or not recipient: return flask.jsonify({"error": "Необхідно вказати 'sender_username' та 'recipient_username'"}), 400

    # ВАЖЛИВО: Додати перевірку авторизації, що запитувач дійсно є 'recipient'
    # (наприклад, перевірити токен сесії)
    log_info(f"Спроба прийняти запит від '{sender}'. Отримувач (поточний користувач): '{recipient}'.")

    success = database.accept_friend_request(sender, recipient)

    if success:
        log_info(f"Запит від '{sender}' до '{recipient}' успішно прийнято.")
        # Можна надіслати сповіщення 'sender'
        return flask.jsonify({"message": f"Ви тепер друзі з '{sender}'."}), 200
    else:
        # Причина може бути: запит не існує, вже оброблений, помилка БД
        log_error(f"Не вдалося прийняти запит від '{sender}' до '{recipient}'.")
        # Відповідь може залежати від причини, але поки загальна
        return flask.jsonify({"error": "Не вдалося прийняти запит. Можливо, він вже був оброблений або виникла помилка."}), 400 # Bad Request or 404 Not Found?


@app.route('/api/friend_request/reject', methods=['POST'])
def reject_request():
    """Відхиляє запит в друзі."""
    data = flask.request.get_json()
    if not data: return flask.jsonify({"error": "Відсутні дані"}), 400
    sender = data.get('sender_username'); recipient = data.get('recipient_username')
    if not sender or not recipient: return flask.jsonify({"error": "Необхідно вказати 'sender_username' та 'recipient_username'"}), 400

    # ВАЖЛИВО: Додати перевірку авторизації 'recipient'
    log_info(f"Спроба відхилити запит від '{sender}'. Отримувач (поточний користувач): '{recipient}'.")

    success = database.reject_friend_request(sender, recipient)

    if success:
        log_info(f"Запит від '{sender}' до '{recipient}' успішно відхилено.")
        # Можна надіслати сповіщення 'sender'
        return flask.jsonify({"message": f"Запит від '{sender}' відхилено."}), 200
    else:
        log_error(f"Не вдалося відхилити запит від '{sender}' до '{recipient}'.")
        return flask.jsonify({"error": "Не вдалося відхилити запит. Можливо, він вже був оброблений."}), 400

@app.route('/api/friendship/remove', methods=['POST'])
def remove_friend():
    """Видаляє друга."""
    data = flask.request.get_json()
    if not data: return flask.jsonify({"error": "Відсутні дані в запиті (очікується JSON)"}), 400
    user_a = data.get('user_a'); user_b = data.get('user_b')
    if not user_a or not user_b: return flask.jsonify({"error": "Необхідно вказати 'user_a' та 'user_b'"}), 400

    # ВАЖЛИВО: Додати перевірку авторизації (чи є запитувач user_a або user_b)
    # current_requester = ... # отримати з токена/сесії
    # if current_requester not in [user_a, user_b]:
    #     return flask.jsonify({"error": "Неавторизовано"}), 403

    log_info(f"Спроба видалити дружбу між '{user_a}' та '{user_b}'.")
    success = database.remove_friendship(user_a, user_b)

    if success:
        log_info(f"Дружбу між '{user_a}' та '{user_b}' успішно видалено (або вже не існувала).")
        # Визначення, хто був видалений для повідомлення (потрібна інфо про запитувача)
        # other_user = user_b if current_requester == user_a else user_a
        return flask.jsonify({"message": f"Друг видалений."}), 200 # Повідомлення може бути кращим
    else:
        # Ця гілка спрацює тільки при помилці БД
        log_error(f"Не вдалося видалити дружбу між '{user_a}' та '{user_b}' (помилка БД).")
        return flask.jsonify({"error": "Внутрішня помилка сервера при видаленні друга."}), 500

# --- Старий ендпоінт для прикладу (можна видалити) ---
# @app.route('/api/data')
# def get_data():
#     return flask.jsonify({"message": "Дані з бекенду"})

if __name__ == "__main__":
    # Ініціалізація БД при старті сервера
    try:
        database.setup_database()
        log_info("Базу даних успішно ініціалізовано.")
    except Exception as e:
        log_error(f"КРИТИЧНО: Не вдалося ініціалізувати базу даних: {e}. Сервер не може стартувати.")
        sys.exit(1)

    log_info("Запуск Flask сервера на http://0.0.0.0:5000 ...")
    # host='0.0.0.0' робить сервер доступним з інших пристроїв у мережі
    # debug=True зручно для розробки, але вимкніть для продакшену
    app.run(host='0.0.0.0', port=5000, debug=True)