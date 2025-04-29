# backend/server.py
import flask
import os
import sys

# Додаємо батьківську директорію до шляху Python
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

try:
    import database # Тепер має імпортуватися коректно
except ImportError as e:
    print(f"Помилка імпорту модуля database: {e}")
    sys.exit(1)

app = flask.Flask(__name__)

# --- Ендпоінт надсилання запиту ---
@app.route('/api/friend_request', methods=['POST'])
def handle_friend_request():
    """
    Обробляє надсилання запиту в друзі.
    Створює запис у таблиці friend_requests зі статусом 'pending'.
    Очікує JSON з полями 'sender_username' та 'recipient_username'.
    """
    data = flask.request.get_json()
    if not data:
        return flask.jsonify({"error": "Відсутні дані в запиті (очікується JSON)"}), 400

    sender = data.get('sender_username')
    recipient = data.get('recipient_username')

    if not sender or not recipient:
        return flask.jsonify({"error": "Необхідно вказати 'sender_username' та 'recipient_username'"}), 400

    print(f"[SERVER] Отримано запит в друзі від '{sender}' до '{recipient}'")

    # Перевірка існування користувачів
    if not database.check_user_exists(sender):
        print(f"[SERVER_ERR] Відправник '{sender}' не знайдений.")
        # Не повідомляємо клієнту про це з міркувань безпеки
        return flask.jsonify({"error": "Не вдалося обробити запит"}), 400 # Або 404? Залежить від політики

    if not database.check_user_exists(recipient):
        print(f"[SERVER_ERR] Отримувач '{recipient}' не знайдений.")
        # Повідомляємо клієнту, бо він ініціював дію щодо цього користувача
        return flask.jsonify({"error": f"Користувача '{recipient}' не знайдено."}), 404

    # Спроба додати PENDING запит
    success, reason = database.add_pending_request(sender, recipient)

    if success:
        if reason == "accepted_reverse":
            print(f"[SERVER] Запит від '{sender}' до '{recipient}' автоматично прийнято (був зворотній запит).")
            return flask.jsonify({"message": f"Ви тепер друзі з '{recipient}' (зустрічний запит)."}), 200 # OK
        else:
            print(f"[SERVER] Запит від '{sender}' до '{recipient}' успішно створено.")
            # Тут можна додати механізм push-сповіщень для recipient, якщо використовується WebSocket або подібне
            return flask.jsonify({"message": f"Запит в друзі до '{recipient}' надіслано."}), 201 # Created
    else:
        # Обробка різних причин невдачі
        if reason == "cannot_request_self":
            return flask.jsonify({"error": "Ви не можете надіслати запит самому собі."}), 400 # Bad Request
        elif reason == "already_friends":
            return flask.jsonify({"error": f"Ви вже друзі з '{recipient}'."}), 409 # Conflict
        elif reason == "request_already_pending":
            return flask.jsonify({"error": f"Запит до '{recipient}' вже очікує розгляду."}), 409 # Conflict
        elif reason == "unknown_integrity_error" or reason == "database_error":
            print(f"[SERVER_ERR] Не вдалося створити запит: {sender} -> {recipient}, Причина: {reason}")
            return flask.jsonify({"error": "Внутрішня помилка сервера при обробці запиту."}), 500 # Internal Server Error
        else:
            # Невідома помилка
             print(f"[SERVER_ERR] Невідома помилка при додаванні запиту: {sender} -> {recipient}, Причина: {reason}")
             return flask.jsonify({"error": "Не вдалося обробити запит."}), 500


# --- Ендпоінт отримання сповіщень (запитів) ---
@app.route('/api/notifications/<username>', methods=['GET'])
def get_notifications(username):
    """
    Повертає список запитів в друзі, що очікують на розгляд цим користувачем.
    """
    print(f"[SERVER] Запит сповіщень для користувача '{username}'.")
    # Перевірка, чи існує користувач (опціонально, залежить від вимог)
    # if not database.check_user_exists(username):
    #     return flask.jsonify({"error": "Користувача не знайдено"}), 404

    pending_requests = database.get_pending_requests(username)
    print(f"[SERVER] Знайдено {len(pending_requests)} запитів для '{username}'.")

    # Можна додати інші типи сповіщень сюди в майбутньому
    return flask.jsonify({"pending_friend_requests": pending_requests}), 200


# --- Ендпоінт прийняття запиту ---
@app.route('/api/friend_request/accept', methods=['POST'])
def accept_request():
    """
    Приймає запит в друзі.
    Очікує JSON: {'sender_username': '...', 'recipient_username': '...'}
    де recipient_username - це поточний користувач, який приймає запит.
    """
    data = flask.request.get_json()
    if not data: return flask.jsonify({"error": "Відсутні дані"}), 400

    sender = data.get('sender_username')
    # Поточного користувача (отримувача запиту) теж треба передати
    recipient = data.get('recipient_username')

    if not sender or not recipient:
        return flask.jsonify({"error": "Необхідно вказати 'sender_username' та 'recipient_username'"}), 400

    # ВАЖЛИВО: В реальному додатку тут має бути перевірка,
    # що користувач, який робить запит до цього ендпоінту,
    # дійсно є 'recipient'. Це вимагає системи сесій/токенів на сервері.
    # Поки що ми довіряємо даним від клієнта.
    print(f"[SERVER] Спроба прийняти запит від '{sender}'. Отримувач (поточний користувач): '{recipient}'.")

    success = database.accept_friend_request(sender, recipient)

    if success:
        print(f"[SERVER] Запит від '{sender}' до '{recipient}' успішно прийнято.")
        # Можна надіслати сповіщення 'sender', що його запит прийнято
        return flask.jsonify({"message": f"Ви тепер друзі з '{sender}'."}), 200
    else:
        print(f"[SERVER_ERR] Не вдалося прийняти запит від '{sender}' до '{recipient}' (можливо, вже оброблено або помилка БД).")
        # Відповідь може залежати від причини невдачі (якої зараз не повертає accept_friend_request)
        return flask.jsonify({"error": "Не вдалося прийняти запит. Можливо, він вже був оброблений."}), 400 # Або 404/500


# --- Ендпоінт відхилення запиту ---
@app.route('/api/friend_request/reject', methods=['POST'])
def reject_request():
    """
    Відхиляє запит в друзі.
    Очікує JSON: {'sender_username': '...', 'recipient_username': '...'}
    де recipient_username - це поточний користувач, який відхиляє запит.
    """
    data = flask.request.get_json()
    if not data: return flask.jsonify({"error": "Відсутні дані"}), 400

    sender = data.get('sender_username')
    recipient = data.get('recipient_username')

    if not sender or not recipient:
        return flask.jsonify({"error": "Необхідно вказати 'sender_username' та 'recipient_username'"}), 400

    # ВАЖЛИВО: Аналогічна перевірка автентичності 'recipient', як і в /accept
    print(f"[SERVER] Спроба відхилити запит від '{sender}'. Отримувач (поточний користувач): '{recipient}'.")

    success = database.reject_friend_request(sender, recipient)

    if success:
        print(f"[SERVER] Запит від '{sender}' до '{recipient}' успішно відхилено.")
        # Можна надіслати сповіщення 'sender', що його запит відхилено
        return flask.jsonify({"message": f"Запит від '{sender}' відхилено."}), 200
    else:
        print(f"[SERVER_ERR] Не вдалося відхилити запит від '{sender}' до '{recipient}' (можливо, вже оброблено або помилка БД).")
        return flask.jsonify({"error": "Не вдалося відхилити запит. Можливо, він вже був оброблений."}), 400 # Або 404/500

# --- Ендпоінт видалення друга ---
@app.route('/api/friendship/remove', methods=['POST'])
def remove_friend():
    """
    Обробляє видалення друга.
    Очікує JSON: {'user_a': '...', 'user_b': '...'}
    де один з користувачів - той, хто ініціює видалення.
    """
    data = flask.request.get_json()
    if not data:
        return flask.jsonify({"error": "Відсутні дані в запиті (очікується JSON)"}), 400

    user_a = data.get('user_a')
    user_b = data.get('user_b')

    if not user_a or not user_b:
        return flask.jsonify({"error": "Необхідно вказати 'user_a' та 'user_b'"}), 400

    # ВАЖЛИВО: В реальному додатку тут має бути перевірка,
    # що користувач, який робить запит до цього ендпоінту,
    # дійсно є user_a або user_b (перевірка сесії/токену).
    # Поки що ми довіряємо даним від клієнта.
    print(f"[SERVER] Спроба видалити дружбу між '{user_a}' та '{user_b}'.")

    # Викликаємо функцію бази даних
    success = database.remove_friendship(user_a, user_b)

    if success:
        print(f"[SERVER] Дружбу між '{user_a}' та '{user_b}' успішно видалено (або вже не існувала).")
        return flask.jsonify({"message": f"Ви більше не друзі з '{user_b if user_a == flask.request.headers.get('X-Current-User') else user_a}'."}), 200 # OK
        # Примітка: Визначення, хто є 'other user', потребує передачі поточного користувача, наприклад, у заголовку
    else:
        # Ця гілка спрацює тільки якщо була помилка БД
        print(f"[SERVER_ERR] Не вдалося видалити дружбу між '{user_a}' та '{user_b}' (помилка БД).")
        return flask.jsonify({"error": "Внутрішня помилка сервера при видаленні друга."}), 500 # Internal Server Error

# Старий ендпоінт для прикладу
@app.route('/api/data')
def get_data():
    return flask.jsonify({"message": "Дані з бекенду"})


if __name__ == "__main__":
    # Ініціалізація БД
    try:
        database.setup_database()
        print("[SERVER] Базу даних успішно ініціалізовано.")
    except Exception as e:
        print(f"[SERVER_CRITICAL] Не вдалося ініціалізувати базу даних: {e}. Сервер не може стартувати.")
        sys.exit(1)

    print("[SERVER] Запуск Flask сервера...")
    app.run(host='0.0.0.0', port=5000, debug=True) # debug=True зручно для розробки