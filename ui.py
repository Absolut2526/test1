# ui.py
import flet as ft
import database
import auth
import time
import requests # <-- Додано імпорт
import json     # <-- Додано імпорт для обробки JSON-відповідей

# URL вашого бекенд-сервера
BACKEND_URL = "http://localhost:5000"

# --- UI для екрану Входу/Реєстрації ---
def create_login_register_view(page: ft.Page, show_logged_in_callback):
    # (Код цієї функції залишається БЕЗ ЗМІН з попередньої версії)
    reg_username_field = ft.TextField(label="Ім'я користувача (реєстрація)", width=300)
    reg_password_field = ft.TextField(label="Пароль (реєстрація)", password=True, can_reveal_password=True, width=300)
    reg_confirm_password_field = ft.TextField(label="Підтвердіть пароль", password=True, can_reveal_password=True, width=300)
    login_username_field = ft.TextField(label="Ім'я користувача (вхід)", width=300)
    login_password_field = ft.TextField(label="Пароль (вхід)", password=True, can_reveal_password=True, width=300)
    feedback_text = ft.Text(value="", color=ft.colors.RED, text_align=ft.TextAlign.CENTER, width=300)
    def register_click(e):
        username = reg_username_field.value.strip(); password = reg_password_field.value; confirm_password = reg_confirm_password_field.value
        feedback_text.value = ""; feedback_text.color = ft.colors.RED
        if not username or not password or not confirm_password: feedback_text.value = "Будь ласка, заповніть всі поля реєстрації."; page.update(); return
        if password != confirm_password: feedback_text.value = "Паролі не співпадають."; reg_password_field.value = ""; reg_confirm_password_field.value = ""; reg_password_field.focus(); page.update(); return
        # Використовуємо find_user_by_username для перевірки без урахування регістру, як у логіні
        if database.find_user_by_username(username): feedback_text.value = f"Користувач '{username}' вже існує."
        else:
            hashed_pw = auth.hash_password(password)
            # Використовуємо фактичне ім'я користувача (з регістром) для додавання
            if database.add_user(username, hashed_pw):
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' зареєстрований. Збереження сесії.")
                page.client_storage.set(auth.SESSION_KEY, username) # Зберігаємо ім'я з оригінальним регістром
                show_logged_in_callback(username); return
            else: feedback_text.value = "Не вдалося зареєструвати користувача (помилка БД)."
        page.update()
    def login_click(e):
        username_input = login_username_field.value.strip(); password = login_password_field.value
        feedback_text.value = ""; feedback_text.color = ft.colors.RED
        if not username_input or not password: feedback_text.value = "Будь ласка, заповніть всі поля для входу."; page.update(); return

        # Знаходимо користувача без урахування регістру, але отримуємо ім'я з БД (з правильним регістром)
        actual_username = database.find_user_by_username(username_input)
        if actual_username:
            stored_hash = database.get_user_hash(actual_username) # Використовуємо ім'я з БД
            if stored_hash:
                entered_hash = auth.hash_password(password)
                if stored_hash == entered_hash:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{actual_username}' увійшов. Збереження сесії.")
                    page.client_storage.set(auth.SESSION_KEY, actual_username) # Зберігаємо ім'я з БД
                    show_logged_in_callback(actual_username); return
                else: feedback_text.value = "Неправильний пароль."
            else:
                # Це не повинно статися, якщо find_user_by_username повернув ім'я
                feedback_text.value = "Помилка отримання даних користувача."
        else: feedback_text.value = f"Користувача '{username_input}' не знайдено."
        page.update()
    register_button = ft.ElevatedButton("Зареєструватися", on_click=register_click, width=300)
    login_button = ft.ElevatedButton("Увійти", on_click=login_click, width=300)
    login_tab_content = ft.Column([login_username_field, login_password_field, login_button], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    register_tab_content = ft.Column([reg_username_field, reg_password_field, reg_confirm_password_field, register_button], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    tabs = ft.Tabs(selected_index=0, animation_duration=300, tabs=[ft.Tab(text="Реєстрація", content=register_tab_content), ft.Tab(text="Вхід", content=login_tab_content)], expand=1)
    view_column = ft.Column([tabs, ft.Container(content=feedback_text, padding=ft.padding.only(top=20))], alignment=ft.MainAxisAlignment.START, horizontal_alignment=ft.CrossAxisAlignment.CENTER, expand=True)
    return view_column


# --- UI для основного екрану програми ---
def create_logged_in_view(page: ft.Page, username: str, show_login_callback):
    """Створює UI для основного екрану програми."""
    search_user_field = ft.TextField(label="Введіть ім'я користувача", expand=True)
    search_result_area = ft.Column(visible=False, spacing=10, animate_opacity=ft.Animation(300, ft.AnimationCurve.EASE_IN_OUT))
    friends_list_area = ft.Column(visible=False, spacing=5, animate_opacity=ft.Animation(300, ft.AnimationCurve.EASE_IN_OUT))
    notifications_area = ft.Column(visible=False, spacing=5) # Область для сповіщень

    # --- Функція для показу повідомлень (ВИПРАВЛЕНА ВЕРСІЯ) ---
    def show_message(message_text, color=ft.colors.BLACK, duration_ms=3000):
        # Створюємо SnackBar
        snack_bar = ft.SnackBar(
            content=ft.Text(message_text, color=ft.colors.WHITE), # Білий текст для кращого контрасту
            bgcolor=color,
            duration=duration_ms,
            open=True # Відразу встановлюємо як відкритий
        )
        # Призначаємо його атрибуту page.snack_bar
        page.snack_bar = snack_bar
        # Оновлюємо сторінку, щоб показати SnackBar
        page.update()

    def logout_click(e):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' виходить. Видалення сесії.")
        page.client_storage.remove(auth.SESSION_KEY)
        show_login_callback()

    # --- ОНОВЛЕНА Функція надсилання запиту ---
    def send_friend_request_api(target_username):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user:
            show_message("Помилка: Не вдалося визначити поточного користувача.", ft.colors.RED)
            return

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Надсилання запиту в друзі від '{current_user}' до '{target_username}'...")
        search_result_area.controls.clear() # Очистити попередні результати
        # Показати індикатор завантаження (опціонально)
        search_result_area.controls.append(ft.ProgressRing(width=16, height=16, stroke_width = 2))
        search_result_area.visible = True
        page.update()

        api_endpoint = f"{BACKEND_URL}/api/friend_request"
        payload = {
            "sender_username": current_user,
            "recipient_username": target_username
        }

        try:
            # Встановлюємо заголовки, щоб сервер знав, що ми надсилаємо JSON
            headers = {'Content-Type': 'application/json'}
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10) # Додано timeout та headers

            # Обробка відповіді, навіть якщо вона не JSON
            search_result_area.controls.clear() # Очистити індикатор

            if 200 <= response.status_code < 300: # Успішні коди (200, 201, тощо)
                try:
                    response_data = response.json()
                    message = response_data.get("message", "Запит успішно оброблено.")
                    search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN), ft.Text(message, color=ft.colors.GREEN)]))
                    print(f"[API_SUCCESS] {response.status_code}: {message}")
                except json.JSONDecodeError:
                    # Успішний статус, але відповідь не JSON
                    message = f"Запит успішно оброблено (Код: {response.status_code})."
                    search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN), ft.Text(message, color=ft.colors.GREEN)]))
                    print(f"[API_SUCCESS_NO_JSON] {response.status_code}")
            else:
                # Помилка
                try:
                     response_data = response.json()
                     error_message = response_data.get("error", f"Невідома помилка з сервера (Код: {response.status_code})")
                except json.JSONDecodeError:
                     error_message = f"Помилка сервера (Код: {response.status_code}). Не вдалося розібрати відповідь."

                search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.ERROR, color=ft.colors.RED), ft.Text(error_message, color=ft.colors.RED)]))
                print(f"[API_ERROR] {response.status_code}: {error_message}")


        except requests.exceptions.RequestException as req_err:
            search_result_area.controls.clear() # Очистити індикатор
            error_text = f"Помилка мережі при надсиланні запиту: {req_err}"
            search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.ERROR_OUTLINE, color=ft.colors.RED), ft.Text(error_text, color=ft.colors.RED)]))
            print(f"[NETWORK_ERROR] {error_text}")
        except Exception as e:
             search_result_area.controls.clear() # Очистити індикатор
             error_text = f"Неочікувана помилка в UI: {e}"
             search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.ERROR_OUTLINE, color=ft.colors.RED), ft.Text(error_text, color=ft.colors.RED)]))
             print(f"[UNEXPECTED_ERROR] {error_text}")

        page.update()


    def search_user_click(e):
        target_username_query = search_user_field.value.strip()
        current_user = page.client_storage.get(auth.SESSION_KEY)
        search_result_area.controls.clear(); search_result_area.visible = True
        if not target_username_query:
             search_result_area.controls.append(ft.Text("Введіть ім'я користувача.", color=ft.colors.ORANGE))
             page.update(); return
        if target_username_query.lower() == current_user.lower():
             search_result_area.controls.append(ft.Text("Ви не можете шукати себе."))
             page.update(); return

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Пошук користувача '{target_username_query}'...")
        # Використовуємо локальний пошук через database.py
        # В реальному додатку тут теж міг би бути API виклик
        found_username = database.find_user_by_username(target_username_query)
        if found_username:
            search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN), ft.Text(f"Користувача '{found_username}' знайдено.")]))
             # Перевірка, чи вони вже друзі (локально)
            are_friends = database.check_friendship_exists(current_user, found_username)
            # Перевірка, чи є активний запит (локально)
            # (Це складніше перевірити локально без статусу, краще покладатись на відповідь API)

            if are_friends:
                 search_result_area.controls.append(ft.Text(f"Ви вже друзі з '{found_username}'."))
            else:
                 # --- Кнопка викликає send_friend_request_api ---
                 search_result_area.controls.append(
                     ft.ElevatedButton(
                         f"Надіслати запит в друзі до '{found_username}'",
                         icon=ft.icons.PERSON_ADD,
                         on_click=lambda _, u=found_username: send_friend_request_api(u) # <--- ВИКЛИК API
                     )
                 )
        else:
            search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.CANCEL, color=ft.colors.RED), ft.Text(f"Користувача '{target_username_query}' не знайдено.")]))
        page.update()

    def show_friends_click(e):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user: return # Додаткова перевірка
        friends_list_area.controls.clear(); friends_list_area.visible = True
        friends_list_area.update() # Показати одразу

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Завантаження списку друзів для '{current_user}'...")
        # Додаємо індикатор завантаження
        loading_indicator = ft.Row([ft.ProgressRing(width=16, height=16, stroke_width = 2), ft.Text("Завантаження...")])
        friends_list_area.controls.append(loading_indicator)
        page.update()

        # Отримуємо друзів (можна додати обробку помилок)
        friends = []
        try:
            friends = database.get_friends(current_user)
        except Exception as db_err:
             print(f"[DB_ERROR] Помилка при отриманні друзів: {db_err}")
             friends_list_area.controls.clear()
             friends_list_area.controls.append(ft.Text("Помилка завантаження списку друзів.", color=ft.colors.RED))
             page.update()
             return

        # Видаляємо індикатор завантаження
        friends_list_area.controls.remove(loading_indicator)

        if friends:
            friends_list_area.controls.append(ft.Text("Список друзів:", weight=ft.FontWeight.BOLD))
            lv = ft.ListView(spacing=5, auto_scroll=True, expand=False, height=150) # Обмеження висоти для прокрутки
            for friend in friends:
                 # TODO: Додати кнопку "Видалити з друзів" (потребує API)
                 friend_row = ft.Row(
                     [
                         ft.Icon(ft.icons.PERSON_OUTLINE),
                         ft.Text(friend, expand=True), # Дозволяємо імені розширюватись
                         ft.IconButton(
                             ft.icons.PERSON_REMOVE_OUTLINED, # Іконка видалення
                             tooltip=f"Видалити {friend} з друзів",
                             on_click=lambda _, f=friend: remove_friend_api(f), # Виклик API при кліку
                             icon_color=ft.colors.RED_400 # Колір іконки
                         )
                     ],
                     alignment=ft.MainAxisAlignment.SPACE_BETWEEN # Розташування елементів
                 )
                 lv.controls.append(friend_row)
            friends_list_area.controls.append(lv)
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Знайдено друзів: {', '.join(friends)}")
        else:
            friends_list_area.controls.append(ft.Text("У вас поки що немає друзів."))
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Друзів не знайдено.")

        friends_list_area.controls.append(ft.TextButton("Приховати список", on_click=hide_friends_list))
        page.update()

    def hide_friends_list(e):
        friends_list_area.visible = False
        # friends_list_area.controls.clear() # Не очищаємо, щоб швидко показати знову
        page.update()


    # --- Функції для обробки сповіщень (запитів в друзі) ---
    def accept_request_api(sender_username):
         current_user = page.client_storage.get(auth.SESSION_KEY)
         if not current_user:
             show_message("Помилка сесії. Спробуйте увійти знову.", ft.colors.RED)
             return

         print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Прийняття запиту від '{sender_username}' користувачем '{current_user}'...")
         api_endpoint = f"{BACKEND_URL}/api/friend_request/accept"
         payload = {"sender_username": sender_username, "recipient_username": current_user}
         headers = {'Content-Type': 'application/json'}
         try:
             response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)
             if 200 <= response.status_code < 300:
                 show_message(f"Ви тепер друзі з {sender_username}!", ft.colors.GREEN)
                 # Оновити список сповіщень та, можливо, список друзів
                 load_notifications()
                 if friends_list_area.visible: # Оновити видимий список друзів
                      show_friends_click(None)
             else:
                 try:
                     error_msg = response.json().get("error", f"Не вдалося прийняти запит (Код: {response.status_code}).")
                 except json.JSONDecodeError:
                     error_msg = f"Не вдалося прийняти запит (Код: {response.status_code}). Сервер не повернув JSON."
                 show_message(f"Помилка: {error_msg}", ft.colors.RED)
                 print(f"[API_ERROR] Accept Request {sender_username}->{current_user}: {response.status_code} - {error_msg}")
         except Exception as e:
             show_message(f"Помилка мережі або сервера при прийнятті запиту.", ft.colors.RED)
             print(f"[NETWORK_ERROR] Accept Request: {e}")
         page.update()

    def reject_request_api(sender_username):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user:
             show_message("Помилка сесії. Спробуйте увійти знову.", ft.colors.RED)
             return

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Відхилення запиту від '{sender_username}' користувачем '{current_user}'...")
        api_endpoint = f"{BACKEND_URL}/api/friend_request/reject"
        payload = {"sender_username": sender_username, "recipient_username": current_user}
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)
            if 200 <= response.status_code < 300:
                show_message(f"Запит від {sender_username} відхилено.", ft.colors.ORANGE)
                # Оновити список сповіщень
                load_notifications()
            else:
                try:
                    error_msg = response.json().get("error", f"Не вдалося відхилити запит (Код: {response.status_code}).")
                except json.JSONDecodeError:
                     error_msg = f"Не вдалося відхилити запит (Код: {response.status_code}). Сервер не повернув JSON."
                show_message(f"Помилка: {error_msg}", ft.colors.RED)
                print(f"[API_ERROR] Reject Request {sender_username}->{current_user}: {response.status_code} - {error_msg}")
        except Exception as e:
            show_message(f"Помилка мережі або сервера при відхиленні запиту.", ft.colors.RED)
            print(f"[NETWORK_ERROR] Reject Request: {e}")
        page.update()

    # --- Функція для видалення друга через API ---
    def remove_friend_api(friend_to_remove):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user:
             show_message("Помилка сесії. Спробуйте увійти знову.", ft.colors.RED)
             return

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Видалення друга '{friend_to_remove}' користувачем '{current_user}'...")

        api_endpoint = f"{BACKEND_URL}/api/friendship/remove"
        # Неважливо, хто user_a, а хто user_b для бекенду, але для ясності:
        payload = {"user_a": current_user, "user_b": friend_to_remove}
        headers = {
            'Content-Type': 'application/json',
            'X-Current-User': current_user # Передаємо поточного користувача для повідомлення у відповіді
            }

        try:
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)
            if 200 <= response.status_code < 300:
                try:
                    message = response.json().get("message", f"Друга {friend_to_remove} видалено.")
                except json.JSONDecodeError:
                    message = f"Друга {friend_to_remove} видалено."
                show_message(message, ft.colors.GREEN)
                # Оновити список друзів, якщо він видимий
                if friends_list_area.visible:
                    show_friends_click(None) # Перезавантажити список друзів
            else:
                try:
                    error_msg = response.json().get("error", f"Не вдалося видалити друга (Код: {response.status_code}).")
                except json.JSONDecodeError:
                     error_msg = f"Не вдалося видалити друга (Код: {response.status_code}). Сервер не повернув JSON."
                show_message(f"Помилка: {error_msg}", ft.colors.RED)
                print(f"[API_ERROR] Remove Friend {current_user}-{friend_to_remove}: {response.status_code} - {error_msg}")
        except Exception as e:
            show_message(f"Помилка мережі або сервера при видаленні друга.", ft.colors.RED)
            print(f"[NETWORK_ERROR] Remove Friend: {e}")
        # page.update() # Не потрібно, бо show_friends_click зробить update

    def load_notifications():
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user:
             notifications_area.controls.clear()
             notifications_area.controls.append(ft.Text("Помилка сесії.", color=ft.colors.RED))
             notifications_area.visible = True
             page.update()
             return

        notifications_area.controls.clear()
        notifications_area.controls.append(ft.Row([ft.ProgressRing(width=16, height=16, stroke_width = 2), ft.Text("Завантаження запитів...")]))
        notifications_area.visible = True
        page.update()

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Завантаження сповіщень для '{current_user}'...")
        api_endpoint = f"{BACKEND_URL}/api/notifications/{current_user}"
        try:
            response = requests.get(api_endpoint, timeout=10)
            notifications_area.controls.clear() # Очистити індикатор

            if 200 <= response.status_code < 300:
                data = response.json()
                pending_requests = data.get("pending_friend_requests", [])

                if pending_requests:
                    notifications_area.controls.append(ft.Text("Запити в друзі:", weight=ft.FontWeight.BOLD))
                    for req in pending_requests:
                        sender = req.get("sender")
                        if not sender: continue # Пропустити, якщо немає відправника
                        # timestamp = req.get("timestamp", "N/A") # Можна додати відображення часу
                        notifications_area.controls.append(
                            ft.Row(
                                [
                                    ft.Icon(ft.icons.PERSON),
                                    ft.Text(f"{sender}", expand=True), # Дозволити тексту розширюватись
                                    ft.IconButton(ft.icons.CHECK, tooltip="Прийняти", on_click=lambda _, s=sender: accept_request_api(s), icon_color=ft.colors.GREEN),
                                    ft.IconButton(ft.icons.CLOSE, tooltip="Відхилити", on_click=lambda _, s=sender: reject_request_api(s), icon_color=ft.colors.RED),
                                ],
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN # Розташувати елементи
                            )
                        )
                else:
                     notifications_area.controls.append(ft.Text("Нових запитів немає."))
                print(f"[API_SUCCESS] Запити завантажено: {len(pending_requests)} знайдено.")

            else:
                 try:
                     error_msg = response.json().get("error", f"Помилка завантаження сповіщень (Код: {response.status_code})")
                 except json.JSONDecodeError:
                      error_msg = f"Помилка завантаження сповіщень (Код: {response.status_code}). Сервер не повернув JSON."
                 notifications_area.controls.append(ft.Text(error_msg, color=ft.colors.RED))
                 print(f"[API_ERROR] Load Notifications: {response.status_code} - {error_msg}")

        except Exception as e:
             notifications_area.controls.clear() # Очистити індикатор
             error_text = f"Помилка мережі або сервера при завантаженні сповіщень: {e}"
             notifications_area.controls.append(ft.Text(error_text, color=ft.colors.RED))
             print(f"[NETWORK_ERROR] Load Notifications: {e}")

        # Додати кнопку закриття/оновлення
        notifications_area.controls.append(
            ft.Row([
                ft.TextButton("Оновити", icon=ft.icons.REFRESH, on_click=lambda e: load_notifications()),
                ft.TextButton("Приховати", on_click=lambda e: toggle_notifications_area(False))
            ], alignment=ft.MainAxisAlignment.SPACE_AROUND)
        )
        page.update()

    def toggle_notifications_area(show: bool | None = None):
         if show is None:
             notifications_area.visible = not notifications_area.visible
         else:
             notifications_area.visible = show

         if notifications_area.visible:
             load_notifications() # Завантажувати при показі
         page.update()


    # --- Кнопки AppBar ---
    notifications_button_appbar = ft.IconButton(
        icon=ft.icons.NOTIFICATIONS_OUTLINED,
        tooltip="Сповіщення / Запити в друзі",
        on_click=lambda e: toggle_notifications_area() # Показувати/ховати область
    )
    logout_button_appbar = ft.IconButton(icon=ft.icons.LOGOUT, tooltip="Вийти", on_click=logout_click)
    appbar = ft.AppBar(
        title=ft.Text("Головна сторінка"),
        bgcolor=ft.colors.SURFACE_VARIANT,
        actions=[notifications_button_appbar, logout_button_appbar]
    )


    # --- Основний контент ---
    main_content_column = ft.Column(
        controls=[
            ft.Container(height=10),
            ft.Text(f"Вітаємо, {username}!", size=22, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
            ft.Divider(height=15),

            # --- Область Сповіщень (Прихована спочатку) ---
            notifications_area,
            ft.Divider(height=10, color=ft.colors.TRANSPARENT), # Невеликий відступ після сповіщень
            # ------------------------------------------

            ft.Text("Пошук друзів:", size=16),
            ft.Row([search_user_field, ft.ElevatedButton("Пошук", icon=ft.icons.SEARCH, on_click=search_user_click)], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            search_result_area, # Результат пошуку та кнопка запиту
            ft.Divider(height=20),
            ft.ElevatedButton("Мої друзі", icon=ft.icons.PEOPLE_OUTLINE, on_click=show_friends_click),
            friends_list_area, # Список друзів
            ft.Divider(height=20),
            ft.Text("Інші секції (приклади):", size=16),
            ft.Container(height=10),
            ft.Card(content=ft.Container(padding=15, content=ft.Row([ft.Icon(ft.icons.INSIGHTS, color=ft.colors.BLUE_700), ft.Text(" Аналітика")], vertical_alignment=ft.CrossAxisAlignment.CENTER))),
            ft.Card(content=ft.Container(padding=15, content=ft.Row([ft.Icon(ft.icons.SETTINGS, color=ft.colors.ORANGE_800), ft.Text(" Налаштування")], vertical_alignment=ft.CrossAxisAlignment.CENTER))),
        ],
        expand=True,
        scroll=ft.ScrollMode.ADAPTIVE # Важливо для прокрутки, коли контенту багато
    )
    main_container = ft.Container(content=main_content_column, padding=ft.padding.symmetric(horizontal=20))

    return appbar, main_container