# ui.py (Повна версія з виправленням кнопки та вказаним BACKEND_URL)
import flet as ft
import auth # Залишено для SESSION_KEY
import time
import requests # Для API запитів
import json     # Для обробки JSON

# !!! URL БЕКЕНДУ !!!
BACKEND_URL = "http://192.168.196.131:5000"
# Переконайся, що цей IP доступний з пристрою, де запускається Flet-клієнт,
# і що порт 5000 відкритий у фаєрволі сервера.

# --- Функція для показу повідомлень (SnackBar) ---
def show_message(page: ft.Page, message_text, color=ft.colors.BLACK, duration_ms=3000):
    """Показує спливаюче повідомлення внизу екрану."""
    try:
        snack_bar = ft.SnackBar(
            content=ft.Text(message_text, color=ft.colors.WHITE), # Білий текст для контрасту
            bgcolor=color,
            duration=duration_ms,
            open=True
        )
        page.snack_bar = snack_bar
        page.update()
    except Exception as e:
        print(f"[UI_ERR] Помилка показу SnackBar: {e}") # Логування помилки SnackBar

# --- UI для екрану Входу/Реєстрації (ОНОВЛЕНИЙ з API) ---
def create_login_register_view(page: ft.Page, show_logged_in_callback):
    """Створює UI для входу та реєстрації, взаємодіє з API."""
    reg_username_field = ft.TextField(label="Ім'я користувача (реєстрація)", width=300, autofocus=True)
    reg_password_field = ft.TextField(label="Пароль (реєстрація)", password=True, can_reveal_password=True, width=300)
    reg_confirm_password_field = ft.TextField(label="Підтвердіть пароль", password=True, can_reveal_password=True, width=300, on_submit=lambda e: register_click(e)) # Реєстрація по Enter
    login_username_field = ft.TextField(label="Ім'я користувача (вхід)", width=300)
    login_password_field = ft.TextField(label="Пароль (вхід)", password=True, can_reveal_password=True, width=300, on_submit=lambda e: login_click(e)) # Вхід по Enter
    feedback_text = ft.Text(value="", color=ft.colors.RED, text_align=ft.TextAlign.CENTER, width=300)
    loading_indicator = ft.ProgressRing(width=20, height=20, visible=False, tooltip="Завантаження...") # Індикатор завантаження

    # --- Реєстрація через API ---
    def register_click(e):
        username = reg_username_field.value.strip()
        password = reg_password_field.value
        confirm_password = reg_confirm_password_field.value
        feedback_text.value = ""; feedback_text.color = ft.colors.RED
        loading_indicator.visible = False; page.update()

        if not username or not password or not confirm_password:
            feedback_text.value = "Будь ласка, заповніть всі поля реєстрації."; page.update(); return
        if password != confirm_password:
            feedback_text.value = "Паролі не співпадають."; reg_password_field.value = ""; reg_confirm_password_field.value = ""; reg_password_field.focus(); page.update(); return

        loading_indicator.visible = True; page.update()
        api_endpoint = f"{BACKEND_URL}/api/register"
        payload = {"username": username, "password": password}
        headers = {'Content-Type': 'application/json'}

        try:
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)
            loading_indicator.visible = False

            if response.status_code == 201:
                feedback_text.value = "Реєстрація успішна! Тепер ви можете увійти."
                feedback_text.color = ft.colors.GREEN
                reg_username_field.value = ""
                reg_password_field.value = ""
                reg_confirm_password_field.value = ""
                tabs.selected_index = 1
                login_username_field.focus()
            elif response.status_code == 409:
                 feedback_text.value = f"Користувач '{username}' вже існує."
            else:
                 try: error_msg = response.json().get("error", f"Код: {response.status_code}")
                 except json.JSONDecodeError: error_msg = f"Помилка сервера ({response.status_code})."
                 feedback_text.value = f"Помилка реєстрації: {error_msg}"
            page.update()

        except requests.exceptions.ConnectionError: loading_indicator.visible = False; feedback_text.value = "Помилка підключення до сервера."; page.update()
        except requests.exceptions.Timeout: loading_indicator.visible = False; feedback_text.value = "Сервер не відповідає (timeout)."; page.update()
        except requests.exceptions.RequestException as req_err: loading_indicator.visible = False; feedback_text.value = f"Помилка мережі: {req_err}"; page.update()
        except Exception as exc: loading_indicator.visible = False; feedback_text.value = f"Неочікувана помилка: {exc}"; page.update()

    # --- Вхід через API ---
    def login_click(e):
        username_input = login_username_field.value.strip()
        password = login_password_field.value
        feedback_text.value = ""; feedback_text.color = ft.colors.RED
        loading_indicator.visible = False; page.update()

        if not username_input or not password:
            feedback_text.value = "Будь ласка, заповніть всі поля для входу."; page.update(); return

        loading_indicator.visible = True; page.update()
        api_endpoint = f"{BACKEND_URL}/api/login"
        payload = {"username": username_input, "password": password}
        headers = {'Content-Type': 'application/json'}

        try:
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)
            loading_indicator.visible = False

            if response.status_code == 200:
                response_data = response.json()
                actual_username = response_data.get("username")
                if not actual_username:
                     feedback_text.value = "Помилка відповіді сервера."; page.update(); return

                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{actual_username}' увійшов (API). Сесія збережена.")
                page.client_storage.set(auth.SESSION_KEY, actual_username)
                show_logged_in_callback(actual_username); return
            elif response.status_code == 401:
                feedback_text.value = "Неправильне ім'я користувача або пароль."
            else:
                try: error_msg = response.json().get("error", f"Код: {response.status_code}")
                except json.JSONDecodeError: error_msg = f"Помилка сервера ({response.status_code})."
                feedback_text.value = f"Помилка входу: {error_msg}"
            page.update()

        except requests.exceptions.ConnectionError: loading_indicator.visible = False; feedback_text.value = "Помилка підключення до сервера."; page.update()
        except requests.exceptions.Timeout: loading_indicator.visible = False; feedback_text.value = "Сервер не відповідає (timeout)."; page.update()
        except requests.exceptions.RequestException as req_err: loading_indicator.visible = False; feedback_text.value = f"Помилка мережі: {req_err}"; page.update()
        except Exception as exc: loading_indicator.visible = False; feedback_text.value = f"Неочікувана помилка: {exc}"; page.update()

    register_button = ft.ElevatedButton("Зареєструватися", on_click=register_click, width=300, icon=ft.icons.PERSON_ADD_ALT_1)
    login_button = ft.ElevatedButton("Увійти", on_click=login_click, width=300, icon=ft.icons.LOGIN)

    login_tab_content = ft.Column([login_username_field, login_password_field, login_button], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    register_tab_content = ft.Column([reg_username_field, reg_password_field, reg_confirm_password_field, register_button], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    tabs = ft.Tabs(selected_index=1, animation_duration=300, tabs=[ft.Tab(text="Реєстрація", content=register_tab_content), ft.Tab(text="Вхід", content=login_tab_content)], expand=1)

    view_column = ft.Column([
        tabs,
        ft.Row([loading_indicator, ft.Container(content=feedback_text, padding=ft.padding.only(top=5))],
               alignment=ft.MainAxisAlignment.CENTER,
               vertical_alignment=ft.CrossAxisAlignment.CENTER)
    ], alignment=ft.MainAxisAlignment.START, horizontal_alignment=ft.CrossAxisAlignment.CENTER, expand=True)

    return view_column


# --- UI для основного екрану програми ---
def create_logged_in_view(page: ft.Page, username: str, show_login_callback):
    """Створює UI для залогіненого користувача, взаємодіє з API."""
    search_user_field = ft.TextField(label="Знайти користувача за ім'ям", expand=True, hint_text="Введіть ім'я...", on_submit=lambda e: search_user_click(e))
    search_result_area = ft.Column(visible=False, spacing=10, animate_opacity=ft.Animation(300, ft.AnimationCurve.EASE_IN_OUT))
    friends_list_area = ft.Column(visible=False, spacing=5, animate_opacity=ft.Animation(300, ft.AnimationCurve.EASE_IN_OUT))
    notifications_area = ft.Column(visible=False, spacing=5)
    search_loading_indicator = ft.ProgressRing(width=16, height=16, stroke_width = 2, visible=False)
    friends_loading_indicator = ft.ProgressRing(width=16, height=16, stroke_width = 2, visible=False)
    notifications_loading_indicator = ft.ProgressRing(width=16, height=16, stroke_width = 2, visible=False)

    # Ключовий момент: Ref для кнопки надсилання запиту
    send_request_button_ref = ft.Ref[ft.ElevatedButton]()

    def logout_click(e):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' виходить.")
        page.client_storage.remove(auth.SESSION_KEY)
        show_login_callback()

    # --- Надсилання запиту в друзі через API ---
    def send_friend_request_api(target_username):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user: show_message(page, "Помилка сесії.", ft.colors.RED); return

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Надсилання запиту від '{current_user}' до '{target_username}'...")

        # Деактивуємо кнопку ПЕРЕД надсиланням запиту
        button_instance = send_request_button_ref.current
        if button_instance:
            button_instance.disabled = True
            button_instance.text = "Надсилання..."
            page.update() # Оновлюємо UI, щоб показати зміни кнопки
        else:
            # Якщо з якоїсь причини Ref не спрацював, просто повідомляємо
            show_message(page, f"Надсилаємо запит до {target_username}...", ft.colors.BLUE)

        api_endpoint = f"{BACKEND_URL}/api/friend_request"
        payload = {"sender_username": current_user, "recipient_username": target_username}
        headers = {'Content-Type': 'application/json'}

        try:
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)

            # Обробка відповіді
            button_instance = send_request_button_ref.current # Отримуємо посилання знову

            if 201 <= response.status_code < 300: # Успіх
                 response_data = response.json()
                 message = response_data.get("message", "Запит оброблено.")
                 show_message(page, message, ft.colors.GREEN)
                 print(f"[API_SUCCESS] Friend Request {response.status_code}: {message}")
                 # Змінюємо кнопку остаточно
                 if button_instance:
                     button_instance.text = "Запит надіслано"
                     button_instance.icon = ft.icons.CHECK
                     button_instance.disabled = True # Залишаємо деактивованою
            else: # Помилка API
                 try:
                     response_data = response.json()
                     error_message = response_data.get("error", f"Код: {response.status_code}")
                 except json.JSONDecodeError:
                     error_message = f"Помилка сервера ({response.status_code})."
                 show_message(page, f"Не вдалося надіслати запит: {error_message}", ft.colors.RED)
                 print(f"[API_ERROR] Friend Request {response.status_code}: {error_message}")
                 # Повертаємо кнопку до активного стану
                 if button_instance:
                     button_instance.disabled = False
                     # Відновлюємо текст кнопки, використовуючи збережене ім'я користувача
                     # (target_username передано в функцію як аргумент)
                     button_instance.text = f"Надіслати запит '{target_username}'"
                     button_instance.icon = ft.icons.PERSON_ADD # Повертаємо іконку

        except requests.exceptions.RequestException as req_err:
             error_texts = { requests.exceptions.ConnectionError: "Помилка підключення.", requests.exceptions.Timeout: "Timeout." }
             error_text = error_texts.get(type(req_err), f"Помилка мережі: {req_err}")
             show_message(page, error_text, ft.colors.RED)
             # Повертаємо кнопку до активного стану
             button_instance = send_request_button_ref.current
             if button_instance:
                 button_instance.disabled = False
                 button_instance.text = f"Надіслати запит '{target_username}'"
                 button_instance.icon = ft.icons.PERSON_ADD
        except Exception as e:
             show_message(page, f"Неочікувана помилка: {e}", ft.colors.RED)
             # Повертаємо кнопку до активного стану
             button_instance = send_request_button_ref.current
             if button_instance:
                 button_instance.disabled = False
                 button_instance.text = f"Надіслати запит '{target_username}'"
                 button_instance.icon = ft.icons.PERSON_ADD

        # Важливо оновити сторінку після всіх маніпуляцій з кнопкою
        page.update()


    # --- Пошук користувача через API ---
    def search_user_click(e):
        target_username_query = search_user_field.value.strip()
        current_user = page.client_storage.get(auth.SESSION_KEY)
        search_result_area.controls.clear(); search_result_area.visible = True
        search_loading_indicator.visible = True; page.update()

        # Скидаємо посилання на кнопку при кожному новому пошуку
        send_request_button_ref.current = None

        if not target_username_query:
             search_loading_indicator.visible = False
             search_result_area.controls.append(ft.Text("Введіть ім'я для пошуку.", color=ft.colors.ORANGE))
             page.update(); return
        if target_username_query.lower() == current_user.lower():
             search_loading_indicator.visible = False
             search_result_area.controls.append(ft.Text("Ви не можете шукати себе."))
             page.update(); return

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Пошук '{target_username_query}' через API...")
        api_endpoint = f"{BACKEND_URL}/api/search_user"
        params = {"query": target_username_query}

        try:
             response = requests.get(api_endpoint, params=params, timeout=10)
             search_loading_indicator.visible = False

             if response.status_code == 200:
                 response_data = response.json()
                 found_username = response_data.get("username")
                 search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN), ft.Text(f"Знайдено: '{found_username}'")]))

                 # Створюємо кнопку з Ref
                 send_button = ft.ElevatedButton(
                         ref=send_request_button_ref, # Прив'язуємо Ref
                         text=f"Надіслати запит '{found_username}'",
                         icon=ft.icons.PERSON_ADD,
                         on_click=lambda _, u=found_username: send_friend_request_api(u)
                     )
                 search_result_area.controls.append(send_button)

             elif response.status_code == 404:
                 search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.CANCEL, color=ft.colors.RED), ft.Text(f"Користувача '{target_username_query}' не знайдено.")]))
             else:
                 try: error_msg = response.json().get("error", f"Код: {response.status_code}")
                 except json.JSONDecodeError: error_msg = f"Помилка сервера ({response.status_code})."
                 search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.ERROR, color=ft.colors.RED), ft.Text(f"Помилка пошуку: {error_msg}", color=ft.colors.RED)]))

        except requests.exceptions.ConnectionError: search_loading_indicator.visible = False; search_result_area.controls.append(ft.Text("Помилка підключення.", color=ft.colors.RED))
        except requests.exceptions.Timeout: search_loading_indicator.visible = False; search_result_area.controls.append(ft.Text("Timeout.", color=ft.colors.RED))
        except requests.exceptions.RequestException as req_err: search_loading_indicator.visible = False; search_result_area.controls.append(ft.Text(f"Помилка мережі: {req_err}", color=ft.colors.RED))
        except Exception as e: search_loading_indicator.visible = False; search_result_area.controls.append(ft.Text(f"Помилка: {e}", color=ft.colors.RED))

        page.update()

    # --- Отримання списку друзів через API ---
    def show_friends_click(e):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user: return
        friends_list_area.controls.clear(); friends_list_area.visible = True
        friends_loading_indicator.visible = True; page.update()

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Завантаження друзів для '{current_user}'...")
        api_endpoint = f"{BACKEND_URL}/api/friends/{current_user}"

        try:
            response = requests.get(api_endpoint, timeout=10)
            friends_loading_indicator.visible = False

            if response.status_code == 200:
                 response_data = response.json()
                 friends = response_data.get("friends", [])
                 if friends:
                     friends_list_area.controls.append(ft.Text("Список друзів:", weight=ft.FontWeight.BOLD))
                     lv = ft.ListView(spacing=5, auto_scroll=True, expand=False, height=150)
                     for friend in friends:
                         friend_row = ft.Row(
                             [
                                 ft.Icon(ft.icons.PERSON_OUTLINE),
                                 ft.Text(friend, expand=True),
                                 ft.IconButton(
                                     ft.icons.PERSON_REMOVE_OUTLINED,
                                     tooltip=f"Видалити {friend}",
                                     on_click=lambda _, f=friend: remove_friend_api(f),
                                     icon_color=ft.colors.RED_400,
                                     data=friend
                                 )
                             ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                         )
                         lv.controls.append(friend_row)
                     friends_list_area.controls.append(lv)
                     print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Друзі завантажені: {len(friends)}")
                 else:
                     friends_list_area.controls.append(ft.Text("У вас немає друзів."))
                     print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Друзів не знайдено (API).")
            elif response.status_code == 404:
                 friends_list_area.controls.append(ft.Text("Помилка: користувач не знайдений.", color=ft.colors.RED))
            else:
                 try: error_msg = response.json().get("error", f"Код: {response.status_code}")
                 except json.JSONDecodeError: error_msg = f"Помилка сервера ({response.status_code})."
                 friends_list_area.controls.append(ft.Text(f"Помилка завантаження друзів: {error_msg}", color=ft.colors.RED))

        except requests.exceptions.ConnectionError: friends_loading_indicator.visible = False; friends_list_area.controls.append(ft.Text("Помилка підключення.", color=ft.colors.RED))
        except requests.exceptions.Timeout: friends_loading_indicator.visible = False; friends_list_area.controls.append(ft.Text("Timeout.", color=ft.colors.RED))
        except requests.exceptions.RequestException as req_err: friends_loading_indicator.visible = False; friends_list_area.controls.append(ft.Text(f"Помилка мережі: {req_err}", color=ft.colors.RED))
        except Exception as e: friends_loading_indicator.visible = False; friends_list_area.controls.append(ft.Text(f"Помилка: {e}", color=ft.colors.RED))

        friends_list_area.controls.append(ft.TextButton("Приховати список", on_click=hide_friends_list))
        page.update()

    def hide_friends_list(e):
        friends_list_area.visible = False
        page.update()

    # --- Прийняття запиту через API ---
    def accept_request_api(sender_username):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user: show_message(page, "Помилка сесії.", ft.colors.RED); return
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Прийняття запиту від '{sender_username}'...")
        show_message(page, f"Приймаємо запит від {sender_username}...", ft.colors.BLUE)

        api_endpoint = f"{BACKEND_URL}/api/friend_request/accept"
        payload = {"sender_username": sender_username, "recipient_username": current_user}
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)
            if 200 <= response.status_code < 300:
                show_message(page, f"Ви тепер друзі з {sender_username}!", ft.colors.GREEN)
                load_notifications()
                if friends_list_area.visible: show_friends_click(None)
            else:
                try: error_msg = response.json().get("error", f"Код: {response.status_code}")
                except json.JSONDecodeError: error_msg = f"Код: {response.status_code}"
                show_message(page, f"Помилка прийняття: {error_msg}", ft.colors.RED)
                print(f"[API_ERROR] Accept Request: {response.status_code} - {error_msg}")
        except Exception as e:
            show_message(page, f"Помилка мережі/сервера.", ft.colors.RED)
            print(f"[NETWORK_ERROR] Accept Request: {e}")

    # --- Відхилення запиту через API ---
    def reject_request_api(sender_username):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user: show_message(page, "Помилка сесії.", ft.colors.RED); return
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Відхилення запиту від '{sender_username}'...")
        show_message(page, f"Відхиляємо запит від {sender_username}...", ft.colors.BLUE)

        api_endpoint = f"{BACKEND_URL}/api/friend_request/reject"
        payload = {"sender_username": sender_username, "recipient_username": current_user}
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)
            if 200 <= response.status_code < 300:
                show_message(page, f"Запит від {sender_username} відхилено.", ft.colors.ORANGE)
                load_notifications()
            else:
                try: error_msg = response.json().get("error", f"Код: {response.status_code}")
                except json.JSONDecodeError: error_msg = f"Код: {response.status_code}"
                show_message(page, f"Помилка відхилення: {error_msg}", ft.colors.RED)
                print(f"[API_ERROR] Reject Request: {response.status_code} - {error_msg}")
        except Exception as e:
            show_message(page, f"Помилка мережі/сервера.", ft.colors.RED)
            print(f"[NETWORK_ERROR] Reject Request: {e}")

    # --- Видалення друга через API ---
    def remove_friend_api(friend_to_remove):
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user: show_message(page, "Помилка сесії.", ft.colors.RED); return
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Видалення друга '{friend_to_remove}'...")
        show_message(page, f"Видаляємо {friend_to_remove}...", ft.colors.BLUE)

        api_endpoint = f"{BACKEND_URL}/api/friendship/remove"
        payload = {"user_a": current_user, "user_b": friend_to_remove}
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10)
            if 200 <= response.status_code < 300:
                try: message = response.json().get("message", f"Друга видалено.")
                except json.JSONDecodeError: message = f"Друга видалено."
                show_message(page, message, ft.colors.GREEN)
                if friends_list_area.visible: show_friends_click(None)
            else:
                try: error_msg = response.json().get("error", f"Код: {response.status_code}")
                except json.JSONDecodeError: error_msg = f"Код: {response.status_code}"
                show_message(page, f"Помилка видалення: {error_msg}", ft.colors.RED)
                print(f"[API_ERROR] Remove Friend: {response.status_code} - {error_msg}")
        except Exception as e:
            show_message(page, f"Помилка мережі/сервера.", ft.colors.RED)
            print(f"[NETWORK_ERROR] Remove Friend: {e}")

    # --- Завантаження сповіщень (запитів в друзі) через API ---
    def load_notifications():
        current_user = page.client_storage.get(auth.SESSION_KEY)
        if not current_user:
             notifications_area.controls.clear(); notifications_area.controls.append(ft.Text("Помилка сесії.", color=ft.colors.RED)); notifications_area.visible = True; page.update(); return

        notifications_area.controls.clear()
        notifications_loading_indicator.visible = True
        notifications_area.controls.append(ft.Row([notifications_loading_indicator, ft.Text("Оновлення запитів...")]))
        notifications_area.visible = True
        page.update()

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UI: Завантаження сповіщень для '{current_user}'...")
        api_endpoint = f"{BACKEND_URL}/api/notifications/{current_user}"
        try:
            response = requests.get(api_endpoint, timeout=10)
            notifications_loading_indicator.visible = False
            notifications_area.controls.clear()

            if 200 <= response.status_code < 300:
                data = response.json()
                pending_requests = data.get("pending_friend_requests", [])
                if pending_requests:
                    notifications_area.controls.append(ft.Text("Очікуючі запити:", weight=ft.FontWeight.BOLD))
                    lv_notify = ft.ListView(spacing=5, auto_scroll=True, expand=False, height=150)
                    for req in pending_requests:
                        sender = req.get("sender")
                        if not sender: continue
                        lv_notify.controls.append(
                            ft.Row(
                                [
                                    ft.Icon(ft.icons.PERSON_ADD_ALT),
                                    ft.Text(f"{sender}", expand=True),
                                    ft.IconButton(ft.icons.CHECK_CIRCLE_OUTLINE, tooltip="Прийняти", on_click=lambda _, s=sender: accept_request_api(s), icon_color=ft.colors.GREEN_700),
                                    ft.IconButton(ft.icons.CANCEL_OUTLINED, tooltip="Відхилити", on_click=lambda _, s=sender: reject_request_api(s), icon_color=ft.colors.RED_700),
                                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN
                            )
                        )
                    notifications_area.controls.append(lv_notify)
                else:
                     notifications_area.controls.append(ft.Text("Нових запитів немає."))
                print(f"[API_SUCCESS] Сповіщення завантажено: {len(pending_requests)} знайдено.")
            else:
                 try: error_msg = response.json().get("error", f"Код: {response.status_code}")
                 except json.JSONDecodeError: error_msg = f"Код: {response.status_code}"
                 notifications_area.controls.append(ft.Text(f"Помилка завантаження сповіщень: {error_msg}", color=ft.colors.RED))
                 print(f"[API_ERROR] Load Notifications: {response.status_code} - {error_msg}")

        except requests.exceptions.ConnectionError: notifications_loading_indicator.visible = False; notifications_area.controls.clear(); notifications_area.controls.append(ft.Text("Помилка підключення.", color=ft.colors.RED))
        except requests.exceptions.Timeout: notifications_loading_indicator.visible = False; notifications_area.controls.clear(); notifications_area.controls.append(ft.Text("Timeout.", color=ft.colors.RED))
        except Exception as e:
             notifications_loading_indicator.visible = False; notifications_area.controls.clear()
             error_text = f"Помилка завантаження сповіщень: {e}"
             notifications_area.controls.append(ft.Text(error_text, color=ft.colors.RED))
             print(f"[NETWORK_ERROR] Load Notifications: {e}")

        notifications_area.controls.append(
            ft.Row([
                ft.TextButton("Оновити", icon=ft.icons.REFRESH, on_click=lambda e: load_notifications()),
                ft.TextButton("Приховати", on_click=lambda e: toggle_notifications_area(False))
            ], alignment=ft.MainAxisAlignment.SPACE_AROUND)
        )
        page.update()

    def toggle_notifications_area(show: bool | None = None):
         """Показує або приховує область сповіщень."""
         if show is None:
             notifications_area.visible = not notifications_area.visible
         else:
             notifications_area.visible = show
         if notifications_area.visible:
             load_notifications()
         page.update()

    # --- Кнопки AppBar ---
    notifications_button_appbar = ft.IconButton(
        icon=ft.icons.NOTIFICATIONS_OUTLINED,
        tooltip="Сповіщення / Запити в друзі",
        on_click=lambda e: toggle_notifications_area()
    )
    logout_button_appbar = ft.IconButton(icon=ft.icons.LOGOUT, tooltip="Вийти", on_click=logout_click)
    appbar = ft.AppBar(
        title=ft.Text("Головна сторінка"),
        bgcolor=ft.colors.SURFACE_VARIANT,
        actions=[notifications_button_appbar, logout_button_appbar]
    )

    # --- Основний контент сторінки ---
    main_content_column = ft.Column(
        controls=[
            ft.Container(height=10),
            ft.Text(f"Вітаємо, {username}!", size=22, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
            ft.Divider(height=15),
            notifications_area,
            ft.Divider(height=10, color=ft.colors.TRANSPARENT),
            ft.Text("Пошук друзів:", size=16),
            ft.Row([search_user_field,
                    search_loading_indicator,
                    ft.ElevatedButton("Знайти", icon=ft.icons.SEARCH, on_click=search_user_click)],
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            search_result_area,
            ft.Divider(height=20),
            ft.Row([
                ft.ElevatedButton("Мої друзі", icon=ft.icons.PEOPLE_OUTLINE, on_click=show_friends_click),
                friends_loading_indicator
            ]),
            friends_list_area,
        ],
        expand=True,
        scroll=ft.ScrollMode.ADAPTIVE
    )
    main_container = ft.Container(content=main_content_column, padding=ft.padding.symmetric(horizontal=20))

    return appbar, main_container