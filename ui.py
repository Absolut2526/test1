# ui.py
import flet as ft
import database # Імпортуємо наш модуль бази даних
import auth     # Імпортуємо наш модуль автентифікації
import time

# Цей файл містить функції для створення частин UI та їх обробники подій

def create_login_register_view(page: ft.Page, show_logged_in_callback):
    """
    Створює UI для екрану входу/реєстрації та повертає головний елемент (Column).
    Використовує show_logged_in_callback для переходу на головний екран після успіху.
    """
    # --- Елементи керування ---
    reg_username_field = ft.TextField(label="Ім'я користувача (реєстрація)", width=300)
    reg_password_field = ft.TextField(label="Пароль (реєстрація)", password=True, can_reveal_password=True, width=300)
    reg_confirm_password_field = ft.TextField(label="Підтвердіть пароль", password=True, can_reveal_password=True, width=300)
    login_username_field = ft.TextField(label="Ім'я користувача (вхід)", width=300)
    login_password_field = ft.TextField(label="Пароль (вхід)", password=True, can_reveal_password=True, width=300)
    feedback_text = ft.Text(value="", color=ft.colors.RED, text_align=ft.TextAlign.CENTER, width=300)

    # --- Обробники подій (визначені всередині функції, щоб мати доступ до елементів) ---
    def register_click(e):
        username = reg_username_field.value.strip()
        password = reg_password_field.value
        confirm_password = reg_confirm_password_field.value

        feedback_text.value = ""; feedback_text.color = ft.colors.RED

        if not username or not password or not confirm_password:
            feedback_text.value = "Будь ласка, заповніть всі поля реєстрації."
            page.update(); return
        if password != confirm_password:
            feedback_text.value = "Паролі не співпадають."
            reg_password_field.value = ""; reg_confirm_password_field.value = ""
            reg_password_field.focus(); page.update(); return

        # Використовуємо функції з database.py
        if database.check_user_exists(username):
            feedback_text.value = f"Користувач '{username}' вже існує."
        else:
            hashed_pw = auth.hash_password(password) # Використовуємо функцію з auth.py
            if database.add_user(username, hashed_pw):
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' зареєстрований. Збереження сесії.")
                page.client_storage.set(auth.SESSION_KEY, username) # Використовуємо константу з auth.py
                show_logged_in_callback(username) # Викликаємо callback для переходу
                return # Виходимо після успіху
            else:
                 feedback_text.value = "Не вдалося зареєструвати користувача (помилка БД)."

        page.update()

    def login_click(e):
        username = login_username_field.value.strip()
        password = login_password_field.value

        feedback_text.value = ""; feedback_text.color = ft.colors.RED

        if not username or not password:
            feedback_text.value = "Будь ласка, заповніть всі поля для входу."
            page.update(); return

        stored_hash = database.get_user_hash(username) # Використовуємо функцію з database.py

        if stored_hash:
            entered_hash = auth.hash_password(password)
            if stored_hash == entered_hash:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' увійшов. Збереження сесії.")
                page.client_storage.set(auth.SESSION_KEY, username)
                show_logged_in_callback(username) # Викликаємо callback для переходу
                return # Виходимо після успіху
            else:
                feedback_text.value = "Неправильний пароль."
        else:
            feedback_text.value = f"Користувача '{username}' не знайдено."

        page.update()

    # --- Створення UI ---
    register_button = ft.ElevatedButton("Зареєструватися", on_click=register_click, width=300)
    login_button = ft.ElevatedButton("Увійти", on_click=login_click, width=300)
    login_tab_content = ft.Column([login_username_field, login_password_field, login_button], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    register_tab_content = ft.Column([reg_username_field, reg_password_field, reg_confirm_password_field, register_button], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    tabs = ft.Tabs(
        selected_index=0, animation_duration=300,
        tabs=[ft.Tab(text="Реєстрація", content=register_tab_content), ft.Tab(text="Вхід", content=login_tab_content)],
        expand=1)

    # Головний стовпець для цього виду
    view_column = ft.Column(
            [tabs, ft.Container(content=feedback_text, padding=ft.padding.only(top=20))],
            alignment=ft.MainAxisAlignment.START, horizontal_alignment=ft.CrossAxisAlignment.CENTER, expand=True)

    return view_column

def create_logged_in_view(page: ft.Page, username: str, show_login_callback):
    """
    Створює UI для основного екрану програми та повертає кортеж (appbar, main_container).
    Використовує show_login_callback для повернення на екран входу після виходу.
    """
    # --- Елементи керування ---
    search_user_field = ft.TextField(label="Введіть ім'я користувача", expand=True)
    search_result_area = ft.Column(visible=False, spacing=10)

    # --- Обробники подій ---
    def logout_click(e):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' виходить. Видалення сесії.")
        page.client_storage.remove(auth.SESSION_KEY)
        show_login_callback() # Викликаємо callback для повернення на екран входу

    def send_friend_request(target_username):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' імітує надсилання запиту в друзі до: {target_username}")
        search_result_area.controls.clear()
        search_result_area.controls.append(ft.Text(f"Запит користувачу '{target_username}' надіслано (імітація).", color=ft.colors.GREEN))
        # TODO: Додати реальну логіку надсилання/збереження запиту
        page.update()

    def search_user_click(e):
        target_username_query = search_user_field.value.strip()
        current_user = page.client_storage.get(auth.SESSION_KEY) # Отримуємо поточного користувача

        search_result_area.controls.clear()
        search_result_area.visible = True

        if not target_username_query:
            search_result_area.controls.append(ft.Text("Введіть ім'я користувача.", color=ft.colors.ORANGE))
            page.update(); return

        if target_username_query.lower() == current_user.lower(): # Порівняння без урахування регістру
            search_result_area.controls.append(ft.Text("Ви не можете шукати себе."))
            page.update(); return

        # Використовуємо функцію пошуку з database.py
        found_username = database.find_user_by_username(target_username_query)

        if found_username:
            # TODO: Перевірка на вже існуючу дружбу/запит
            search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN), ft.Text(f"Користувача '{found_username}' знайдено.")]))
            search_result_area.controls.append(ft.ElevatedButton(f"Надіслати запит в друзі до '{found_username}'", icon=ft.icons.PERSON_ADD, on_click=lambda _, u=found_username: send_friend_request(u)))
        else:
            search_result_area.controls.append(ft.Row([ft.Icon(ft.icons.CANCEL, color=ft.colors.RED), ft.Text(f"Користувача '{target_username_query}' не знайдено.")]))

        page.update()

    # --- Створення UI ---
    logout_button_appbar = ft.IconButton(icon=ft.icons.LOGOUT, tooltip="Вийти", on_click=logout_click)
    appbar = ft.AppBar(title=ft.Text("Головна сторінка"), bgcolor=ft.colors.SURFACE_VARIANT, actions=[logout_button_appbar])

    main_content_column = ft.Column(
        controls=[
            ft.Container(height=10),
            ft.Text(f"Вітаємо, {username}!", size=22, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
            ft.Divider(height=15),
            ft.Text("Пошук друзів:", size=16),
            ft.Row([search_user_field, ft.ElevatedButton("Пошук", icon=ft.icons.SEARCH, on_click=search_user_click)], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            search_result_area,
            ft.Divider(height=25),
            ft.Text("Інші секції (приклади):", size=16),
            ft.Container(height=10),
            ft.Card(content=ft.Container(padding=15, content=ft.Row([ft.Icon(ft.icons.INSIGHTS, color=ft.colors.BLUE_700), ft.Text(" Аналітика")], vertical_alignment=ft.CrossAxisAlignment.CENTER))),
            ft.Card(content=ft.Container(padding=15, content=ft.Row([ft.Icon(ft.icons.SETTINGS, color=ft.colors.ORANGE_800), ft.Text(" Налаштування")], vertical_alignment=ft.CrossAxisAlignment.CENTER))),
            ft.Card(content=ft.Container(padding=15, content=ft.Row([ft.Icon(ft.icons.PERSON, color=ft.colors.GREEN_700), ft.Text(" Мій профіль")], vertical_alignment=ft.CrossAxisAlignment.CENTER))),
        ],
        expand=True,
        scroll=ft.ScrollMode.ADAPTIVE
    )
    # Обгортаємо основний вміст у контейнер для відступів
    main_container = ft.Container(content=main_content_column, padding=ft.padding.symmetric(horizontal=20))

    return appbar, main_container # Повертаємо AppBar та основний контейнер