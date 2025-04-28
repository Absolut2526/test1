import flet as ft
import sqlite3
import hashlib
import os
import time # Для логування часу

# --- Глобальні константи ---
# Шлях до файлу бази даних (у тій же папці, що і скрипт)
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'users.db'))
# Ключ для зберігання імені користувача в сховищі клієнта (для сесії)
SESSION_KEY = "logged_in_user"
print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Шлях до БД: {db_path}")

# --- Головна функція програми Flet ---

def main(page: ft.Page):
    """
    Основна функція, яка визначає інтерфейс користувача та ВСЮ логіку програми,
    включаючи допоміжні функції, обробники подій та перемикання видів.
    """

    # --- Допоміжні функції, визначені всередині main ---

    def setup_database():
        """
        Створює файл БД та таблицю 'users', якщо вони ще не існують.
        Викликається один раз при старті програми.
        Використовує 'try...finally' для гарантованого закриття з'єднання.
        (Визначено всередині main)
        """
        conn = None # Ініціалізуємо змінну з'єднання
        try:
            # З'єднуємось з БД (файл буде створено, якщо його немає)
            conn = sqlite3.connect(db_path) # db_path - глобальна константа
            cursor = conn.cursor()
            # Виконуємо запит SQL для створення таблиці
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )
            ''')
            conn.commit()
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Перевірка/створення таблиці 'users' виконано.")
        except sqlite3.Error as e:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка під час початкового налаштування БД: {e}")
        finally:
            if conn:
                conn.close()

    def hash_password(password):
        """
        Хешує наданий пароль за допомогою алгоритму SHA-256.
        Повертає хеш у вигляді шістнадцяткового рядка.
        (Визначено всередині main)
        """
        password_bytes = password.encode('utf-8')
        sha256_hash = hashlib.sha256(password_bytes)
        hashed_password = sha256_hash.hexdigest()
        return hashed_password

    # --- Налаштування сторінки ---
    page.title = "Програма з Логіном (Все в Main)"
    page.window_width = 500
    page.window_height = 750
    # Вирівнювання буде встановлюватися динамічно

    # --- Виклик функції налаштування БД (визначеної вище всередині main) ---
    setup_database()

    # --- Визначення елементів керування (доступні всередині main та вкладених функцій) ---
    reg_username_field = ft.TextField(label="Ім'я користувача (реєстрація)", width=300, tooltip="Введіть бажане ім'я користувача")
    reg_password_field = ft.TextField(label="Пароль (реєстрація)", password=True, can_reveal_password=True, width=300, tooltip="Введіть надійний пароль")
    reg_confirm_password_field = ft.TextField(label="Підтвердіть пароль", password=True, can_reveal_password=True, width=300, tooltip="Введіть пароль ще раз для перевірки")
    login_username_field = ft.TextField(label="Ім'я користувача (вхід)", width=300, tooltip="Введіть ваше ім'я користувача")
    login_password_field = ft.TextField(label="Пароль (вхід)", password=True, can_reveal_password=True, width=300, tooltip="Введіть ваш пароль")
    feedback_text = ft.Text(value="", color=ft.colors.RED, text_align=ft.TextAlign.CENTER, width=300)
    search_user_field = ft.TextField(label="Введіть ім'я користувача", expand=True)
    search_result_area = ft.Column(visible=False, spacing=10) # Спочатку невидима

    # --- Вкладені функції для перемикання видів ---

    def show_logged_in_view(username):
        """
        Очищає сторінку та відображає основний інтерфейс програми.
        (Визначено всередині main)
        """
        page.clean()
        page.vertical_alignment = ft.MainAxisAlignment.START
        page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH

        logout_button_appbar = ft.IconButton(
            icon=ft.icons.LOGOUT, tooltip="Вийти", on_click=logout_click)

        page.appbar = ft.AppBar(
            title=ft.Text("Головна сторінка"),
            bgcolor=ft.colors.SURFACE_VARIANT,
            actions=[logout_button_appbar]
        )

        main_content = ft.Column(
            controls=[
                ft.Container(height=10),
                ft.Text(f"Вітаємо, {username}!", size=22, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
                ft.Divider(height=15),
                ft.Text("Пошук друзів:", size=16),
                ft.Row(
                    controls=[
                        search_user_field, # Використовуємо змінну з області видимості main
                        ft.ElevatedButton("Пошук", icon=ft.icons.SEARCH, on_click=search_user_click) # Виклик іншої вкладеної функції
                    ],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER
                ),
                search_result_area, # Використовуємо змінну з області видимості main
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
        page.add(ft.Container(content=main_content, padding=ft.padding.symmetric(horizontal=20)))
        page.update()

    def show_login_register_view():
        """
        Очищає сторінку, прибирає AppBar та показує екран входу/реєстрації.
        (Визначено всередині main)
        """
        page.clean()
        page.appbar = None
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        feedback_text.value = ""
        search_result_area.visible = False # Приховуємо результати пошуку
        search_result_area.controls.clear()
        # Додаємо login_register_column (визначений нижче в main)
        page.add(login_register_column)
        page.update()

    # --- Вкладені функції-обробники подій ---

    def logout_click(e):
        """Обробник натискання кнопки 'Вийти'."""
        current_user = page.client_storage.get(SESSION_KEY)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{current_user}' виходить. Видалення сесії.")
        page.client_storage.remove(SESSION_KEY)
        show_login_register_view() # Виклик іншої вкладеної функції

    # Функція-заглушка для кнопки "Надіслати запит"
    def send_friend_request(target_username):
        """Імітує надсилання запиту в друзі."""
        current_user = page.client_storage.get(SESSION_KEY)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{current_user}' імітує надсилання запиту в друзі до: {target_username}")
        search_result_area.controls.clear()
        search_result_area.controls.append(
            ft.Text(f"Запит користувачу '{target_username}' надіслано (імітація).", color=ft.colors.GREEN)
        )
        page.update()

    # Обробник кнопки пошуку користувача
    def search_user_click(e):
        """Обробляє пошук користувача в БД."""
        target_username = search_user_field.value.strip()
        current_user = page.client_storage.get(SESSION_KEY)

        search_result_area.controls.clear()
        search_result_area.visible = True
        search_result_area.update()

        if not target_username:
            search_result_area.controls.append(ft.Text("Будь ласка, введіть ім'я користувача для пошуку.", color=ft.colors.ORANGE))
            page.update(); return

        if target_username == current_user:
            search_result_area.controls.append(ft.Text("Ви не можете шукати або додати себе в друзі."))
            page.update(); return

        conn_search = None
        try:
            conn_search = sqlite3.connect(db_path) # db_path - глобальна
            cursor_search = conn_search.cursor()
            # Використовуємо параметризований запит
            cursor_search.execute("SELECT username FROM users WHERE username=? COLLATE NOCASE", (target_username,))
            result = cursor_search.fetchone()

            if result:
                found_username = result[0]
                search_result_area.controls.append(
                    ft.Row([ ft.Icon(ft.icons.CHECK_CIRCLE, color=ft.colors.GREEN), ft.Text(f"Користувача '{found_username}' знайдено.")], alignment=ft.MainAxisAlignment.START)
                )
                search_result_area.controls.append(
                    ft.ElevatedButton(
                        f"Надіслати запит в друзі до '{found_username}'",
                        icon=ft.icons.PERSON_ADD,
                        on_click=lambda _, u=found_username: send_friend_request(u) # Виклик іншої вкладеної функції
                    )
                )
            else:
                search_result_area.controls.append(
                     ft.Row([ ft.Icon(ft.icons.CANCEL, color=ft.colors.RED), ft.Text(f"Користувача '{target_username}' не знайдено.")], alignment=ft.MainAxisAlignment.START)
                )
        except sqlite3.Error as db_err:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при пошуку користувача: {db_err}")
            search_result_area.controls.append(ft.Text(f"Помилка бази даних при пошуку: {db_err}", color=ft.colors.RED))
        except Exception as ex:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Невідома помилка при пошуку користувача: {ex}")
            search_result_area.controls.append(ft.Text(f"Сталася невідома помилка: {ex}", color=ft.colors.RED))
        finally:
            if conn_search:
                conn_search.close()
        page.update()

    def register_click(e):
        """Обробник натискання кнопки 'Зареєструватися'."""
        username = reg_username_field.value.strip()
        password = reg_password_field.value
        confirm_password = reg_confirm_password_field.value
        feedback_text.value = ""
        feedback_text.color = ft.colors.RED
        if not username or not password or not confirm_password:
            feedback_text.value = "Будь ласка, заповніть всі поля реєстрації."
            page.update(); return
        if password != confirm_password:
            feedback_text.value = "Паролі не співпадають."
            reg_password_field.value = ""; reg_confirm_password_field.value = ""
            reg_password_field.focus(); page.update(); return
        conn_reg = None
        try:
            conn_reg = sqlite3.connect(db_path)
            cursor_reg = conn_reg.cursor()
            cursor_reg.execute("SELECT username FROM users WHERE username=?", (username,))
            if cursor_reg.fetchone():
                feedback_text.value = f"Користувач '{username}' вже існує."
            else:
                hashed_pw = hash_password(password) # Виклик вкладеної функції hash_password
                cursor_reg.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pw))
                conn_reg.commit()
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' зареєстрований. Збереження сесії.")
                page.client_storage.set(SESSION_KEY, username) # SESSION_KEY - глобальна
                show_logged_in_view(username) # Виклик вкладеної функції
                return
        except sqlite3.Error as db_err:
            feedback_text.value = f"Помилка бази даних: {db_err}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при реєстрації: {db_err}")
        except Exception as ex:
            feedback_text.value = f"Сталася невідома помилка: {ex}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Невідома помилка при реєстрації: {ex}")
        finally:
            if conn_reg: conn_reg.close()
        page.update()

    def login_click(e):
        """Обробник натискання кнопки 'Увійти'."""
        username = login_username_field.value.strip()
        password = login_password_field.value
        feedback_text.value = ""
        feedback_text.color = ft.colors.RED
        if not username or not password:
            feedback_text.value = "Будь ласка, заповніть всі поля для входу."
            page.update(); return
        conn_log = None
        try:
            conn_log = sqlite3.connect(db_path)
            cursor_log = conn_log.cursor()
            cursor_log.execute("SELECT password_hash FROM users WHERE username=?", (username,))
            result = cursor_log.fetchone()
            if result:
                stored_hash = result[0]
                entered_hash = hash_password(password) # Виклик вкладеної функції hash_password
                if stored_hash == entered_hash:
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' увійшов. Збереження сесії.")
                    page.client_storage.set(SESSION_KEY, username) # SESSION_KEY - глобальна
                    show_logged_in_view(username) # Виклик вкладеної функції
                    return
                else:
                    feedback_text.value = "Неправильний пароль."
            else:
                feedback_text.value = f"Користувача '{username}' не знайдено."
        except sqlite3.Error as db_err:
            feedback_text.value = f"Помилка бази даних: {db_err}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при вході: {db_err}")
        except Exception as ex:
            feedback_text.value = f"Сталася невідома помилка: {ex}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Невідома помилка при вході: {ex}")
        finally:
            if conn_log: conn_log.close()
        page.update()

    # --- Створення UI для екрану входу/реєстрації (виконується один раз в main) ---
    register_button = ft.ElevatedButton("Зареєструватися", on_click=register_click, width=300, tooltip="Створити новий обліковий запис")
    login_button = ft.ElevatedButton("Увійти", on_click=login_click, width=300, tooltip="Увійти з існуючим обліковим записом")
    login_tab_content = ft.Column([login_username_field, login_password_field, login_button], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    register_tab_content = ft.Column([reg_username_field, reg_password_field, reg_confirm_password_field, register_button], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=20)
    tabs = ft.Tabs(
        selected_index=0, animation_duration=300,
        tabs=[ft.Tab(text="Реєстрація", content=register_tab_content), ft.Tab(text="Вхід", content=login_tab_content)],
        expand=1)
    # Ця змінна тепер локальна для main, але доступна вкладеним функціям (show_login_register_view)
    login_register_column = ft.Column(
            [tabs, ft.Container(content=feedback_text, padding=ft.padding.only(top=20))],
            alignment=ft.MainAxisAlignment.START, horizontal_alignment=ft.CrossAxisAlignment.CENTER, expand=True)

    # --- Початкове відображення інтерфейсу при запуску ---
    # Перевіряємо наявність збереженої сесії в сховищі клієнта
    logged_in_user = page.client_storage.get(SESSION_KEY) # SESSION_KEY - глобальна
    if logged_in_user:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Знайдено збережену сесію для: {logged_in_user}. Показ основного інтерфейсу.")
        show_logged_in_view(logged_in_user) # Виклик вкладеної функції
    else:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Збережена сесія не знайдена. Показ екрану входу/реєстрації.")
        show_login_register_view() # Виклик вкладеної функції


# --- Точка входу для запуску програми ---
if __name__ == "__main__":
    # Запускаємо Flet додаток, вказуючи головну функцію 'main'
    ft.app(target=main)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Роботу програми завершено.")