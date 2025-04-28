import flet as ft
import sqlite3
import hashlib
import os
import time # Для логування часу

# --- Глобальні налаштування та шляхи ---

# Шлях до файлу бази даних (у тій же папці, що і скрипт)
# Використання __file__ робить шлях відносним до розташування скрипта
# os.path.abspath потрібен для надійності, особливо якщо скрипт запускається з іншого місця
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'users.db'))

# Ключ для зберігання імені користувача в сховищі клієнта (для сесії)
SESSION_KEY = "logged_in_user"
print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Шлях до БД: {db_path}")

# --- Функції роботи з базою даних та паролями ---

def setup_database():
    """
    Створює файл БД та таблицю 'users', якщо вони ще не існують.
    Ця функція викликається один раз при старті програми.
    Використовує 'try...finally' для гарантованого закриття з'єднання.
    """
    conn = None # Ініціалізуємо змінну з'єднання
    try:
        # З'єднуємось з БД (файл буде створено, якщо його немає)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Виконуємо запит SQL для створення таблиці
        # IF NOT EXISTS запобігає помилці, якщо таблиця вже створена
        # PRIMARY KEY на username забезпечує унікальність імен користувачів
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        # Зберігаємо зміни в БД
        conn.commit()
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Перевірка/створення таблиці 'users' виконано.")
    except sqlite3.Error as e:
        # Обробляємо можливі помилки SQLite під час налаштування
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка під час початкового налаштування БД: {e}")
    finally:
        # Гарантовано закриваємо з'єднання, якщо воно було відкрито
        if conn:
            conn.close()

def hash_password(password):
    """
    Хешує наданий пароль за допомогою алгоритму SHA-256.
    Повертає хеш у вигляді шістнадцяткового рядка.
    """
    # Пароль потрібно спершу закодувати в байти (utf-8 є стандартом)
    password_bytes = password.encode('utf-8')
    # Створюємо об'єкт хешу SHA-256
    sha256_hash = hashlib.sha256(password_bytes)
    # Отримуємо хеш у вигляді шістнадцяткового рядка
    hashed_password = sha256_hash.hexdigest()
    return hashed_password

# --- Головна функція програми Flet ---

def main(page: ft.Page):
    """
    Основна функція, яка визначає інтерфейс користувача та логіку програми.
    """
    # --- Налаштування сторінки ---
    page.title = "Програма з Логіном"
    page.window_width = 500
    page.window_height = 700
    # Вирівнювання буде встановлюватися динамічно залежно від стану (логін/вхід)

    # --- Виклик функції налаштування БД при старті ---
    setup_database()

    # --- Визначення елементів керування для форм входу/реєстрації ---
    reg_username_field = ft.TextField(
        label="Ім'я користувача (реєстрація)",
        width=300,
        tooltip="Введіть бажане ім'я користувача"
    )
    reg_password_field = ft.TextField(
        label="Пароль (реєстрація)",
        password=True,
        can_reveal_password=True,
        width=300,
        tooltip="Введіть надійний пароль"
    )
    reg_confirm_password_field = ft.TextField(
        label="Підтвердіть пароль",
        password=True,
        can_reveal_password=True,
        width=300,
        tooltip="Введіть пароль ще раз для перевірки"
    )
    login_username_field = ft.TextField(
        label="Ім'я користувача (вхід)",
        width=300,
        tooltip="Введіть ваше ім'я користувача"
    )
    login_password_field = ft.TextField(
        label="Пароль (вхід)",
        password=True,
        can_reveal_password=True,
        width=300,
        tooltip="Введіть ваш пароль"
    )
    # Текстове поле для виведення повідомлень про помилки
    feedback_text = ft.Text(
        value="",
        color=ft.colors.RED,
        text_align=ft.TextAlign.CENTER,
        width=300
    )

    # --- Функції для перемикання між видами (сценами) ---

    def show_logged_in_view(username):
        """
        Очищає сторінку та відображає основний інтерфейс програми для залогіненого користувача.
        Встановлює AppBar та основний контент.
        """
        page.clean() # Очищаємо попередній вміст
        page.vertical_alignment = ft.MainAxisAlignment.START # Вирівнюємо вміст зверху
        page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH # Розтягуємо по ширині

        # Створюємо кнопку "Вийти" (іконка) для AppBar
        logout_button_appbar = ft.IconButton(
            icon=ft.icons.LOGOUT,
            tooltip="Вийти з облікового запису",
            on_click=logout_click # Обробник натискання
        )

        # Створюємо та встановлюємо AppBar для сторінки
        page.appbar = ft.AppBar(
            title=ft.Text("Головна сторінка"), # Заголовок панелі
            bgcolor=ft.colors.SURFACE_VARIANT, # Колір фону панелі
            actions=[logout_button_appbar] # Додаємо кнопку виходу до дій у AppBar
        )

        # Створюємо основний вміст сторінки (панель інструментів)
        main_content = ft.Column(
            controls=[
                ft.Container(height=10), # Невеликий відступ зверху
                ft.Text(f"Вітаємо, {username}!", size=22, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
                ft.Divider(height=20), # Розділювач з відступами
                ft.Text("Ваша панель інструментів:", size=16),
                ft.Container(height=15),

                # Приклади секцій або функцій у вигляді карток (placeholders)
                ft.Card(
                    content=ft.Container(
                        padding=15,
                        content=ft.Row( # Використовуємо Row для іконки та тексту поруч
                            controls=[
                                ft.Icon(ft.icons.INSIGHTS, color=ft.colors.BLUE_700), # Іконка
                                ft.Text(" Аналітика (приклад)") # Текст
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER # Вирівнюємо по вертикалі
                        )
                    )
                ),
                ft.Card(
                     content=ft.Container(
                        padding=15,
                        content=ft.Row(
                            controls=[
                                ft.Icon(ft.icons.SETTINGS, color=ft.colors.ORANGE_800),
                                ft.Text(" Налаштування (приклад)")
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER
                        )
                    )
                ),
                 ft.Card(
                     content=ft.Container(
                        padding=15,
                        content=ft.Row(
                            controls=[
                                ft.Icon(ft.icons.PERSON, color=ft.colors.GREEN_700),
                                ft.Text(" Мій профіль (приклад)")
                            ],
                            vertical_alignment=ft.CrossAxisAlignment.CENTER
                        )
                    )
                ),

                ft.Container(height=20), # Відступ
                ft.Text("Тут може бути інша корисна інформація або дії...", italic=True) # Додатковий текст

            ],
            # Дозволяємо колонці зайняти весь доступний вертикальний простір
            expand=True
        )

        # Додаємо основний вміст на сторінку (з бічними відступами)
        page.add(ft.Container(content=main_content, padding=ft.padding.symmetric(horizontal=20)))
        page.update() # Оновлюємо сторінку для відображення змін

    def show_login_register_view():
        """
        Очищає сторінку, прибирає AppBar (якщо він є) та показує екран входу/реєстрації.
        """
        page.clean() # Очищаємо сторінку
        page.appbar = None # !!! Дуже важливо: прибираємо AppBar !!!
        # Повертаємо початкові налаштування вирівнювання для форми входу
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        feedback_text.value = "" # Очищаємо текст помилок
        # Переконуємось, що об'єкт з вкладками існує перед додаванням
        # (Має існувати, оскільки визначається нижче, але це додаткова пересторога)
        if 'login_register_column' in locals() or 'login_register_column' in globals():
             page.add(login_register_column) # Додаємо колонку з вкладками
        else:
             # Цей блок коду не повинен виконуватися в нормальному режимі
             print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка: login_register_column не знайдено при виклику show_login_register_view")
             page.add(ft.Text("Помилка завантаження інтерфейсу входу."))
        page.update() # Оновлюємо сторінку

    # --- Обробники подій ---

    def logout_click(e):
        """Обробник натискання кнопки 'Вийти' (з AppBar)."""
        current_user = page.client_storage.get(SESSION_KEY) # Отримуємо ім'я для логування
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{current_user}' виходить. Видалення сесії.")
        # Видаляємо ключ сесії зі сховища клієнта
        page.client_storage.remove(SESSION_KEY)
        # Показуємо екран входу/реєстрації
        show_login_register_view()

    def register_click(e):
        """Обробник натискання кнопки 'Зареєструватися'."""
        username = reg_username_field.value.strip()
        password = reg_password_field.value
        confirm_password = reg_confirm_password_field.value

        feedback_text.value = ""
        feedback_text.color = ft.colors.RED

        # 1. Валідація введених даних
        if not username or not password or not confirm_password:
            feedback_text.value = "Будь ласка, заповніть всі поля реєстрації."
            page.update(); return # Оновлюємо тільки текст і виходимо

        if password != confirm_password:
            feedback_text.value = "Паролі не співпадають."
            # Очищаємо поля паролів для зручності користувача
            reg_password_field.value = ""
            reg_confirm_password_field.value = ""
            reg_password_field.focus() # Ставимо фокус на перше поле пароля
            page.update(); return

        # 2. Взаємодія з базою даних (у блоці try...except...finally)
        conn_reg = None # Ініціалізуємо змінну для з'єднання
        try:
            # Створюємо НОВЕ з'єднання з БД СПЕЦІАЛЬНО для цього запиту
            # Це необхідно через те, що обробники Flet можуть виконуватися в окремих потоках
            conn_reg = sqlite3.connect(db_path)
            cursor_reg = conn_reg.cursor()

            # Перевіряємо, чи існує користувач з таким ім'ям
            cursor_reg.execute("SELECT username FROM users WHERE username=?", (username,))
            if cursor_reg.fetchone(): # Якщо fetchone() повернув запис, користувач існує
                feedback_text.value = f"Користувач '{username}' вже існує."
            else:
                # Користувач не існує - проводимо реєстрацію
                hashed_pw = hash_password(password) # Хешуємо пароль
                # Вставляємо нового користувача в таблицю 'users'
                cursor_reg.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pw))
                conn_reg.commit() # Зберігаємо зміни в БД

                # Реєстрація успішна!
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' зареєстрований. Збереження сесії.")
                # Зберігаємо ім'я користувача в сховищі клієнта для сесії
                page.client_storage.set(SESSION_KEY, username)
                # Показуємо основний інтерфейс програми
                show_logged_in_view(username)
                return # Важливо вийти тут, щоб не виконувати page.update() нижче

        except sqlite3.Error as db_err:
            # Обробка помилок SQLite під час реєстрації
            feedback_text.value = f"Помилка бази даних: {db_err}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при реєстрації: {db_err}")
        except Exception as ex:
            # Обробка інших можливих помилок
            feedback_text.value = f"Сталася невідома помилка: {ex}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Невідома помилка при реєстрації: {ex}")
        finally:
            # Гарантовано закриваємо з'єднання, якщо воно було відкрито
            if conn_reg:
                conn_reg.close()

        # Оновлюємо feedback_text тільки якщо сталася помилка (тобто не було успішного return)
        page.update()


    def login_click(e):
        """Обробник натискання кнопки 'Увійти'."""
        username = login_username_field.value.strip()
        password = login_password_field.value

        feedback_text.value = ""
        feedback_text.color = ft.colors.RED

        # 1. Валідація введених даних
        if not username or not password:
            feedback_text.value = "Будь ласка, заповніть всі поля для входу."
            page.update(); return

        # 2. Взаємодія з базою даних
        conn_log = None
        try:
             # Створюємо НОВЕ з'єднання з БД СПЕЦІАЛЬНО для цього запиту
            conn_log = sqlite3.connect(db_path)
            cursor_log = conn_log.cursor()

            # Шукаємо користувача за ім'ям та отримуємо хеш його пароля
            cursor_log.execute("SELECT password_hash FROM users WHERE username=?", (username,))
            result = cursor_log.fetchone() # Отримуємо один рядок результату або None

            if result: # Якщо користувач знайдений
                stored_hash = result[0] # Перший стовпець результату - це збережений хеш
                entered_hash = hash_password(password) # Хешуємо введений пароль

                # Порівнюємо збережений хеш з хешем введеного пароля
                if stored_hash == entered_hash:
                    # Паролі співпали - вхід успішний!
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' увійшов. Збереження сесії.")
                     # Зберігаємо ім'я користувача в сховищі клієнта для сесії
                    page.client_storage.set(SESSION_KEY, username)
                    # Показуємо основний інтерфейс програми
                    show_logged_in_view(username)
                    return # Виходимо, щоб не виконувати page.update() нижче
                else:
                    # Паролі не співпали
                    feedback_text.value = "Неправильний пароль."
            else:
                # Користувач з таким ім'ям не знайдений
                feedback_text.value = f"Користувача '{username}' не знайдено."

        except sqlite3.Error as db_err:
            feedback_text.value = f"Помилка бази даних: {db_err}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка SQLite при вході: {db_err}")
        except Exception as ex:
            feedback_text.value = f"Сталася невідома помилка: {ex}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Невідома помилка при вході: {ex}")
        finally:
            if conn_log:
                conn_log.close()

        # Оновлюємо feedback_text тільки якщо сталася помилка
        page.update()

    # --- Створення UI для екрану входу/реєстрації (виконується завжди при старті) ---
    # Кнопки
    register_button = ft.ElevatedButton(
        "Зареєструватися",
        on_click=register_click,
        width=300,
        tooltip="Створити новий обліковий запис"
        )
    login_button = ft.ElevatedButton(
        "Увійти",
        on_click=login_click,
        width=300,
        tooltip="Увійти з існуючим обліковим записом"
        )
    # Вміст вкладок
    login_tab_content = ft.Column(
            [login_username_field, login_password_field, login_button],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=20
        )
    register_tab_content = ft.Column(
            [reg_username_field, reg_password_field, reg_confirm_password_field, register_button],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=20
        )
    # Сам об'єкт Tabs
    tabs = ft.Tabs(
        selected_index=0, # Початково вибрана вкладка "Реєстрація"
        animation_duration=300,
        tabs=[
            ft.Tab(text="Реєстрація", content=register_tab_content),
            ft.Tab(text="Вхід", content=login_tab_content),
        ],
        expand=1, # Розтягувати вкладки
    )
    # Основна колонка для екрану входу/реєстрації
    login_register_column = ft.Column(
            [
                tabs, # Вкладки зверху
                ft.Container(content=feedback_text, padding=ft.padding.only(top=20)) # Поле для помилок знизу
            ],
            alignment=ft.MainAxisAlignment.START, # Вміст колонки починається зверху
            horizontal_alignment=ft.CrossAxisAlignment.CENTER, # Центрування по горизонталі
            expand=True # Розтягувати колонку
    )

    # --- Початкове відображення інтерфейсу при запуску ---
    # Перевіряємо, чи є збережена сесія в сховищі клієнта
    logged_in_user = page.client_storage.get(SESSION_KEY)
    if logged_in_user:
        # Якщо так, показуємо основний інтерфейс програми
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Знайдено збережену сесію для: {logged_in_user}. Показ основного інтерфейсу.")
        show_logged_in_view(logged_in_user)
    else:
        # Якщо ні, показуємо екран входу/реєстрації
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Збережена сесія не знайдена. Показ екрану входу/реєстрації.")
        show_login_register_view()

# --- Точка входу для запуску програми ---
# Цей блок виконується тільки якщо скрипт запускається напряму (не імпортується)
if __name__ == "__main__":
    # Запускаємо Flet додаток, вказуючи головну функцію 'main'
    ft.app(target=main)
    # Цей рядок виконається після закриття вікна програми
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Роботу програми завершено.")