import flet as ft
import sqlite3
import hashlib
import os
import time # Для логування часу

# --- Глобальні налаштування та шляхи ---

# Шлях до файлу бази даних (у тій же папці, що і скрипт)
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'users.db'))
# Ключ для зберігання імені користувача в сховищі клієнта
SESSION_KEY = "logged_in_user"
print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Шлях до БД: {db_path}")

# --- Функції роботи з базою даних та паролями ---

def setup_database():
    """
    Створює файл БД та таблицю 'users', якщо вони ще не існують.
    Ця функція викликається один раз при старті програми.
    """
    conn = None # Ініціалізуємо змінну з'єднання
    try:
        # З'єднуємось з БД (файл буде створено, якщо його немає)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Виконуємо запит SQL для створення таблиці
        # IF NOT EXISTS запобігає помилці, якщо таблиця вже створена
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
        # Обробляємо можливі помилки SQLite
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка під час початкового налаштування БД: {e}")
        # В реальному додатку тут може бути більш складна логіка обробки помилок
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
    page.title = "Форма Реєстрації та Входу"
    page.window_width = 400
    page.window_height = 600
    # Початкове вирівнювання буде встановлено залежно від наявності сесії

    # --- Виклик функції налаштування БД при старті ---
    setup_database()

    # --- Визначення елементів керування (поля вводу, кнопки, текст) ---

    # Поля для реєстрації
    reg_username_field = ft.TextField(
        label="Ім'я користувача (реєстрація)",
        width=300,
        tooltip="Введіть бажане ім'я користувача"
    )
    reg_password_field = ft.TextField(
        label="Пароль (реєстрація)",
        password=True,         # Приховує введений текст
        can_reveal_password=True, # Додає іконку для показу/приховування пароля
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

    # Поля для входу
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

    # Текстове поле для виведення повідомлень (помилок або успіху)
    feedback_text = ft.Text(
        value="",               # Початково порожнє
        color=ft.colors.RED,  # Початковий колір для помилок
        text_align=ft.TextAlign.CENTER, # Вирівнювання тексту по центру
        width=300               # Обмежуємо ширину для кращого переносу
    )

    # --- Функції для перемикання між видами (сценами) ---

    def show_logged_in_view(username):
        """
        Очищає сторінку та відображає простий інтерфейс для залогіненого користувача.
        """
        page.clean() # Видаляє всі існуючі елементи зі сторінки
        # Налаштовуємо вирівнювання для цієї сцени
        page.vertical_alignment = ft.MainAxisAlignment.START
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

        # Додаємо новий вміст на сторінку
        page.add(
             # Контейнер для кращого контролю над відступами та вирівнюванням
             ft.Container(
                 content=ft.Column( # Вертикальне розташування елементів
                     [
                         # Текст привітання
                         ft.Text(
                             f"Вітаємо, {username}!",
                             size=18, # Розмір шрифту
                             text_align=ft.TextAlign.CENTER
                         ),
                         # Вертикальний відступ
                         ft.Container(height=20),
                         # Кнопка виходу
                         ft.ElevatedButton(
                             "Вийти",
                             on_click=logout_click, # Обробник натискання
                             width=150
                         )
                     ],
                     # Вирівнювання елементів всередині колонки
                     horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                     width=300 # Обмежуємо ширину колонки
                 ),
                 # Відступи навколо вмісту контейнера
                 padding=ft.padding.symmetric(vertical=50, horizontal=20),
                 # Вирівнювання самого контейнера по центру сторінки
                 alignment=ft.alignment.center
             )
        )
        page.update() # Оновлюємо сторінку для відображення змін

    def show_login_register_view():
        """
        Очищає сторінку та відображає початковий інтерфейс з вкладками входу/реєстрації.
        """
        page.clean()
        # Повертаємо початкові налаштування вирівнювання
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        feedback_text.value = "" # Очищаємо повідомлення про помилки
        # Додаємо заздалегідь створений елемент з вкладками
        # Переконуємось, що login_register_column визначено перед цим викликом
        if 'login_register_column' in locals() or 'login_register_column' in globals():
             page.add(login_register_column)
        else:
             # Це не повинно трапитись у нормальному потоці, але додамо перевірку
             print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Помилка: login_register_column не знайдено при виклику show_login_register_view")
             # Можна додати базовий текст помилки на сторінку
             page.add(ft.Text("Помилка завантаження інтерфейсу входу."))
        page.update()

    # --- Обробники подій ---

    def logout_click(e):
        """Обробник натискання кнопки 'Вийти'."""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач виходить. Видалення сесії.")
        # Видаляємо ключ сесії зі сховища
        page.client_storage.remove(SESSION_KEY)
        # Показуємо екран входу/реєстрації
        show_login_register_view()

    def register_click(e):
        """Обробник натискання кнопки 'Зареєструватися'."""
        # Отримуємо значення з полів, видаляючи зайві пробіли з імені користувача
        username = reg_username_field.value.strip()
        password = reg_password_field.value
        confirm_password = reg_confirm_password_field.value

        # Очищаємо попереднє повідомлення та встановлюємо колір для помилок
        feedback_text.value = ""
        feedback_text.color = ft.colors.RED

        # 1. Валідація введених даних
        if not username or not password or not confirm_password:
            feedback_text.value = "Будь ласка, заповніть всі поля реєстрації."
            page.update() # Оновлюємо тільки текст повідомлення
            return # Зупиняємо виконання функції

        if password != confirm_password:
            feedback_text.value = "Паролі не співпадають."
            # Очищаємо поля паролів для зручності
            reg_password_field.value = ""
            reg_confirm_password_field.value = ""
            reg_password_field.focus() # Ставимо фокус на перше поле пароля
            page.update()
            return

        # 2. Взаємодія з базою даних
        conn_reg = None # Ініціалізуємо змінну для з'єднання
        try:
            # Створюємо НОВЕ з'єднання з БД СПЕЦІАЛЬНО для цього запиту
            conn_reg = sqlite3.connect(db_path)
            cursor_reg = conn_reg.cursor()

            # Перевіряємо, чи існує користувач з таким ім'ям
            cursor_reg.execute("SELECT username FROM users WHERE username=?", (username,))
            if cursor_reg.fetchone(): # Якщо знайдено запис
                feedback_text.value = f"Користувач '{username}' вже існує."
            else:
                # Користувач не існує - реєструємо
                hashed_pw = hash_password(password) # Хешуємо пароль
                # Вставляємо нового користувача в таблицю
                cursor_reg.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pw))
                conn_reg.commit() # Зберігаємо зміни в БД

                # Реєстрація успішна! Зберігаємо сесію та показуємо екран привітання
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' зареєстрований. Збереження сесії.")
                # !!! Зберігаємо ім'я користувача в сховищі клієнта !!!
                page.client_storage.set(SESSION_KEY, username)
                show_logged_in_view(username)
                return # Важливо вийти тут, щоб не оновлювати feedback_text нижче

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

        # Оновлюємо feedback_text тільки якщо сталася помилка (не було return раніше)
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
            page.update()
            return

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
                stored_hash = result[0] # Перший стовпець результату - це хеш
                entered_hash = hash_password(password) # Хешуємо введений пароль

                # Порівнюємо збережений хеш з хешем введеного пароля
                if stored_hash == entered_hash:
                    # Паролі співпали - вхід успішний! Зберігаємо сесію
                    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Користувач '{username}' увійшов. Збереження сесії.")
                     # !!! Зберігаємо ім'я користувача в сховищі клієнта !!!
                    page.client_storage.set(SESSION_KEY, username)
                    show_logged_in_view(username)
                    return # Виходимо, щоб не оновлювати feedback_text
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

    # --- Створення кнопок ---
    register_button = ft.ElevatedButton(
        "Зареєструватися",
        on_click=register_click, # Прив'язка обробника
        width=300,
        tooltip="Створити новий обліковий запис"
        )
    login_button = ft.ElevatedButton(
        "Увійти",
        on_click=login_click, # Прив'язка обробника
        width=300,
        tooltip="Увійти з існуючим обліковим записом"
        )

    # --- Створення UI для екрану входу/реєстрації (Вкладки) ---
    # Визначаємо вміст кожної вкладки окремо
    login_tab_content = ft.Column(
            [login_username_field, login_password_field, login_button],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=20 # Відстань між елементами в колонці
        )
    register_tab_content = ft.Column(
            [reg_username_field, reg_password_field, reg_confirm_password_field, register_button],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=20
        )
    # Створюємо сам об'єкт Tabs
    tabs = ft.Tabs(
        selected_index=0, # Початково активна перша вкладка (Реєстрація)
        animation_duration=300, # Тривалість анімації перемикання
        tabs=[
            ft.Tab(
                text="Реєстрація", # Назва вкладки
                content=register_tab_content # Вміст вкладки
            ),
            ft.Tab(
                text="Вхід",
                content=login_tab_content
            ),
        ],
        expand=1, # Дозволяє вкладкам зайняти доступний простір
    )

    # --- Створення основного контейнера для екрану Входу/Реєстрації ---
    # Зберігаємо цей UI в змінній, щоб легко показувати його знову після виходу
    login_register_column = ft.Column(
            [
                tabs, # Додаємо вкладки
                # Контейнер для тексту зворотного зв'язку з відступом зверху
                ft.Container(content=feedback_text, padding=ft.padding.only(top=20))
            ],
            # Вирівнювання цього основного стовпця
            alignment=ft.MainAxisAlignment.START, # Вкладки зверху
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            expand=True # Дозволяє колонці розширюватися
    )

    # --- Початкове відображення інтерфейсу ---
    # Перевіряємо наявність збереженої сесії при старті програми
    logged_in_user = page.client_storage.get(SESSION_KEY)
    if logged_in_user:
        # Якщо є збережене ім'я користувача, показуємо екран привітання
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Знайдено збережену сесію для: {logged_in_user}. Показ екрану привітання.")
        # Встановлюємо відповідне вирівнювання для екрану привітання
        page.vertical_alignment = ft.MainAxisAlignment.START
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        show_logged_in_view(logged_in_user)
    else:
        # Якщо немає, показуємо екран входу/реєстрації
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Збережена сесія не знайдена. Показ екрану входу/реєстрації.")
        # Встановлюємо вирівнювання для екрану входу
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        show_login_register_view()

# --- Точка входу для запуску програми ---
if __name__ == "__main__":
    # Запускаємо Flet додаток, вказуючи головну функцію 'main'
    # Можна додати view=ft.AppView.FLET_APP для стандартного вікна
    ft.app(target=main)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Роботу програми завершено.")