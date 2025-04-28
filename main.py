# main.py
import flet as ft
import database # Наш модуль БД
import auth     # Наш модуль автентифікації
import ui       # Наш модуль UI
import time

def main(page: ft.Page):
    """
    Головна функція програми. Ініціалізує БД, перевіряє сесію
    та відображає відповідний UI, використовуючи функції з ui.py.
    """
    page.title = "Програма з Логіном (Модульна)"
    page.window_width = 500
    page.window_height = 750

    # Ініціалізація бази даних при старті
    try:
        database.setup_database()
    except Exception as e:
        # Критична помилка, якщо БД не налаштовано
        page.add(ft.Text(f"Критична помилка ініціалізації бази даних: {e}\nДодаток не може продовжити роботу."))
        page.update()
        return # Зупиняємо виконання main

    # --- Функції для перемикання UI (використовуються як callbacks) ---
    def display_logged_in(username: str):
        """Відображає головний екран програми."""
        page.clean() # Очищаємо попередній вміст
        page.vertical_alignment = ft.MainAxisAlignment.START
        page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH

        # Викликаємо функцію з ui.py для створення AppBar та основного вмісту
        appbar, main_view = ui.create_logged_in_view(page, username, display_login_register)

        page.appbar = appbar   # Встановлюємо AppBar
        page.add(main_view)    # Додаємо основний вміст
        page.update()

    def display_login_register():
        """Відображає екран входу/реєстрації."""
        page.clean()
        page.appbar = None    # Прибираємо AppBar
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

        # Викликаємо функцію з ui.py для створення форми входу/реєстрації
        login_register_view = ui.create_login_register_view(page, display_logged_in)

        page.add(login_register_view) # Додаємо створений UI
        page.update()

    # --- Перевірка початкового стану сесії ---
    logged_in_user = page.client_storage.get(auth.SESSION_KEY)
    if logged_in_user:
        # Якщо користувач вже залогінений (є сесія), показуємо головний екран
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Знайдено збережену сесію для: {logged_in_user}. Показ основного інтерфейсу.")
        display_logged_in(logged_in_user)
    else:
        # Якщо сесії немає, показуємо екран входу/реєстрації
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Збережена сесія не знайдена. Показ екрану входу/реєстрації.")
        display_login_register()

# --- Точка входу для запуску програми ---
if __name__ == "__main__":
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Запуск додатку...")
    ft.app(target=main)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Роботу програми завершено.")