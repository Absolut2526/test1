# main.py
import flet as ft
# import database # <- ВИДАЛЕНО
import auth     # Потрібен для SESSION_KEY
import ui       # Містить UI логіку та виклики API
import time

def main(page: ft.Page):
    """Головна функція додатку Flet."""
    page.title = "Клієнт чату (API)"
    page.window_width = 500
    page.window_height = 750
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

    # --- ВИДАЛЕНО БЛОК ІНІЦІАЛІЗАЦІЇ БД ---
    # База даних тепер ініціалізується та керується сервером.

    def display_logged_in(username: str):
        """Показує основний інтерфейс для залогіненого користувача."""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Відображення головного екрану для: {username}")
        page.clean() # Очистити попередній контент (екран входу)
        page.vertical_alignment = ft.MainAxisAlignment.START # Змінити вирівнювання
        page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH
        # Створюємо AppBar та основний контент через ui.py
        appbar, main_view = ui.create_logged_in_view(page, username, display_login_register)
        page.appbar = appbar # Встановлюємо AppBar
        page.add(main_view)  # Додаємо основний контент
        page.update()

    def display_login_register():
        """Показує екран входу/реєстрації."""
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Відображення екрану входу/реєстрації")
        page.clean() # Очистити попередній контент (головний екран)
        page.appbar = None # Видалити AppBar
        page.vertical_alignment = ft.MainAxisAlignment.CENTER # Центрувати екран входу
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        # Створюємо контент екрану входу/реєстрації через ui.py
        login_register_view = ui.create_login_register_view(page, display_logged_in)
        page.add(login_register_view)
        page.update()

    # --- Перевірка наявності сесії при старті додатку ---
    logged_in_user = page.client_storage.get(auth.SESSION_KEY)
    if logged_in_user:
        # ВАЖЛИВО: В реальному додатку тут варто було б зробити API-запит
        # для перевірки валідності сесії/токена на сервері.
        # Зараз ми просто довіряємо локальному сховищу.
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Знайдено збережену сесію для: {logged_in_user}. Показ основного інтерфейсу.")
        display_logged_in(logged_in_user)
    else:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Збережена сесія не знайдена. Показ екрану входу/реєстрації.")
        display_login_register()

if __name__ == "__main__":
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Запуск клієнтського додатку Flet...")
    # ВАЖЛИВО: Переконайтесь, що Flask сервер (backend/server.py) запущено окремо!
    ft.app(target=main)
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Клієнтський додаток Flet завершив роботу.")