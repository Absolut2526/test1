import flet as ft
import database
import auth
import ui
import time

def main(page: ft.Page):
    page.title = "Програма з Логіном (Модульна)"
    page.window_width = 500
    page.window_height = 750

    try:
        database.setup_database()
    except Exception as e:
        page.add(ft.Text(f"Критична помилка ініціалізації бази даних: {e}\nДодаток не може продовжити роботу."))
        page.update()
        return

    def display_logged_in(username: str):
        page.clean(); page.vertical_alignment = ft.MainAxisAlignment.START; page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH
        appbar, main_view = ui.create_logged_in_view(page, username, display_login_register)
        page.appbar = appbar; page.add(main_view); page.update()

    def display_login_register():
        page.clean(); page.appbar = None; page.vertical_alignment = ft.MainAxisAlignment.CENTER; page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        login_register_view = ui.create_login_register_view(page, display_logged_in)
        page.add(login_register_view); page.update()

    logged_in_user = page.client_storage.get(auth.SESSION_KEY)
    if logged_in_user:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Знайдено збережену сесію для: {logged_in_user}. Показ основного інтерфейсу.")
        display_logged_in(logged_in_user)
    else:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Збережена сесія не знайдена. Показ екрану входу/реєстрації.")
        display_login_register()

if __name__ == "__main__":
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Запуск додатку...")
    ft.app(target=main)