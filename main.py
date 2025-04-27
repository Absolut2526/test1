import asyncio
from aiogram import Bot, Dispatcher, types

TOKEN_API = "8152070548:AAGYQ3FolODRG-0urMRR0dVtXnYJj5G7Y1I"


bot = Bot(token=TOKEN_API)
dp = Dispatcher()


async def main():
    await dp.start_polling(bot)


@dp.message()
async def echo(message: types.Message):
    await message.answer(text=message.text)


if __name__ == '__main__':
    asyncio.run(main())