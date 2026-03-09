import sys
import asyncio
import logging

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import BotCommand
from aiogram.enums import ParseMode

from config import BOT_TOKEN, LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT
from handlers import (
    base_router,
    url_router,
    email_handler,
    pdf_router,
    word_router,
    apk_router,
    video_router,
    image_handler,
    archive_handler,
    js_handler,
)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


async def main() -> None:
    if not BOT_TOKEN:
        logger.critical("BOT_TOKEN topilmadi! .env faylni tekshiring.")
        sys.exit(1)

    logger.info("Bot ishga tushirilmoqda...")

    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )

    dp = Dispatcher()

    dp.include_router(base_router)
    dp.include_router(url_router)
    dp.include_router(email_handler)
    dp.include_router(pdf_router)
    dp.include_router(word_router)
    dp.include_router(apk_router)
    dp.include_router(video_router)
    dp.include_router(image_handler)
    dp.include_router(archive_handler)
    dp.include_router(js_handler)

    try:
        me = await bot.get_me()
        logger.info(f"Bot muvaffaqiyatli ulangan: @{me.username}")
        
        commands = [
            BotCommand(command="start", description="Botni ishga tushirish"),
            BotCommand(command="scan", description="Havolani tekshirish (/scan url)"),
            BotCommand(command="report", description="Oxirgi hisobotni olish"),
            BotCommand(command="stats", description="Tahlillar statistikasi"),
            BotCommand(command="help", description="Yordam va qoidalar"),
        ]
        await bot.set_my_commands(commands)
        logger.info("Bot komandalari menyuga o'rnatildi.")
    except Exception as e:
        logger.error(f"Telegram API bilan ulanishda xato: {e}")
        sys.exit(1)

    try:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)
    finally:
        await bot.session.close()
        logger.info("Bot faoliyati to'xtatildi.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Dastur foydalanuvchi tomonidan to'xtatildi (Ctrl+C).")
