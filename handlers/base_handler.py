import os
import time
import logging
from collections import defaultdict
from typing import Optional

from aiogram import Bot, Router, F
from aiogram.filters import CommandStart, Command
from aiogram.types import Message, Document, CallbackQuery

from config import RATE_LIMIT, RATE_WINDOW, MAX_FILE_SIZE, TEMP_DIR

logger = logging.getLogger(__name__)
router = Router(name="base_handler")

_rate_store: dict[int, list[float]] = defaultdict(list)
_last_reports: dict[int, str] = {}


def check_rate_limit(user_id: int) -> bool:
    now = time.time()
    _rate_store[user_id] = [
        ts for ts in _rate_store[user_id]
        if now - ts < RATE_WINDOW
    ]
    if len(_rate_store[user_id]) >= RATE_LIMIT:
        return False
    _rate_store[user_id].append(now)
    return True


def get_remaining_requests(user_id: int) -> int:
    now = time.time()
    _rate_store[user_id] = [
        ts for ts in _rate_store[user_id]
        if now - ts < RATE_WINDOW
    ]
    return max(0, RATE_LIMIT - len(_rate_store[user_id]))


def get_wait_time(user_id: int) -> int:
    if not _rate_store[user_id]:
        return 0
    oldest = min(_rate_store[user_id])
    wait = int(RATE_WINDOW - (time.time() - oldest)) + 1
    return max(0, wait)


def save_last_report(user_id: int, report: str) -> None:
    _last_reports[user_id] = report


def get_last_report(user_id: int) -> Optional[str]:
    return _last_reports.get(user_id)


async def download_file(bot: Bot, message: Message) -> Optional[str]:
    document: Document = message.document

    if not document:
        return None

    if document.file_size and document.file_size > MAX_FILE_SIZE:
        size_mb = document.file_size / (1024 * 1024)
        await message.reply(
            f"❌ <b>Fayl juda katta!</b>\n"
            f"📦 Hajmi: {size_mb:.1f} MB\n"
            f"📏 Maksimal: {MAX_FILE_SIZE / (1024 * 1024):.0f} MB\n\n"
            f"Iltimos, kichikroq fayl yuboring.",
            parse_mode="HTML",
        )
        return None

    file_name = document.file_name or f"file_{document.file_id}"
    safe_name = "".join(
        c if c.isalnum() or c in ('_', '-', '.') else '_'
        for c in file_name
    )
    file_path = os.path.join(TEMP_DIR, f"{message.from_user.id}_{safe_name}")

    try:
        file = await bot.get_file(document.file_id)
        await bot.download_file(file.file_path, destination=file_path)
        logger.info("Fayl yuklandi: %s (%s)", safe_name, document.file_size)
        return file_path
    except Exception as e:
        logger.error("Fayl yuklash xatosi: %s", e)
        err_msg = str(e).lower()
        if "file is too big" in err_msg or "file size" in err_msg:
            await message.reply(
                "❌ **Faylni yuklab bo'lmadi!**\n\n"
                "Sizning Telegram API serveringiz ushbu hajmdagi faylni yuklab olishga ruxsat bermadi.\n\n"
                "Iltimos, faylni <a href='https://www.virustotal.com/'>VirusTotal</a> orqali to'g'ridan-to'g'ri tekshiring.",
                parse_mode="HTML",
                disable_web_page_preview=True
            )
        else:
            await message.reply(
                "❌ <b>Faylni yuklab olishda xatolik yuz berdi.</b>\n"
                "Iltimos, qayta urinib ko'ring.",
                parse_mode="HTML",
            )
        return None


def cleanup_file(file_path: str) -> None:
    try:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        logger.error("Fayl o'chirish xatosi: %s", e)


async def send_rate_limit_message(message: Message) -> None:
    wait_time = get_wait_time(message.from_user.id)
    await message.reply(
        f"⏳ <b>Juda ko'p so'rov!</b>\n\n"
        f"Siz 1 daqiqada {RATE_LIMIT} ta so'rov yubordingiz.\n"
        f"Iltimos, <b>{wait_time} sekund</b> kutib turing.\n\n"
        f"💡 Bu cheklov botni haddan tashqari yuklanishdan himoya qiladi.",
        parse_mode="HTML",
    )


async def send_error_message(message: Message, error_text: str = "") -> None:
    text = (
        "❌ <b>Xatolik yuz berdi</b>\n\n"
        "Tekshiruv jarayonida kutilmagan xatolik sodir bo'ldi.\n"
    )
    if error_text:
        safe_error = error_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        text += f"📋 <i>{safe_error[:200]}</i>\n\n"
    text += "Iltimos, qayta urinib ko'ring yoki /help buyrug'ini yuboring."
    await message.reply(text, parse_mode="HTML")


HELP_TEXT = (
    "📖 <b>Qo'llanma va yordam</b>\n\n"
    "<b>Botdan qanday foydalaniladi?</b>\n"
    "1. Xabarda istalgan URL havolani yuboring.\n"
    "2. Yoki fayl (PDF, Word, Arxiv, APK, Video, Rasm, Email, JS) yuboring.\n"
    "3. Bot avtomatik tahlil qilib, natijani ko'rsatadi.\n\n"
    "<b>Komandalar:</b>\n"
    "/scan [url] — Havolani tekshirish\n"
    "/report — Oxirgi tekshiruv hisobotini olish\n"
    "/stats — Foydalanuvchi statistikasini ko'rish\n\n"
    "<b>Holatlar (Ballar):</b>\n"
    "🟢 75-100: Xavfsiz deb hisoblanadi\n"
    "🟡 45-74: Shubhali belgilar mavjud\n"
    "🔴 0-44: Xavfli! (Ochish tavsiya etilmaydi)\n"
)

START_TEXT = (
    "🛡 <b>Anti Hacker Bot ga xush kelibsiz!</b>\n\n"
    "Har qanday fayl yoki havolani yuboring — xavfsizligini 10 soniyada ishonchli tahlil qilamiz. Noma'lum narsalarni ochishdan oldin bizda tekshiring!\n\n"
    "<b>Biz nimani aniqlaymiz:</b>\n"
    "🛡 <i>Phishing va firibgarlik havolalari</i>\n"
    "🦠 <i>Malware va zararli fayllar</i>\n"
    "🕵️ <i>Hacker izlari va Trackers (Cookies)</i>\n"
    "🤖 <i>AI (Sun'iy Intelekt) orqali xavfsizlik xulosasi</i>\n\n"
    "<b>Qo'llab-quvvatlanadi:</b>\n"
    "🔗 URL • 📄 PDF • 📝 Word • 📱 APK • 📦 ZIP/RAR\n"
    "🖼 Rasm • 🎬 Video • 📧 Email • ⚡️ JS\n\n"
    "Bot sizga bir necha soniya ichida to'liq xavfsizlik tahlili natijasini yuboradi.\n\n"
    "⚠️ <b>Eslatma:</b>\n"
    "Bot sizning xavfsizligingiz uchun ishlashga tayyor. Noma'lum fayl va linklarni ochishdan oldin doimo bizda tekshirib oling!\n\n"
    "🔐 <i>Internetda xavfsiz bo'ling!</i>\n\n"
    "⬇️ Pastdagi menyudan foydalaning yoki to'g'ridan-to'g'ri yuboring!"
)


@router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    if not check_rate_limit(message.from_user.id):
        await send_rate_limit_message(message)
        return

    from keyboards import get_main_menu
    await message.answer(
        START_TEXT,
        parse_mode="HTML",
        reply_markup=get_main_menu(),
    )


@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    if not check_rate_limit(message.from_user.id):
        await send_rate_limit_message(message)
        return

    from keyboards import get_main_menu
    await message.answer(
        HELP_TEXT,
        parse_mode="HTML",
        reply_markup=get_main_menu(),
    )


@router.message(F.text == "🔍 URL Tekshirish")
async def reply_scan_url(message: Message) -> None:
    await message.answer(
        "🔗 <b>URL tekshirish</b>\n\n"
        "Iltimos, tekshirmoqchi bo'lgan havolangizni menga yuboring\n"
        "(masalan: <code>https://example.com</code>)\n\n"
        "Yoki /scan buyrug'ini ishlating:\n"
        "<code>/scan https://example.com</code>",
        parse_mode="HTML",
    )


@router.message(F.text == "📎 Fayl Yuborish")
async def reply_send_file(message: Message) -> None:
    await message.answer(
        "📎 <b>Fayl tekshirish</b>\n\n"
        "Iltimos, tekshirish uchun faylni menga yuboring.\n\n"
        "<b>Qo'llab-quvvatlanadigan formatlar:</b>\n"
        "📄 PDF — yashirin JS, havolalar, metadata\n"
        "📝 DOCX/DOC — makroslar, tashqi havolalar\n"
        "📱 APK — ruxsatlar, imzo tekshiruvi\n"
        "🎬 Video (MP4, AVI, MKV) — format, metadata\n\n"
        "📏 Maksimal hajm: <b>20 MB</b>",
        parse_mode="HTML",
    )


@router.message(Command("stats"))
async def cmd_stats(message: Message) -> None:
    from utils.stats_manager import format_user_stats
    stats_text = format_user_stats(message.from_user.id)
    await message.reply(stats_text, parse_mode="HTML")


@router.message(F.text == "📊 Oxirgi Hisobot")
async def reply_last_report(message: Message) -> None:
    report = get_last_report(message.from_user.id)
    if report:
        await message.reply(
            "📊 <b>Oxirgi tekshiruv hisobotingiz:</b>\n\n" + report,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
    else:
        await message.reply(
            "ℹ️ Hali hech narsa tekshirmadingiz.\n"
            "URL yuboring yoki fayl biriktiring.",
            parse_mode="HTML",
        )


@router.message(F.text == "📖 Yordam")
async def reply_help(message: Message) -> None:
    await message.answer(
        HELP_TEXT,
        parse_mode="HTML",
    )


@router.callback_query(F.data.startswith("full_report:"))
async def callback_full_report(callback: CallbackQuery) -> None:
    await callback.answer()
    user_id = callback.from_user.id
    report = get_last_report(user_id)
    if report:
        await callback.message.answer(
            "📊 <b>To'liq hisobotingiz:</b>\n\n" + report,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
    else:
        await callback.message.answer(
            "ℹ️ Hali hech narsa tekshirmadingiz.\n"
            "URL yoki fayl yuboring.",
            parse_mode="HTML",
        )


@router.message(Command("report"))
async def cmd_report(message: Message) -> None:
    report = get_last_report(message.from_user.id)
    if report:
        await message.reply(
            "📊 <b>Oxirgi tekshiruv hisobotingiz:</b>\n\n" + report,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
    else:
        await message.reply(
            "ℹ️ Hali hech narsa tekshirmadingiz.\n"
            "URL yoki fayl yuboring.",
            parse_mode="HTML",
        )
