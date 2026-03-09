import time
import logging

from aiogram import Router, F
from aiogram.types import Message

from utils.file_analyzer import analyze_docx
from utils.report_generator import generate_report
from keyboards import get_file_check_keyboard
from handlers.base_handler import (
    check_rate_limit,
    send_rate_limit_message,
    download_file,
    cleanup_file,
    save_last_report,
    send_error_message,
    get_remaining_requests,
)

logger = logging.getLogger(__name__)
router = Router(name="word_handler")


def _is_word_file(file_name: str) -> bool:
    if not file_name:
        return False
    lower_name = file_name.lower()
    return lower_name.endswith('.docx') or lower_name.endswith('.doc')


@router.message(
    F.document,
    F.document.file_name.func(lambda name: _is_word_file(name) if name else False)
)
async def handle_word(message: Message) -> None:
    user_id = message.from_user.id

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    file_name = message.document.file_name or "document.docx"
    ext = file_name.rsplit('.', 1)[-1].lower()

    if ext == 'doc':
        await message.reply(
            "⚠️ <b>Diqqat:</b> Eski <code>.doc</code> formati aniqlandi.\n"
            "Bu format makroslarga ko'proq moyil. "
            "Asosiy tahlil <code>.docx</code> uchun optimallashtirilgan.\n"
            "Tekshiruv davom etmoqda...",
            parse_mode="HTML",
        )

    processing_msg = await message.reply(
        f"📝 <b>Word fayl tekshirilmoqda...</b>\n"
        f"📎 Fayl: <code>{file_name}</code>\n"
        f"⏳ Iltimos, kutib turing...",
        parse_mode="HTML",
    )

    file_path = None
    try:
        file_path = await download_file(message.bot, message)
        if not file_path:
            try:
                await processing_msg.delete()
            except Exception:
                pass
            return

        start_time = time.time()
        analysis = analyze_docx(file_path)
        check_time = time.time() - start_time

        file_hash = analysis.get('file_hash', '')
        report = generate_report(
            scan_type="DOCX",
            name=file_name,
            score=analysis['score'],
            details=analysis['details'],
            check_time=check_time,
            warnings=analysis.get('warnings'),
            metadata=analysis.get('metadata'),
            file_hash=file_hash,
        )

        save_last_report(user_id, report)
        remaining = get_remaining_requests(user_id)

        try:
            await processing_msg.delete()
        except Exception:
            pass

        keyboard = None
        if file_hash:
            keyboard = get_file_check_keyboard(file_hash)

        await message.reply(
            report + f"\n\n🔢 <i>Qolgan so'rovlar: {remaining}/{5}</i>",
            parse_mode="HTML",
            reply_markup=keyboard,
            disable_web_page_preview=True,
        )

        logger.info(
            "Word tekshirildi: %s → ball: %d (user: %d)",
            file_name, analysis['score'], user_id,
        )

    except Exception as e:
        logger.error("Word tekshiruv xatosi: %s", e)
        try:
            await processing_msg.delete()
        except Exception:
            pass
        await send_error_message(message, str(e))
    finally:
        if file_path:
            cleanup_file(file_path)
