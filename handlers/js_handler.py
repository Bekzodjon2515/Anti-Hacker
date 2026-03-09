import time
import logging

from aiogram import Router, F
from aiogram.types import Message

from utils.file_analyzer import analyze_js
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
from utils.stats_manager import record_scan

logger = logging.getLogger(__name__)
router = Router(name="js_handler")

from config import SUPPORTED_EXTENSIONS
JS_EXTENSIONS = tuple(SUPPORTED_EXTENSIONS['js'])


@router.message(F.document, F.document.file_name.lower().endswith(JS_EXTENSIONS))
async def handle_js(message: Message) -> None:
    user_id = message.from_user.id

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    file_name = message.document.file_name or "script.js"

    processing_msg = await message.reply(
        f"⚡ <b>JavaScript tekshirilmoqda...</b>\n"
        f"📎 Fayl: <code>{file_name}</code>\n"
        f"⏳ Obfuskatsiya va xavfli kodlar izlanmoqda...",
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
        analysis = analyze_js(file_path, file_name=file_name)
        check_time = time.time() - start_time

        file_hash = analysis.get('file_hash', '')
        report = generate_report(
            scan_type="JavaScript",
            name=file_name,
            score=analysis['score'],
            details=analysis['details'],
            check_time=check_time,
            warnings=analysis.get('warnings'),
            metadata=analysis.get('metadata'),
            file_hash=file_hash,
        )

        save_last_report(user_id, report)
        record_scan(user_id, "JS", analysis['score'])
        remaining = get_remaining_requests(user_id)

        try:
            await processing_msg.delete()
        except Exception:
            pass

        keyboard = get_file_check_keyboard(file_hash) if file_hash else None

        await message.reply(
            report + f"\n\n🔢 <i>Qolgan so'rovlar: {remaining}/{5}</i>",
            parse_mode="HTML",
            reply_markup=keyboard,
            disable_web_page_preview=True,
        )

    except Exception as e:
        logger.error("JS tekshiruv xatosi: %s", e)
        try:
            await processing_msg.delete()
        except Exception:
            pass
        await send_error_message(message, str(e))
    finally:
        if file_path:
            cleanup_file(file_path)
