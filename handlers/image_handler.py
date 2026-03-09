import time
import logging

from aiogram import Router, F
from aiogram.types import Message

from utils.file_analyzer import analyze_image
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
router = Router(name="image_handler")

from config import SUPPORTED_EXTENSIONS
IMAGE_EXTENSIONS = tuple(SUPPORTED_EXTENSIONS['image'])


@router.message(F.photo)
async def handle_photo(message: Message) -> None:
    user_id = message.from_user.id

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    photo = message.photo[-1]
    file_name = f"image_{photo.file_id[-8:]}.jpg"

    await _process_image(message, file_name, photo.file_id)


@router.message(F.document, F.document.file_name.lower().endswith(IMAGE_EXTENSIONS))
async def handle_image_document(message: Message) -> None:
    user_id = message.from_user.id

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    file_name = message.document.file_name or "image.jpg"
    await _process_image(message, file_name, message.document.file_id, is_document=True)


async def _process_image(message: Message, file_name: str, file_id: str, is_document: bool = False) -> None:
    user_id = message.from_user.id

    processing_msg = await message.reply(
        f"🖼️ <b>Rasm tekshirilmoqda...</b>\n"
        f"📎 Fayl: <code>{file_name}</code>\n"
        f"⏳ EXIF va yashirin ma'lumotlar tahlil qilinmoqda...",
        parse_mode="HTML",
    )

    file_path = None
    try:
        from config import TEMP_DIR
        import os

        file = await message.bot.get_file(file_id)
        safe_name = "".join(c if c.isalnum() or c in ('_', '-', '.') else '_' for c in file_name)
        file_path = os.path.join(TEMP_DIR, f"{user_id}_{safe_name}")
        await message.bot.download_file(file.file_path, destination=file_path)

        start_time = time.time()
        analysis = analyze_image(file_path, file_name=file_name)
        check_time = time.time() - start_time

        file_hash = analysis.get('file_hash', '')
        report = generate_report(
            scan_type="Image",
            name=file_name,
            score=analysis['score'],
            details=analysis['details'],
            check_time=check_time,
            warnings=analysis.get('warnings'),
            metadata=analysis.get('metadata'),
            file_hash=file_hash,
        )

        save_last_report(user_id, report)
        record_scan(user_id, "Image", analysis['score'])
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
        logger.error("Rasm tekshiruv xatosi: %s", e)
        try:
            await processing_msg.delete()
        except Exception:
            pass
        await send_error_message(message, str(e))
    finally:
        if file_path:
            cleanup_file(file_path)
