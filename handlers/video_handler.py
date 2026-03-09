import os
import time
import logging

from aiogram import Router, F
from aiogram.types import Message

from config import SUPPORTED_EXTENSIONS, MAX_FILE_SIZE
from utils.file_analyzer import analyze_video
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
router = Router(name="video_handler")

VIDEO_EXTENSIONS = tuple(SUPPORTED_EXTENSIONS['video'])


def _is_video_file(file_name: str) -> bool:
    if not file_name:
        return False
    return file_name.lower().endswith(VIDEO_EXTENSIONS)


@router.message(
    F.document,
    F.document.file_name.func(lambda name: _is_video_file(name) if name else False)
)
async def handle_video_document(message: Message) -> None:
    user_id = message.from_user.id

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    file_name = message.document.file_name or "video.mp4"
    await _process_video_document(message, file_name)


@router.message(F.video)
async def handle_video_native(message: Message) -> None:
    user_id = message.from_user.id

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    video = message.video
    file_name = video.file_name or "video.mp4"

    if video.file_size and video.file_size > MAX_FILE_SIZE:
        size_mb = video.file_size / (1024 * 1024)
        await message.reply(
            f"❌ <b>Video juda katta!</b>\n"
            f"📦 Hajmi: {size_mb:.1f} MB\n"
            f"📏 Maksimal: {MAX_FILE_SIZE / (1024 * 1024):.0f} MB\n\n"
            f"Iltimos, kichikroq video yuboring.",
            parse_mode="HTML",
        )
        return

    processing_msg = await message.reply(
        f"🎬 <b>Video tekshirilmoqda...</b>\n"
        f"📎 Fayl: <code>{file_name}</code>\n"
        f"⏳ Format va metadata tahlil qilinmoqda...",
        parse_mode="HTML",
    )

    file_path = None
    try:
        from config import TEMP_DIR

        file = await message.bot.get_file(video.file_id)
        safe_name = "".join(
            c if c.isalnum() or c in ('_', '-', '.') else '_'
            for c in file_name
        )
        file_path = os.path.join(TEMP_DIR, f"{user_id}_{safe_name}")
        await message.bot.download_file(file.file_path, destination=file_path)

        start_time = time.time()
        analysis = analyze_video(file_path, file_name=file_name)
        check_time = time.time() - start_time

        file_hash = analysis.get('file_hash', '')
        report = generate_report(
            scan_type="Video",
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
            "Video tekshirildi: %s → ball: %d (user: %d)",
            file_name, analysis['score'], user_id,
        )

    except Exception as e:
        logger.error("Video tekshiruv xatosi: %s", e)
        try:
            await processing_msg.delete()
        except Exception:
            pass
        await send_error_message(message, str(e))
    finally:
        if file_path:
            cleanup_file(file_path)


async def _process_video_document(message: Message, file_name: str) -> None:
    user_id = message.from_user.id

    processing_msg = await message.reply(
        f"🎬 <b>Video tekshirilmoqda...</b>\n"
        f"📎 Fayl: <code>{file_name}</code>\n"
        f"⏳ Format va metadata tahlil qilinmoqda...",
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
        analysis = analyze_video(file_path, file_name=file_name)
        check_time = time.time() - start_time

        file_hash = analysis.get('file_hash', '')
        report = generate_report(
            scan_type="Video",
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
            "Video tekshirildi: %s → ball: %d (user: %d)",
            file_name, analysis['score'], user_id,
        )

    except Exception as e:
        logger.error("Video tekshiruv xatosi: %s", e)
        try:
            await processing_msg.delete()
        except Exception:
            pass
        await send_error_message(message, str(e))
    finally:
        if file_path:
            cleanup_file(file_path)
