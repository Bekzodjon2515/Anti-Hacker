import time
import logging

from aiogram import Router, F
from aiogram.types import Message

from utils.file_analyzer import analyze_apk
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
router = Router(name="apk_handler")


@router.message(F.document.file_name.lower().endswith('.apk'))
async def handle_apk(message: Message) -> None:
    user_id = message.from_user.id

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    file_name = message.document.file_name or "application.apk"

    await message.reply(
        "📱 <b>APK fayl aniqlandi!</b>\n\n"
        "⚠️ <b>Muhim:</b> APK fayllarni faqat rasmiy manbalardan "
        "(Google Play Store) o'rnatish tavsiya etiladi.\n"
        "Noma'lum manbadan kelgan APK fayllar telefoningizga "
        "zararli dastur o'rnatishi mumkin.\n\n"
        "🔍 Tekshiruv boshlanmoqda...",
        parse_mode="HTML",
    )

    processing_msg = await message.reply(
        f"📱 <b>APK tekshirilmoqda...</b>\n"
        f"📎 Fayl: <code>{file_name}</code>\n"
        f"⏳ Ruxsatlar va imzo tahlil qilinmoqda...",
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
        analysis = analyze_apk(file_path)
        check_time = time.time() - start_time

        file_hash = analysis.get('file_hash', '')
        report = generate_report(
            scan_type="APK",
            name=file_name,
            score=analysis['score'],
            details=analysis['details'],
            check_time=check_time,
            warnings=analysis.get('warnings'),
            metadata=analysis.get('metadata'),
            file_hash=file_hash,
        )

        permissions = analysis.get('permissions', [])
        suspicious = analysis.get('suspicious_permissions', [])

        if permissions:
            perm_text = "\n\n📋 <b>BARCHA RUXSATLAR:</b>\n"
            for perm in permissions:
                marker = "🔴" if perm in suspicious else "🟢"
                perm_text += f"  {marker} <code>{perm}</code>\n"
            report += perm_text

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
            "APK tekshirildi: %s → ball: %d, ruxsatlar: %d, shubhali: %d (user: %d)",
            file_name, analysis['score'],
            len(permissions), len(suspicious), user_id,
        )

    except Exception as e:
        logger.error("APK tekshiruv xatosi: %s", e)
        try:
            await processing_msg.delete()
        except Exception:
            pass
        await send_error_message(message, str(e))
    finally:
        if file_path:
            cleanup_file(file_path)
