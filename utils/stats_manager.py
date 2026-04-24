import logging
from typing import Dict, Any, Optional
from utils.database import update_stats, get_user_stats, get_global_stats

logger = logging.getLogger(__name__)

async def record_scan(user_id: int, scan_type: str, score: int) -> None:
    await update_stats(user_id, scan_type, score)

async def format_user_stats(user_id: int) -> str:
    stats = await get_user_stats(user_id)
    if not stats or stats["total_scans"] == 0:
        return (
            "📊 <b>Sizning statistikangiz</b>\n\n"
            "ℹ️ Hali hech narsa tekshirmadingiz.\n"
            "URL yuboring yoki fayl biriktiring!"
        )

    # In database it's stored as string timestamps natively if using CURRENT_TIMESTAMP
    # but aiosqlite returns string or None. We handle both:
    first = stats.get("first_scan", "Noma'lum")
    last = stats.get("last_scan", "Noma'lum")

    lines = [
        "📊 <b>SIZNING STATISTIKANGIZ</b>",
        "━━━━━━━━━━━━━━━━━━━",
        f"📝 Jami tekshiruvlar: <b>{stats.get('total_scans', 0)}</b>",
        "",
        "<b>Turlar bo'yicha:</b>",
    ]

    type_icons = {
        "url_scans": ("🔗", "URL"),
        "pdf_scans": ("📄", "PDF"),
        "docx_scans": ("📝", "Word"),
        "apk_scans": ("📱", "APK"),
        "video_scans": ("🎬", "Video"),
        "image_scans": ("🖼", "Rasm"),
        "archive_scans": ("📦", "Arxiv"),
        "js_scans": ("⚡", "JavaScript"),
        "email_checks": ("📧", "Email"),
    }

    for key, (icon, name) in type_icons.items():
        count = stats.get(key, 0)
        if count > 0:
            lines.append(f"  {icon} {name}: {count}")

    lines.extend([
        "",
        "<b>Natijalar:</b>",
        f"  ✅ Xavfsiz: {stats.get('safe_found', 0)}",
        f"  🔴 Xavfli: {stats.get('threats_found', 0)}",
        "",
        f"📅 Birinchi: {first}",
        f"📅 Oxirgi: {last}",
    ])

    g = await get_global_stats()
    lines.extend([
        "",
        "━━━━━━━━━━━━━━━━━━━",
        "<b>Umumiy bot statistikasi:</b>",
        f"  👥 Foydalanuvchilar: {g.get('total_users', 0)}",
        f"  📝 Jami tekshiruvlar: {g.get('total_scans', 0)}",
        f"  🔴 Xavflar aniqlangan: {g.get('threats_found', 0)}",
    ])

    return "\n".join(lines)
