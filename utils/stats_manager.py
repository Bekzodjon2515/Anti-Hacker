import time
import logging
from collections import defaultdict
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

_user_stats: Dict[int, Dict[str, Any]] = defaultdict(lambda: {
    "total_scans": 0,
    "url_scans": 0,
    "file_scans": 0,
    "pdf_scans": 0,
    "docx_scans": 0,
    "apk_scans": 0,
    "video_scans": 0,
    "image_scans": 0,
    "archive_scans": 0,
    "js_scans": 0,
    "email_checks": 0,
    "threats_found": 0,
    "safe_found": 0,
    "first_scan": 0,
    "last_scan": 0,
})

_global_stats: Dict[str, int] = {
    "total_scans": 0,
    "total_users": 0,
    "threats_found": 0,
}


def record_scan(user_id: int, scan_type: str, score: int) -> None:
    stats = _user_stats[user_id]
    now = time.time()

    if stats["total_scans"] == 0:
        stats["first_scan"] = now
        _global_stats["total_users"] += 1

    stats["total_scans"] += 1
    stats["last_scan"] = now

    type_map = {
        "URL": "url_scans",
        "PDF": "pdf_scans",
        "DOCX": "docx_scans",
        "APK": "apk_scans",
        "Video": "video_scans",
        "Image": "image_scans",
        "Archive": "archive_scans",
        "JS": "js_scans",
        "Email": "email_checks",
    }

    key = type_map.get(scan_type, "file_scans")
    stats[key] += 1

    if scan_type in ("URL", "Email"):
        pass
    else:
        stats["file_scans"] += 1

    if score >= 75:
        stats["safe_found"] += 1
    elif score < 45:
        stats["threats_found"] += 1
        _global_stats["threats_found"] += 1

    _global_stats["total_scans"] += 1


def get_user_stats(user_id: int) -> Optional[Dict[str, Any]]:
    if user_id not in _user_stats:
        return None
    return dict(_user_stats[user_id])


def get_global_stats() -> Dict[str, int]:
    return dict(_global_stats)


def format_user_stats(user_id: int) -> str:
    stats = get_user_stats(user_id)
    if not stats or stats["total_scans"] == 0:
        return (
            "📊 <b>Sizning statistikangiz</b>\n\n"
            "ℹ️ Hali hech narsa tekshirmadingiz.\n"
            "URL yuboring yoki fayl biriktiring!"
        )

    from datetime import datetime
    first = datetime.fromtimestamp(stats["first_scan"]).strftime("%Y-%m-%d %H:%M")
    last = datetime.fromtimestamp(stats["last_scan"]).strftime("%Y-%m-%d %H:%M")

    lines = [
        "📊 <b>SIZNING STATISTIKANGIZ</b>",
        "━━━━━━━━━━━━━━━━━━━",
        f"📝 Jami tekshiruvlar: <b>{stats['total_scans']}</b>",
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
        f"  ✅ Xavfsiz: {stats['safe_found']}",
        f"  🔴 Xavfli: {stats['threats_found']}",
        "",
        f"📅 Birinchi: {first}",
        f"📅 Oxirgi: {last}",
    ])

    g = get_global_stats()
    lines.extend([
        "",
        "━━━━━━━━━━━━━━━━━━━",
        "<b>Umumiy bot statistikasi:</b>",
        f"  👥 Foydalanuvchilar: {g['total_users']}",
        f"  📝 Jami tekshiruvlar: {g['total_scans']}",
        f"  🔴 Xavflar aniqlangan: {g['threats_found']}",
    ])

    return "\n".join(lines)
