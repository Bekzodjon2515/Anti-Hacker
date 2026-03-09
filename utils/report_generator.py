import logging
from typing import Dict, List, Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


def generate_report(
    scan_type: str,
    name: str,
    score: int,
    details: List[str],
    check_time: float,
    warnings: Optional[List[str]] = None,
    metadata: Optional[Dict[str, str]] = None,
    file_hash: Optional[str] = None,
    url: Optional[str] = None,
    ai_summary: Optional[str] = None,
) -> str:
    from utils.security_checker import get_security_level
    emoji, status, _ = get_security_level(score)

    safe_name = name.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    lines = [
        "🔍 <b>TEKSHIRUV NATIJALARI</b>",
        "━━━━━━━━━━━━━━━━━━━",
        f"📎 <b>Tur:</b> {scan_type}",
        f"🎯 <b>Nomi:</b> <code>{safe_name}</code>",
        "━━━━━━━━━━━━━━━━━━━",
        f"🛡️ <b>XAVFSIZLIK BALLI:</b> {score}/100",
        f"{emoji} <b>Holat:</b> {status}",
        "",
        "📊 <b>TAHLIL NATIJALARI:</b>",
    ]

    for detail in details:
        lines.append(f"  {detail}")

    if warnings:
        lines.append("")
        lines.append("⚠️ <b>OGOHLANTIRISHLAR:</b>")
        for warning in warnings:
            lines.append(f"  {warning}")

    if metadata:
        lines.append("")
        lines.append("📋 <b>METADATA:</b>")
        for key, value in metadata.items():
            safe_value = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            lines.append(f"  • <b>{key}:</b> {safe_value}")

    if url or file_hash:
        lines.append("")
        lines.append("🔗 <b>CHUQUR TEKSHIRISH:</b>")
        if url:
            from urllib.parse import urlparse
            try:
                domain = urlparse(url).hostname or ""
            except Exception:
                domain = ""
                
            encoded_url = quote(url, safe='')
            encoded_domain = quote(domain, safe='')
            
            lines.append("  <b>[1] Asosiy Tahlil:</b>")
            lines.append(f"  • <a href='https://urlscan.io/search/#{domain}'>URLScan.io (Screenshot & Kod)</a>")
            lines.append(f"  • <a href='https://www.virustotal.com/gui/search/{encoded_url}'>VirusTotal (70+ Antivirus)</a>")
            lines.append("  <b>[2] Maxfiylik va Tracker:</b>")
            lines.append(f"  • <a href='https://themarkup.org/blacklight?url={encoded_url}'>Blacklight (Tracker tahlil)</a>")
            lines.append("  <b>[3] Chuqur Xavfsizlik:</b>")
            lines.append(f"  • <a href='https://www.ssllabs.com/ssltest/analyze.html?d={encoded_domain}'>SSL Labs (Sertifikat)</a>")
            lines.append(f"  • <a href='https://whois.domaintools.com/{encoded_domain}'>WHOIS (Domen egasi)</a>")
            lines.append("  <b>[4] Boshqalar:</b>")
            lines.append(f"  • <a href='https://urlhaus.abuse.ch/browse.php?search={encoded_domain}'>URLhaus (Malware DB)</a>")
        elif file_hash:
            lines.append(
                f"  • <a href='https://www.virustotal.com/gui/file/{file_hash}'>VirusTotal (Hash)</a>"
            )

    if ai_summary:
        safe_ai_summary = ai_summary.replace("<", "&lt;").replace(">", "&gt;")
        lines.extend([
            "",
            "🤖 <b>AI XAVFSIZLIK XULOSASI:</b>",
            f"<i>{safe_ai_summary}</i>"
        ])

    lines.extend([
        "━━━━━━━━━━━━━━━━━━━",
        f"⏱️ <b>Tekshiruv vaqti:</b> {check_time:.1f}s",
    ])

    return "\n".join(lines)


def generate_error_report(error_msg: str) -> str:
    safe_msg = error_msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        "❌ <b>XATOLIK</b>\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        f"{safe_msg}\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        "Qayta urinib ko'ring yoki /help buyrug'ini yuboring."
    )
