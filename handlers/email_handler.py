import time
import logging
import re
from typing import Dict, Any

from aiogram import Router, F
from aiogram.types import Message

from utils.report_generator import generate_report
from handlers.base_handler import (
    check_rate_limit,
    send_rate_limit_message,
    save_last_report,
    send_error_message,
    get_remaining_requests,
)
from utils.stats_manager import record_scan

logger = logging.getLogger(__name__)
router = Router(name="email_handler")

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from email_validator import validate_email, EmailNotValidError
    HAS_EMAIL_VALIDATOR = True
except ImportError:
    HAS_EMAIL_VALIDATOR = False

def extract_emails(text: str) -> list[str]:
    pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    return pattern.findall(text)

def analyze_email(email_str: str) -> Dict[str, Any]:
    result = {
        "email": email_str,
        "score": 100,
        "details": [],
        "warnings": [],
    }

    if not HAS_EMAIL_VALIDATOR:
        result["warnings"].append("⚠️ email_validator kutubxonasi yo'q — tekshiruv cheklangan")
    else:
        try:
            valid = validate_email(email_str, check_deliverability=False)
            email_str = valid.normalized
            result["details"].append("✅ Format: To'g'ri")
        except EmailNotValidError as e:
            result["score"] = 0
            result["warnings"].append(f"🔴 Noto'g'ri email formati: {str(e)}")
            return result

    domain = email_str.split('@')[-1] if '@' in email_str else ""
    
    # Vaqtinchalik elektron pochtalar (Disposable Email Providers)
    disposable_domains = ['10minutemail.com', 'mailinator.com', 'temp-mail.org', 'guerrillamail.com', 'yopmail.com', 'throwawaymail.com', 'crazymail.com']
    if any(d in domain for d in disposable_domains):
        result["warnings"].append("🔴 Vaqtinchalik pochta (Disposable email) — firibgarlik xavfi!")
        result["score"] -= 40
    
    if HAS_DNS and domain:
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result["details"].append(f"✅ MX Record: Mavjud ({len(mx_records)} ta server)")
        except dns.resolver.NoAnswer:
            result["warnings"].append("🔴 MX Record topilmadi — bu domenga xat yuborib/qabul qilib bo'lmaydi")
            result["score"] -= 30
        except dns.resolver.NXDOMAIN:
            result["score"] = 0
            result["warnings"].append("🔴 Domen mavjud emas (NXDOMAIN)")
        except Exception:
            result["warnings"].append("⚠️ DNS tekshiruvda xato")

    result["score"] = max(0, result["score"])
    return result


@router.message(F.text.regexp(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'))
async def handle_email_message(message: Message) -> None:
    user_id = message.from_user.id
    
    if message.text.startswith('/'):
        return

    emails = extract_emails(message.text)
    if not emails:
        return

    # Check if this text also contains URLs, if so URL handler will catch it too. (Aiogram routes to the first match usually)
    # We should let URL handler process URLs. If it's just an email, process here.
    from utils.security_checker import extract_urls
    if extract_urls(message.text):
        return  # Processed by url_handler hopefully

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    email = emails[0]

    processing_msg = await message.reply(
        f"📧 <b>Email tekshirilmoqda...</b>\n"
        f"⏳ Domen va MX yozuvlari tahlil qilinmoqda...",
        parse_mode="HTML",
    )

    try:
        start_time = time.time()
        analysis = analyze_email(email)
        check_time = time.time() - start_time

        report = generate_report(
            scan_type="Email",
            name=email,
            score=analysis['score'],
            details=analysis['details'],
            check_time=check_time,
            warnings=analysis.get('warnings'),
        )

        save_last_report(user_id, report)
        record_scan(user_id, "Email", analysis['score'])
        remaining = get_remaining_requests(user_id)

        try:
            await processing_msg.delete()
        except Exception:
            pass

        await message.reply(
            report + f"\n\n🔢 <i>Qolgan so'rovlar: {remaining}/{5}</i>",
            parse_mode="HTML",
            disable_web_page_preview=True,
        )

        if len(emails) > 1:
            await message.reply(
                f"ℹ️ Xabarda <b>{len(emails)}</b> ta email topildi.\n"
                f"Faqat birinchisi tekshirildi.",
                parse_mode="HTML",
            )

    except Exception as e:
        logger.error("Email tekshiruv xatosi: %s", e)
        try:
            await processing_msg.delete()
        except Exception:
            pass
        await send_error_message(message, str(e))
