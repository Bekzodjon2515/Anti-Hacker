import time
import logging
import asyncio

from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.filters import Command

from utils.security_checker import analyze_url, extract_urls
from utils.url_deep_checker import deep_url_check
from utils.virustotal import get_vt_checker
from utils.report_generator import generate_report
from utils.ai_helper import get_ai_analysis
from keyboards import get_url_check_keyboard
from handlers.base_handler import (
    check_rate_limit,
    send_rate_limit_message,
    save_last_report,
    send_error_message,
    get_remaining_requests,
)
from utils.stats_manager import record_scan

logger = logging.getLogger(__name__)
router = Router(name="url_handler")


@router.message(Command("scan"))
async def cmd_scan(message: Message) -> None:
    user_id = message.from_user.id

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply(
            "🔍 <b>URL tekshiruvi</b>\n\n"
            "Ishlatish: <code>/scan https://example.com</code>\n\n"
            "Yoki shunchaki URL ni xabarga yozing — men avtomatik aniqlayaman.",
            parse_mode="HTML",
        )
        return

    url = args[1].strip()

    if not url.startswith(('http://', 'https://', 'www.')):
        url = 'https://' + url

    if url.startswith('www.'):
        url = 'https://' + url

    await _process_url(message, url)


@router.message(F.text.regexp(r'(?:(?:https?|ftp)://)?[\w.-]+(?:\.[\w\.-]+)+[\w\-_~:/?#[\]@!$&\'*+,;=.]+'))
async def handle_url_message(message: Message) -> None:
    user_id = message.from_user.id

    if message.text.startswith('/'):
        return

    if not check_rate_limit(user_id):
        await send_rate_limit_message(message)
        return

    urls = extract_urls(message.text)
    if not urls:
        return

    url = urls[0]
    await _process_url(message, url)

    if len(urls) > 1:
        await message.reply(
            f"ℹ️ Xabarda <b>{len(urls)}</b> ta URL topildi.\n"
            f"Birinchi URL tekshirildi. Qolganlarini alohida yuboring.",
            parse_mode="HTML",
        )


@router.callback_query(F.data.startswith("rescan_url:"))
async def callback_rescan_url(callback: CallbackQuery) -> None:
    url = callback.data.split(":", 1)[1]
    user_id = callback.from_user.id

    if not check_rate_limit(user_id):
        await callback.answer(
            "⏳ Juda ko'p so'rov! Biroz kutib turing.",
            show_alert=True,
        )
        return

    await callback.answer("🔄 Chuqur qayta tekshirilmoqda...")

    start_time = time.time()
    
    # Run simple check, deep check, and VT check concurrently
    vt = get_vt_checker()
    
    base_analysis_task = asyncio.to_thread(analyze_url, url)
    deep_analysis_task = deep_url_check(url)
    vt_task = vt.check_url(url) if vt else asyncio.sleep(0)
    
    base_analysis, deep_analysis, vt_result = await asyncio.gather(
        base_analysis_task, 
        deep_analysis_task, 
        vt_task,
        return_exceptions=True
    )
    
    if isinstance(base_analysis, Exception):
        logger.error("Base check fail: %s", base_analysis)
        base_analysis = {"score": 0, "details": [], "warnings": ["❌ Asosiy tekshiruvda xato"]}
        
    if isinstance(deep_analysis, Exception):
        logger.error("Deep check fail: %s", deep_analysis)
        deep_analysis = {"all_details": [], "all_warnings": [], "total_score_impact": 0}
        
    if isinstance(vt_result, Exception):
        logger.error("VT check fail: %s", vt_result)
        vt_result = {"details": [], "warnings": [], "score_impact": 0}
    elif not vt_result:
        vt_result = {"details": [], "warnings": [], "score_impact": 0}
        
    score = base_analysis.get('score', 100)
    score += deep_analysis.get('total_score_impact', 0)
    score += vt_result.get('score_impact', 0)
    score = max(0, min(100, score))
    
    
    details = base_analysis.get('details', []) + deep_analysis.get('all_details', []) + vt_result.get('details', [])
    warnings = base_analysis.get('warnings', []) + deep_analysis.get('all_warnings', []) + vt_result.get('warnings', [])
    
    is_https = base_analysis.get('has_ssl', False)
    is_ip = base_analysis.get('is_ip', False)
    has_keywords = bool(base_analysis.get('phishing_keywords_found', []))
    
    ai_summary = await get_ai_analysis(
        url=url,
        domain=base_analysis.get('domain', url),
        score=score,
        warnings=warnings,
        is_https=is_https,
        is_ip=is_ip,
        has_phishing_keywords=has_keywords
    )
    
    check_time = time.time() - start_time

    report = generate_report(
        scan_type="URL",
        name=base_analysis.get('domain', url[:50]),
        score=score,
        details=details,
        check_time=check_time,
        warnings=warnings,
        url=url,
        ai_summary=ai_summary,
    )

    save_last_report(user_id, report)
    record_scan(user_id, "URL", score)

    await callback.message.edit_text(
        report,
        parse_mode="HTML",
        reply_markup=get_url_check_keyboard(url),
        disable_web_page_preview=True,
    )


async def _process_url(message: Message, url: str) -> None:
    user_id = message.from_user.id

    processing_msg = await message.reply(
        "🔍 <b>URL chuqur tekshirilmoqda...</b>\n"
        "⏳ SSL, HTTP Headers, DNS va xavfsizlik ma'lumotlari izlanmoqda...",
        parse_mode="HTML",
    )

    try:
        start_time = time.time()
        
        vt = get_vt_checker()
        
        base_analysis_task = asyncio.to_thread(analyze_url, url)
        deep_analysis_task = deep_url_check(url)
        vt_task = vt.check_url(url) if vt else asyncio.sleep(0)
        
        base_analysis, deep_analysis, vt_result = await asyncio.gather(
            base_analysis_task, 
            deep_analysis_task, 
            vt_task,
            return_exceptions=True
        )
        
        if isinstance(base_analysis, Exception):
            logger.error("Base check fail: %s", base_analysis)
            base_analysis = {"score": 0, "details": [], "warnings": ["❌ Asosiy tekshiruvda xato"], "domain": url[:60]}
            
        if isinstance(deep_analysis, Exception):
            logger.error("Deep check fail: %s", deep_analysis)
            deep_analysis = {"all_details": [], "all_warnings": [], "total_score_impact": 0}
            
        if isinstance(vt_result, Exception):
            logger.error("VT check fail: %s", vt_result)
            vt_result = {"details": [], "warnings": [], "score_impact": 0}
        elif not vt_result:
            vt_result = {"details": [], "warnings": [], "score_impact": 0}

        score = base_analysis.get('score', 100)
        score += deep_analysis.get('total_score_impact', 0)
        score += vt_result.get('score_impact', 0)
        score = max(0, min(100, score))
        
        details = base_analysis.get('details', []) + deep_analysis.get('all_details', []) + vt_result.get('details', [])
        warnings = base_analysis.get('warnings', []) + deep_analysis.get('all_warnings', []) + vt_result.get('warnings', [])
        
        is_https = base_analysis.get('has_ssl', False)
        is_ip = base_analysis.get('is_ip', False)
        has_keywords = bool(base_analysis.get('phishing_keywords_found', []))
        
        ai_summary = await get_ai_analysis(
            url=url,
            domain=base_analysis.get('domain', url),
            score=score,
            warnings=warnings,
            is_https=is_https,
            is_ip=is_ip,
            has_phishing_keywords=has_keywords
        )
        
        check_time = time.time() - start_time

        report = generate_report(
            scan_type="URL",
            name=base_analysis.get('domain', url[:60]),
            score=score,
            details=details,
            check_time=check_time,
            warnings=warnings,
            url=url,
            ai_summary=ai_summary,
        )

        save_last_report(user_id, report)
        record_scan(user_id, "URL", score)
        remaining = get_remaining_requests(user_id)

        try:
            await processing_msg.delete()
        except Exception:
            pass

        await message.reply(
            report + f"\n\n🔢 <i>Qolgan so'rovlar: {remaining}/{5}</i>",
            parse_mode="HTML",
            reply_markup=get_url_check_keyboard(url),
            disable_web_page_preview=True,
        )

        logger.info(
            "URL tekshirildi: %s → ball: %d (user: %d)",
            url[:60], score, user_id,
        )

    except Exception as e:
        logger.error("URL tekshiruv xatosi: %s", e)
        try:
            await processing_msg.delete()
        except Exception:
            pass
        await send_error_message(message, str(e))
