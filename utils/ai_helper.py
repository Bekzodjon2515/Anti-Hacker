import os
import aiohttp
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

async def get_ai_analysis(
    url: str,
    domain: str,
    score: int,
    warnings: list[str],
    is_https: bool,
    is_ip: bool,
    has_phishing_keywords: bool
) -> str:
    if not GEMINI_API_KEY:
        return ""

    prompt = f"""Sen kiberxavfsizlik ekspertisan. Quyidagi URL haqida O'zbek tilida qisqa, aniq xavfsizlik tahlili va xulosasini ber (maksimum 3-4 jumla):

URL: {url}
Domen: {domain}
HTTPS: {'Ha' if is_https else 'Yoq'}
Xavfsizlik balli: {score}/100
Aniqlangan muammolar: {', '.join(warnings) if warnings else 'Yoq'}
IP manzilmi: {'Ha' if is_ip else 'Yoq'}
Phishing kalitsozlar bormi: {'Ha' if has_phishing_keywords else 'Yoq'}

Tahlilni qisqa va aniq qil. Agar sayt xavfli bo'lsa qanday ehtiyot choralarini ko'rish kerakligini ham ayt. Markdown yulduzchalar (**) ishlatma. Faqat sof matn."""

    url_api = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={GEMINI_API_KEY}"
    
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 300,
        }
    }

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url_api, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    try:
                        text = data['candidates'][0]['content']['parts'][0]['text']
                        return text.strip()
                    except (KeyError, IndexError):
                        return "AI javobini qayta ishlashda xatolik."
                else:
                    return f"AI xizmati xatosi: HTTP {resp.status}"
    except Exception as e:
        logger.error(f"AI API dagi xato: {e}")
        return ""
