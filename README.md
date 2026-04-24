# 🛡️ Anti-Hacker Bot (Professional Xavfsizlik Skaneri)

![Python](https://img.shields.io/badge/Python-3.12-green.svg)
![Aiogram](https://img.shields.io/badge/Aiogram-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**Anti-Hacker Bot** — foydalanuvchilarni internetdagi kiber tahdidlar, zararli fayllar va soxta (phishing) havolalardan himoya qiluvchi kuchli Telegram bot. U VirusTotal API va Google Gemini sun'iy intellekti bilan integratsiya qilingan.

## 🚀 Imkoniyatlari

- **🔗 URL tahlili:** Soxta (phishing) havolalarni, xavfsiz bo'lmagan saytlarni aniqlaydi.
- **📱 APK tekshiruvi:** Android ilovalar qanday ruxsatlar so'rayotganini tekshiradi (SMS, Kontaktlar va hk).
- **📄 Hujjatlar:** PDF va Word (.docx) hujjatlaridagi zararli havolalar va skriptlarni aniqlaydi.
- **🎬 Media:** Rasm va videolarga yashiringan meta-ma'lumotlarni tahlil qiladi.
- **📦 Arxivlar:** `.zip`, `.rar` va boshqa arxivlar tarkibidagi xavfli fayllarni ko'rsatadi.
- **⚡ JavaScript (.js):** Xavfli JS kodlarni o'qiydi.
- **🧠 Sun'iy intellekt (Gemini):** Xavfsizlik tekshiruvlari natijasini inson tushunadigan tilda izohlaydi.

## ⚙️ O'rnatish yo'riqnomasi

Loyihani o'z serveringizda yoki kompyuteringizda ishga tushirish uchun:

1. **Repozitoriyni klonlang:**
   ```bash
   git clone https://github.com/SizningUsername/Anti-Hacker.git
   cd Anti-Hacker
   ```

2. **Kutubxonalarni o'rnating:**
   ```bash
   pip install -r requirements.txt
   ```

3. **.env faylini sozlang:**
   Loyihada `.env.example` fayli bor. Shuni nusxalab `.env` nomiga o'zgartiring va o'z kalitlaringizni kiriting:
   ```env
   BOT_TOKEN=telegram_botfather_tokeni
   GEMINI_API_KEY=google_gemini_kaliti
   VT_API_KEY=virustotal_api_kaliti
   ```

4. **Botni ishga tushiring:**
   ```bash
   python main.py
   ```

## 🛠 Texnologiyalar
- **Python 3.12**
- **Aiogram 3.26** (Asinxron bot framework)
- **AioSQLite** (Ma'lumotlar bazasi va statistika)
- **VirusTotal API** (70+ antivirus bazasi)
- **Google Gemini 2.0 Flash** (Tahlil va xulosa yasash uchun AI)

## 📄 Litsenziya
Ushbu loyiha MIT litsenziyasi ostida tarqatiladi.
