# 🛡️ SecurityScanBot V2

SecurityScanBot — bu interaktiv kiberxavfsizlik Telegram boti. Bot yuborilgan fayllarni, arxivlarni, rasmlarni, havolalarni va APK larni chuqur tahlil qilib, foydalanuvchini turli xavflardan, jumladan phishing, trackerlar, troyan va steganografiyadan himoya qiladi.

## 🚀 Imkoniyatlar

1. **Chuqur URL Tekshiruvi:**
    - AI xavfsizlik tahlili (Gemini)
    - SSL va HTTP header tahlili
    - DNS A, MX, NS yozuvlari tespiti
    - WHOIS ma'lumotlari (domenni ro'yxatdan o'tgan yoshi va boshqalar)
    - Tracker / Cookie blokerlari tekshiruvi (Google Analytics, Yandex, Mixpanel, Hotjar)
    
2. **VirusTotal API Integratsiyasi:**
    - 70+ xavfsizlik va antivirus kompaniyalarining tekshiruv natijalarini olib berish.

3. **Kuchaytrilgan Fayl Tahlili:**
    - **APK:** Ruxsatlar tahlili va zararli dasturlar imzosini tekshirish.
    - **Arxivlar (ZIP, RAR, 7z):** Ichidagi zararli kodlarni va zip bombalarni bloklash.
    - **PDF & Word:** Yashirin JavaScript va yomon havolalarga qarshi tekshiruv.
    - **Image:** EXIF GPS location ma'lumotlarini ajratib olish va steganografiya ehtimolini qidirish.
    - **Video:** Format, metadata.
    - **Email & JS:** Elektron pochta faolligini MX orqali tekshirish va JS obfuskatsiyalarini (eval) fosh qilish.

4. **Kard va Shaxsiy Statistika:**
    - Barcha foydalanuvchi statistikasini markazlashgan `/stats` qismida kuzatib borish.

## 🛠️ O'rnatish

1. Repozitoriyni yuklab oling:
```bash
git clone https://github.com/Username/SecurityScanBot.git
cd SecurityScanBot
```

2. Kerakli kutubxonalarni o'rnating:
```bash
pip install -r requirements.txt
```

3. Muhit o'zgaruvchilari (Environment variables): `.env` nomli fayl yarating (namuna `.env.example` da):
```env
BOT_TOKEN=7777777:ABC-DEF1234ghIkl-zyx57W2v1u...
VT_API_KEY=sizning_virustotal_kilitingiz
GEMINI_API_KEY=sizning_gemini_api_kilitingiz
```

4. Pylonda ishga tushiring:
```bash
python main.py
```

## 🤝 Hamkorlik / Hissa qo'shish

Loyiha bo'yicha PR lar xursandchilik bilan qabul qilinadi. Boshlamasdan oldin muammo yarating yoki o'zgartirish haqida muhokama oching.

## 📜 Litsenziya

MIT License
