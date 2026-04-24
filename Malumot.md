# 🛡️ Anti-Hacker Bot — Max Daraja (Professional Kiberxavfsizlik Platformasi)
> **10 Yillik Tajribali Dasturchi Xulosasi va Loyiha Dokumentatsiyasi**

---

## 📋 1. Loyiha Haqida Umumiy Ma'lumot
**Anti-Hacker Bot** — bu foydalanuvchilarni internetdagi turli kiber tahdidlardan, virusli fayllardan va soxta (phishing) havolalardan himoya qilish uchun mo'ljallangan sun'iy intellektga asoslangan Telegram bot platformasi.

Hozirgi kunda Telegram orqali viruslar va firibgarlik havolalari juda tez tarqalmoqda. Bu bot huddi **cho'ntakdagi antivirus** kabi ishlaydi. 

---

## 🚀 2. Botning MAX Darajadagi Imkoniyatlari (v3.0)
Bot oddiy skanerdan professional xavfsizlik ekotizimiga aylantirilmoqda. U quyidagi MAX darajadagi imkoniyatlarga ega bo'ladi:

### 🔗 1. Deep URL Tahlili (Chuqur Havola Tekshiruvi)
Saytning faqat nomini emas, uning ichki arxitekturasini tekshiradi:
- **Phishing/Scam aniqlash:** Sayt dizayni mashhur saytlarga (masalan, Telegram, Payme, Click) o'xshatib yasalganligini tekshiradi.
- **SSL/TLS sertifikatlari:** Saytning ulanish xavfsizligini tekshiradi. Agar sertifikat muddati tugagan yoki soxta bo'lsa, bloklaydi.
- **Domain Reputation:** Sayt domeni qachon ochilganini (`WHOIS`) ko'radi. Kecha ochilgan va bugun aksiya e'lon qilgan saytlarni 99% ehtimol bilan firibgar deb topadi.
- **Redirect zanjiri:** Qisqartirilgan havolalar (bit.ly va h.k) orqasida nima yashiringanini to'liq ochib beradi.

### 📁 2. Multi-Format Fayl Antivirusi (File Scanner)
Fayllarni yuklab olib, kod darajasida (static analysis) tekshiradi:
- 📱 **APK (Android):** Ilova qanday ruxsatlar so'rayotganini tekshiradi. Agar chiroq (fonarik) ilovasi SMS va kontaktlarni o'qishga ruxsat so'rasa, bot buni darhol fosh qiladi.
- 📄 **PDF va DOCX:** Hujjat ichiga yashirilgan zararli JavaScript kodlari yoki avtomatik ishga tushadigan makroslarni aniqlaydi.
- 🎬 **Media (Video/Rasm):** Rasm (.jpg) yoki video (.mp4) formatiga yashirilgan exe viruslarni (Steganografiya) topadi.
- 📦 **Arxivlar (.zip, .rar):** Arxiv ichidagi fayllarni bittalab tekshiradi.

### 🧠 3. Sun'iy Intellekt Integratsiyasi (Google Gemini 2.0)
Natijalarni texnik tilda emas, oddiy odam tushunadigan tilda tushuntirib beradi.
- *"Bu sayt xavfsizlik sertifikatiga ega emas va kecha ochilgan. Katta ehtimol bilan bu plastik kartangiz ma'lumotlarini o'g'irlash uchun qilingan soxta sayt. Unga kirmang!"*

### 🌐 4. Inline va Guruh Rejimi (Viral O'sish)
- **Inline Mode:** Istalgan chatda (do'stingiz bilan yozishayotganda) `@AntiHackerBot https://shubhali-link.uz` deb yozib, chatdan chiqmasdan havolani tekshirishingiz mumkin.
- **Group Guard (Guruh Qorovuli):** Botni guruhga admin qilib qo'shilsa, guruhga tashlangan har bir havola va faylni sekundlar ichida tekshiradi. Xavfli bo'lsa, o'chirib tashlaydi va foydalanuvchini ogohlantiradi.

---

## 🛠️ 3. Texnik Arxitektura (10-yillik tajriba asosida)
Katta yuklamalarga (Highload) bardosh berishi uchun loyiha quyidagi texnologiyalar bilan qurollantiriladi:

1. **Aiogram 3.x (Python):** Asinxron, juda tez ishlaydigan framework. Bloklanib qolishlarsiz minglab so'rovlarni bir vaqtda bajaradi.
2. **VirusTotal API:** Dunyodagi eng kuchli 70+ ta antivirus (Kaspersky, Avast, BitDefender va h.k) bazasiga to'g'ridan-to'g'ri ulangan.
3. **Connection Pooling (Database):** SQLite + WAL rejimi yoki PostgreSQL orqali ma'lumotlar bazasiga soniyasiga 10,000+ so'rovni xatosiz yozish imkoniyati.
4. **Redis Cache:** Bir xil URL'ni qayta-qayta tekshirmaslik uchun xotira (cache) tizimi. Bu API limitlarini tejaydi va javob tezligini 0.1 soniyagacha tushiradi.

---

## 💎 4. Loyihani Biznes (Monetizatsiya) Sifatida Ko'rish

Ushbu loyiha nafaqat foydali vosita, balki katta daromad keltiradigan biznes ham bo'la oladi.

1. **Freemium Model:** Kuniga 10 ta havola bepul. Undan ko'pi uchun Premium obuna (oyiga 10,000 so'm). Premiumda:
   - Cheksiz tekshiruv
   - Real-vaqt monitoringi (Saytlar tushib qolmasligini kuzatish)
   - Fayllarni navbatsiz (birinchi bo'lib) tekshirish.
2. **API Sotish:** Boshqa botlar va saytlar sizning botingiz API'si orqali xavfsizlik tekshiruvini amalga oshiradi.
3. **Reklama:** 100 minglab foydalanuvchilar tekshiruv natijasini kutayotgan paytda xavfsiz va tekshirilgan IT-kurslar yoki xizmatlar reklamasi.

---

## 🏁 XULOSA
Anti-Hacker Bot shunchaki havola tekshiruvchi emas, u O'zbekiston va MDH davlatlari uchun **1-raqamli telegram xavfsizlik devori (Firewall)** bo'lish salohiyatiga ega. Kodning modulli yozilganligi (DRY prinsipi) va kelajakdagi CI/CD avtomatizatsiyasi loyihani to'liq Professional va Max darajadagi platforma sifatida belgilaydi.
