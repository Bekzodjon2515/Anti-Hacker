import sys
sys.path.insert(0, '.')
from config import BOT_TOKEN, VT_API_KEY, GEMINI_API_KEY
from handlers import *
from utils.virustotal import get_vt_checker
from utils.ai_helper import get_ai_analysis

print("=" * 50)
print("Anti-Hacker Bot — Import Test")
print("=" * 50)
print(f"BOT_TOKEN: {'Mavjud' if BOT_TOKEN else 'YOQ!'}")
print(f"GEMINI_API_KEY: {'Mavjud' if GEMINI_API_KEY else 'YOQ!'}")
print(f"VT_API_KEY: {'Mavjud' if VT_API_KEY else 'Kalitsiz ishlaydi'}")

vt = get_vt_checker()
print(f"VT Checker: {'Faol' if vt else 'Kalitsiz (xatosiz ishlaydi)'}")
print("=" * 50)
print("Barcha importlar muvaffaqiyatli!")
print("Bot tayyor!")
