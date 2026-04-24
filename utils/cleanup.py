import os
import time
import asyncio
import logging
from config import TEMP_DIR

logger = logging.getLogger(__name__)

async def start_cleanup_task():
    """Vaqtinchalik fayllarni har soatda tozalovchi background vazifa"""
    while True:
        try:
            now = time.time()
            count = 0
            if os.path.exists(TEMP_DIR):
                for filename in os.listdir(TEMP_DIR):
                    filepath = os.path.join(TEMP_DIR, filename)
                    # Agar fayl 1 soatdan eski bo'lsa o'chiramiz
                    if os.path.isfile(filepath) and os.stat(filepath).st_mtime < now - 3600:
                        try:
                            os.remove(filepath)
                            count += 1
                        except Exception as e:
                            logger.error(f"Faylni o'chirishda xatolik: {e}")
            if count > 0:
                logger.info(f"{count} ta eski vaqtinchalik fayllar tozalandi.")
        except Exception as e:
            logger.error(f"Cleanup task xatosi: {e}")
        
        # Har 1 soatda ishlaydi (3600 sekund)
        await asyncio.sleep(3600)
