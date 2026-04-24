import aiosqlite
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

DB_PATH = "database.db"

# Global connection to avoid opening/closing constantly
_db: Optional[aiosqlite.Connection] = None

async def get_db() -> aiosqlite.Connection:
    global _db
    if _db is None:
        _db = await aiosqlite.connect(DB_PATH)
        # Enable write-ahead logging for better concurrency
        await _db.execute("PRAGMA journal_mode=WAL;")
    return _db

async def init_db():
    try:
        db = await get_db()
        await db.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                report_text TEXT,
                query_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        await db.execute('''
            CREATE TABLE IF NOT EXISTS user_stats (
                user_id INTEGER PRIMARY KEY,
                total_scans INTEGER DEFAULT 0,
                url_scans INTEGER DEFAULT 0,
                file_scans INTEGER DEFAULT 0,
                pdf_scans INTEGER DEFAULT 0,
                docx_scans INTEGER DEFAULT 0,
                apk_scans INTEGER DEFAULT 0,
                video_scans INTEGER DEFAULT 0,
                image_scans INTEGER DEFAULT 0,
                archive_scans INTEGER DEFAULT 0,
                js_scans INTEGER DEFAULT 0,
                email_checks INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0,
                safe_found INTEGER DEFAULT 0,
                first_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        await db.execute('''
            CREATE TABLE IF NOT EXISTS global_stats (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_scans INTEGER DEFAULT 0,
                total_users INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0
            )
        ''')
        
        # Initialize global stats row if it doesn't exist
        await db.execute('''
            INSERT OR IGNORE INTO global_stats (id, total_scans, total_users, threats_found)
            VALUES (1, 0, 0, 0)
        ''')
        
        await db.commit()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

async def close_db():
    global _db
    if _db is not None:
        await _db.close()
        _db = None

async def save_report(user_id: int, report_text: str, query_data: str = "") -> int:
    try:
        db = await get_db()
        cursor = await db.execute(
            "INSERT INTO reports (user_id, report_text, query_data) VALUES (?, ?, ?)",
            (user_id, report_text, query_data)
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        logger.error(f"Error saving report: {e}")
        return 0

async def get_report(report_id: int) -> Optional[tuple]:
    try:
        db = await get_db()
        async with db.execute(
            "SELECT report_text, query_data FROM reports WHERE id = ?",
            (report_id,)
        ) as cursor:
            return await cursor.fetchone()
    except Exception as e:
        logger.error(f"Error getting report: {e}")
        return None

async def get_last_report(user_id: int) -> Optional[str]:
    try:
        db = await get_db()
        async with db.execute(
            "SELECT report_text FROM reports WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None
    except Exception as e:
        logger.error(f"Error getting last report: {e}")
        return None

# --- STATS FUNCTIONS ---

async def update_stats(user_id: int, scan_type: str, score: int):
    try:
        db = await get_db()
        
        # Check if user exists
        async with db.execute("SELECT 1 FROM user_stats WHERE user_id = ?", (user_id,)) as cursor:
            user_exists = await cursor.fetchone() is not None
            
        if not user_exists:
            await db.execute("INSERT INTO user_stats (user_id) VALUES (?)", (user_id,))
            await db.execute("UPDATE global_stats SET total_users = total_users + 1 WHERE id = 1")
            
        type_col_map = {
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
        
        type_col = type_col_map.get(scan_type, "file_scans")
        file_scan_increment = 0 if scan_type in ("URL", "Email") else 1
        
        safe_increment = 1 if score >= 75 else 0
        threat_increment = 1 if score < 45 else 0
        
        query = f'''
            UPDATE user_stats 
            SET total_scans = total_scans + 1,
                {type_col} = {type_col} + 1,
                file_scans = file_scans + {file_scan_increment},
                safe_found = safe_found + {safe_increment},
                threats_found = threats_found + {threat_increment},
                last_scan = CURRENT_TIMESTAMP
            WHERE user_id = ?
        '''
        await db.execute(query, (user_id,))
        
        await db.execute(f'''
            UPDATE global_stats 
            SET total_scans = total_scans + 1,
                threats_found = threats_found + {threat_increment}
            WHERE id = 1
        ''')
        
        await db.commit()
    except Exception as e:
        logger.error(f"Error updating stats: {e}")

async def get_user_stats(user_id: int) -> Optional[Dict[str, Any]]:
    try:
        db = await get_db()
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM user_stats WHERE user_id = ?", (user_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    except Exception as e:
        logger.error(f"Error getting user stats: {e}")
        return None
    finally:
        db.row_factory = None

async def get_global_stats() -> Dict[str, int]:
    try:
        db = await get_db()
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM global_stats WHERE id = 1") as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return {"total_scans": 0, "total_users": 0, "threats_found": 0}
    except Exception as e:
        logger.error(f"Error getting global stats: {e}")
        return {"total_scans": 0, "total_users": 0, "threats_found": 0}
    finally:
        db.row_factory = None
