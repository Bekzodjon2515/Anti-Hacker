import logging
from typing import Optional, Dict, Any

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text, Table, Column, Integer, String, MetaData, select, update, insert

from config import DATABASE_URL

logger = logging.getLogger(__name__)

# Create SQLAlchemy async engine
engine = create_async_engine(DATABASE_URL, echo=False)

metadata = MetaData()

# Define tables using SQLAlchemy Core
reports_table = Table(
    "reports",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer),
    Column("report_text", String(10000)),
    Column("query_data", String(1000)),
    Column("created_at", String(100), server_default=text("CURRENT_TIMESTAMP"))
)

user_stats_table = Table(
    "user_stats",
    metadata,
    Column("user_id", Integer, primary_key=True),
    Column("total_scans", Integer, default=0),
    Column("url_scans", Integer, default=0),
    Column("file_scans", Integer, default=0),
    Column("pdf_scans", Integer, default=0),
    Column("docx_scans", Integer, default=0),
    Column("apk_scans", Integer, default=0),
    Column("video_scans", Integer, default=0),
    Column("image_scans", Integer, default=0),
    Column("archive_scans", Integer, default=0),
    Column("js_scans", Integer, default=0),
    Column("email_checks", Integer, default=0),
    Column("threats_found", Integer, default=0),
    Column("safe_found", Integer, default=0),
    Column("first_scan", String(100), server_default=text("CURRENT_TIMESTAMP")),
    Column("last_scan", String(100), server_default=text("CURRENT_TIMESTAMP"))
)

global_stats_table = Table(
    "global_stats",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("total_scans", Integer, default=0),
    Column("total_users", Integer, default=0),
    Column("threats_found", Integer, default=0)
)

async def init_db():
    try:
        async with engine.begin() as conn:
            # Create all tables
            await conn.run_sync(metadata.create_all)
            
            # Ensure global_stats row exists
            result = await conn.execute(select(global_stats_table).where(global_stats_table.c.id == 1))
            if not result.first():
                await conn.execute(insert(global_stats_table).values(id=1, total_scans=0, total_users=0, threats_found=0))
                
        logger.info("Database initialized successfully with SQLAlchemy.")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

async def close_db():
    await engine.dispose()

async def save_report(user_id: int, report_text: str, query_data: str = "") -> int:
    try:
        async with engine.begin() as conn:
            result = await conn.execute(
                insert(reports_table).values(
                    user_id=user_id,
                    report_text=report_text,
                    query_data=query_data
                )
            )
            return result.lastrowid
    except Exception as e:
        logger.error(f"Error saving report: {e}")
        return 0

async def get_report(report_id: int) -> Optional[tuple]:
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                select(reports_table.c.report_text, reports_table.c.query_data)
                .where(reports_table.c.id == report_id)
            )
            return result.fetchone()
    except Exception as e:
        logger.error(f"Error getting report: {e}")
        return None

async def get_last_report(user_id: int) -> Optional[str]:
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                select(reports_table.c.report_text)
                .where(reports_table.c.user_id == user_id)
                .order_by(reports_table.c.id.desc())
                .limit(1)
            )
            row = result.fetchone()
            return row[0] if row else None
    except Exception as e:
        logger.error(f"Error getting last report: {e}")
        return None

# --- STATS FUNCTIONS ---

async def update_stats(user_id: int, scan_type: str, score: int):
    try:
        async with engine.begin() as conn:
            # Check if user exists
            result = await conn.execute(select(user_stats_table.c.user_id).where(user_stats_table.c.user_id == user_id))
            user_exists = result.first() is not None
            
            if not user_exists:
                await conn.execute(insert(user_stats_table).values(user_id=user_id))
                await conn.execute(
                    update(global_stats_table)
                    .where(global_stats_table.c.id == 1)
                    .values(total_users=global_stats_table.c.total_users + 1)
                )
                
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
            
            # Use raw SQL string with mapped column for dynamic column update
            # SQLAlchemy text() safely handles this if we bind parameters, but using core updates is better:
            
            update_values = {
                "total_scans": user_stats_table.c.total_scans + 1,
                type_col: getattr(user_stats_table.c, type_col) + 1,
                "file_scans": user_stats_table.c.file_scans + file_scan_increment,
                "safe_found": user_stats_table.c.safe_found + safe_increment,
                "threats_found": user_stats_table.c.threats_found + threat_increment,
                "last_scan": text("CURRENT_TIMESTAMP")
            }
            
            await conn.execute(
                update(user_stats_table)
                .where(user_stats_table.c.user_id == user_id)
                .values(**update_values)
            )
            
            await conn.execute(
                update(global_stats_table)
                .where(global_stats_table.c.id == 1)
                .values(
                    total_scans=global_stats_table.c.total_scans + 1,
                    threats_found=global_stats_table.c.threats_found + threat_increment
                )
            )
    except Exception as e:
        logger.error(f"Error updating stats: {e}")

async def get_user_stats(user_id: int) -> Optional[Dict[str, Any]]:
    try:
        async with engine.connect() as conn:
            result = await conn.execute(select(user_stats_table).where(user_stats_table.c.user_id == user_id))
            row = result.fetchone()
            if row:
                return dict(row._mapping)
            return None
    except Exception as e:
        logger.error(f"Error getting user stats: {e}")
        return None

async def get_global_stats() -> Dict[str, int]:
    try:
        async with engine.connect() as conn:
            result = await conn.execute(select(global_stats_table).where(global_stats_table.c.id == 1))
            row = result.fetchone()
            if row:
                return dict(row._mapping)
            return {"total_scans": 0, "total_users": 0, "threats_found": 0}
    except Exception as e:
        logger.error(f"Error getting global stats: {e}")
        return {"total_scans": 0, "total_users": 0, "threats_found": 0}
