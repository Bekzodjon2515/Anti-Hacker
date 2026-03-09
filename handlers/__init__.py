from .base_handler import router as base_router
from .url_handler import router as url_router
from .pdf_handler import router as pdf_router
from .word_handler import router as word_router
from .apk_handler import router as apk_router
from .video_handler import router as video_router
from .image_handler import router as image_handler
from .archive_handler import router as archive_handler
from .js_handler import router as js_handler
from .email_handler import router as email_handler

__all__ = [
    "base_router",
    "url_router",
    "email_handler",
    "pdf_router",
    "word_router",
    "apk_router",
    "video_router",
    "image_handler",
    "archive_handler",
    "js_handler",
]
