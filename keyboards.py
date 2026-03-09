from aiogram.types import (
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    ReplyKeyboardMarkup,
    KeyboardButton,
)
from urllib.parse import quote


def get_main_menu() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [
                KeyboardButton(text="🔍 URL Tekshirish"),
                KeyboardButton(text="📎 Fayl Yuborish"),
            ],
            [
                KeyboardButton(text="📊 Oxirgi Hisobot"),
                KeyboardButton(text="📖 Yordam"),
            ],
        ],
        resize_keyboard=True,
        input_field_placeholder="URL yuboring yoki fayl biriktiring...",
    )


def get_url_check_keyboard(url: str) -> InlineKeyboardMarkup:
    encoded = quote(url, safe='')
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🔬 VirusTotal",
                    url=f"https://www.virustotal.com/gui/search/{encoded}",
                ),
                InlineKeyboardButton(
                    text="🔍 URLScan.io",
                    url=f"https://urlscan.io/search/#{url}",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="🛡️ Google Safe Browsing",
                    url=f"https://transparencyreport.google.com/safe-browsing/search?url={encoded}",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="🔄 Qayta tekshirish",
                    callback_data=f"rescan_url:{url[:60]}",
                ),
            ],
        ]
    )


def get_file_check_keyboard(file_hash: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="🔬 VirusTotal (Hash)",
                    url=f"https://www.virustotal.com/gui/file/{file_hash}",
                ),
            ],
            [
                InlineKeyboardButton(
                    text="📋 To'liq hisobot",
                    callback_data=f"full_report:{file_hash[:60]}",
                ),
            ],
        ]
    )
