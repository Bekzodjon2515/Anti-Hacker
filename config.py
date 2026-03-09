import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("API")
VT_API_KEY = os.getenv("VT_API_KEY")

MAX_FILE_SIZE = 200 * 1024 * 1024

RATE_LIMIT = 5
RATE_WINDOW = 60

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.xyz', '.top', '.pw', '.cc', '.buzz',
    '.club', '.work', '.date', '.racing',
    '.download', '.stream', '.bid', '.win',
    '.review', '.accountant', '.science',
]

PHISHING_KEYWORDS = [
    'login', 'verify', 'secure', 'bank', 'paypal',
    'account', 'update', 'confirm', 'password', 'signin',
    'billing', 'suspend', 'unlock', 'restore', 'validate',
    'authenticate', 'credential', 'identity', 'ssn', 'social-security',
    'wallet', 'crypto', 'binance', 'coinbase', 'metamask',
]

SUSPICIOUS_PERMISSIONS = [
    'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
    'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
    'READ_CONTACTS', 'CAMERA',
    'PROCESS_OUTGOING_CALLS', 'READ_CALL_LOG',
    'WRITE_EXTERNAL_STORAGE', 'INSTALL_PACKAGES',
    'READ_PHONE_STATE', 'RECEIVE_BOOT_COMPLETED',
    'SYSTEM_ALERT_WINDOW', 'BIND_DEVICE_ADMIN',
    'BIND_ACCESSIBILITY_SERVICE',
]

SUPPORTED_EXTENSIONS = {
    'pdf':   ['.pdf'],
    'word':  ['.doc', '.docx'],
    'apk':   ['.apk'],
    'video': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm'],
    'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'],
    'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
    'js':    ['.js'],
}

TEMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp_files')
os.makedirs(TEMP_DIR, exist_ok=True)

SUSPICIOUS_VIDEO_PATTERNS = [
    'crack', 'hack', 'keygen', 'patch', 'loader',
    'activator', 'free_premium', 'cheat', 'exploit',
    'brute', 'leaked', 'private_video', 'hidden_cam',
]

LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
