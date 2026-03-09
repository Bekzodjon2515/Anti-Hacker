import re
import logging
from urllib.parse import urlparse
from typing import Dict, Any, List

from config import SUSPICIOUS_TLDS, PHISHING_KEYWORDS

logger = logging.getLogger(__name__)

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'x.com', 'linkedin.com', 'reddit.com',
    'amazon.com', 'microsoft.com', 'apple.com', 'github.com',
    'stackoverflow.com', 'wikipedia.org', 'whatsapp.com',
    'telegram.org', 't.me', 'paypal.com', 'netflix.com',
    'spotify.com', 'zoom.us', 'dropbox.com', 'adobe.com',
    'wordpress.com', 'wordpress.org', 'medium.com',
    'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com',
    'mail.google.com', 'docs.google.com', 'drive.google.com',
    'outlook.com', 'live.com', 'office.com', 'office365.com',
    'yahoo.com', 'bing.com', 'duckduckgo.com',
    'twitch.tv', 'discord.com', 'slack.com',
    'ebay.com', 'aliexpress.com', 'shopify.com',
    'stripe.com', 'wise.com', 'revolut.com',
    'uz', 'gov.uz', 'my.gov.uz', 'ziyonet.uz',
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'short.link', 'cutt.ly', 'rb.gy',
    'shorturl.at', 'tiny.cc', 'bc.vc', 'v.gd', 'clck.ru',
    'qps.ru', 'u.to', 'soo.gd', 'rebrand.ly', 'bl.ink',
}


def _get_root_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def _is_trusted(domain: str) -> bool:
    root = _get_root_domain(domain)
    if root in TRUSTED_DOMAINS:
        return True
    if domain in TRUSTED_DOMAINS:
        return True
    for td in TRUSTED_DOMAINS:
        if domain.endswith('.' + td):
            return True
    return False


def _is_shortener(domain: str) -> bool:
    root = _get_root_domain(domain)
    return root in URL_SHORTENERS or domain in URL_SHORTENERS


def _has_punycode(domain: str) -> bool:
    return 'xn--' in domain.lower()


def _looks_like_typosquat(domain: str) -> bool:
    root = _get_root_domain(domain).split('.')[0]
    typo_targets = {
        'google': ['g00gle', 'gogle', 'googel', 'gooogle', 'goog1e'],
        'facebook': ['faceb00k', 'facebok', 'faceboook', 'faceb0ok'],
        'paypal': ['paypa1', 'paypall', 'paypaI', 'paipal', 'paypai'],
        'amazon': ['amaz0n', 'amazom', 'arnazon', 'amazn'],
        'microsoft': ['micros0ft', 'microsoftt', 'mircosoft'],
        'apple': ['app1e', 'appIe', 'aple'],
        'instagram': ['instagramm', 'instagran', 'instag0am'],
        'netflix': ['netf1ix', 'nettflix', 'netfiix'],
    }
    for brand, typos in typo_targets.items():
        if root in typos:
            return True
        if brand in root and root != brand:
            diff = len(root) - len(brand)
            if 1 <= diff <= 3:
                return True
    return False


def extract_urls(text: str) -> List[str]:
    url_pattern = re.compile(
        r'(?:(?:https?|ftp)://)?[\w.-]+(?:\.[\w\.-]+)+[\w\-_~:/?#[\]@!$&\'*+,;=.]+'
    )
    matches = url_pattern.findall(text)
    urls = []
    for m in matches:
        url = m.rstrip('.,;:!?)]}')
        
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
            
        urls.append(url)
    return urls


def _is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.hostname:
            return False
        if '.' not in parsed.hostname and ':' not in parsed.hostname:
            return False
        return True
    except Exception:
        return False


def analyze_url(url: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "url": url,
        "score": 100,
        "details": [],
        "warnings": [],
        "is_valid": False,
        "protocol": None,
        "domain": None,
        "is_ip": False,
        "has_ssl": False,
        "subdomain_count": 0,
        "dash_count": 0,
        "phishing_keywords_found": [],
        "suspicious_tld": False,
        "url_length": len(url),
        "is_trusted": False,
        "is_shortener": False,
    }

    if not _is_valid_url(url):
        if not url.startswith(("http://", "https://")):
            test_url = "https://" + url
            if _is_valid_url(test_url):
                url = test_url
            else:
                result["score"] = 0
                result["warnings"].append("❌ URL formati noto'g'ri")
                return result
        else:
            result["score"] = 0
            result["warnings"].append("❌ URL formati noto'g'ri")
            return result

    result["is_valid"] = True

    try:
        parsed = urlparse(url)
    except Exception:
        result["score"] = 0
        result["warnings"].append("❌ URL'ni parse qilib bo'lmadi")
        return result

    domain = parsed.hostname or ""
    result["domain"] = domain
    path = parsed.path or ""
    query = parsed.query or ""

    trusted = _is_trusted(domain)
    result["is_trusted"] = trusted

    if trusted:
        result["details"].append("✅ Ishonchli domen: Taniqli sayt")

    result["protocol"] = parsed.scheme
    if parsed.scheme == "https":
        result["has_ssl"] = True
        result["details"].append("✅ HTTPS: Mavjud")
    elif parsed.scheme == "http":
        result["has_ssl"] = False
        penalty = 5 if trusted else 15
        result["score"] -= penalty
        result["warnings"].append("⚠️ HTTP: Shifrlash yo'q (HTTPS emas)")
    else:
        result["score"] -= 20
        result["warnings"].append(f"⚠️ Notanish protokol: {parsed.scheme}")

    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(domain):
        result["is_ip"] = True
        result["score"] -= 25
        result["warnings"].append("🔴 IP manzil: Domen nomi o'rniga IP ishlatilgan")

    if _is_shortener(domain):
        result["is_shortener"] = True
        result["score"] -= 15
        result["warnings"].append(
            f"⚠️ URL qisqartiruvchi: {domain} (asl manzil yashirilgan)"
        )

    if _has_punycode(domain):
        result["score"] -= 20
        result["warnings"].append(
            "🔴 Punycode/IDN domen: Harf almashtirish hujumi (homograph)"
        )

    if _looks_like_typosquat(domain):
        result["score"] -= 25
        result["warnings"].append(
            "🔴 Typosquatting: Taniqli saytga o'xshash domen"
        )

    if not trusted:
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result["suspicious_tld"] = True
                result["score"] -= 20
                result["warnings"].append(f"⚠️ Shubhali TLD: {tld}")
                break
    else:
        result["details"].append("✅ TLD: Ishonchli")

    if not result["is_ip"]:
        parts = domain.split(".")
        subdomain_count = max(0, len(parts) - 2)
        result["subdomain_count"] = subdomain_count
        if subdomain_count > 3:
            result["score"] -= 10
            result["warnings"].append(
                f"⚠️ Ko'p subdomen: {subdomain_count} ta (shubhali)"
            )
        elif subdomain_count > 2 and not trusted:
            result["score"] -= 5
            result["warnings"].append(
                f"⚠️ Subdomen soni: {subdomain_count} ta"
            )
        else:
            result["details"].append(f"✅ Subdomen soni: {subdomain_count} (normal)")

    dash_count = domain.count("-")
    result["dash_count"] = dash_count
    if dash_count > 3:
        penalty = 15 if not trusted else 0
        if penalty:
            result["score"] -= penalty
            result["warnings"].append(
                f"⚠️ Ko'p tire: {dash_count} ta (phishing belgisi)"
            )
    elif dash_count <= 1:
        result["details"].append(f"✅ Tire soni: {dash_count} (normal)")
    else:
        if not trusted:
            result["score"] -= 5
            result["warnings"].append(f"⚠️ Tire soni: {dash_count} ta")

    if not trusted:
        check_text = domain + path.lower() + query.lower()
        root_domain_name = _get_root_domain(domain).split('.')[0]

        found_keywords = []
        for keyword in PHISHING_KEYWORDS:
            if keyword == root_domain_name:
                continue
            if keyword in check_text:
                found_keywords.append(keyword)

        result["phishing_keywords_found"] = found_keywords
        if found_keywords:
            in_domain = sum(1 for kw in found_keywords if kw in domain)
            in_path = sum(1 for kw in found_keywords if kw in path.lower())

            domain_penalty = min(in_domain * 10, 25)
            path_penalty = min(in_path * 5, 15)
            total_penalty = min(domain_penalty + path_penalty, 35)

            result["score"] -= total_penalty
            result["warnings"].append(
                f"⚠️ Phishing kalit so'zlar: {', '.join(found_keywords)}"
            )
        else:
            result["details"].append("✅ Phishing kalit so'zlar: Topilmadi")
    else:
        result["details"].append("✅ Phishing kalit so'zlar: Tekshiruv shart emas (ishonchli)")

    if len(url) > 200:
        result["score"] -= 10
        result["warnings"].append(f"⚠️ URL juda uzun: {len(url)} belgi")

    if "@" in parsed.netloc:
        result["score"] -= 25
        result["warnings"].append("🔴 @ belgisi: Credential injection xavfi")

    if url.lower().count("http") > 1:
        result["score"] -= 15
        result["warnings"].append("⚠️ Ikkilangan protokol: Redirect xavfi")

    if "data:" in url.lower():
        result["score"] -= 20
        result["warnings"].append("🔴 Data URI aniqlandi: XSS xavfi")

    if not trusted and result["suspicious_tld"] and result["phishing_keywords_found"]:
        result["score"] -= 10
        result["warnings"].append("🔴 Kombinatsiya: Shubhali TLD + phishing kalit so'zlar")

    if not trusted and dash_count > 2 and result["phishing_keywords_found"]:
        result["score"] -= 5

    result["score"] = max(0, min(100, result["score"]))

    if not result["warnings"]:
        result["details"].append("✅ Qo'shimcha xavf topilmadi")

    logger.info("URL tekshirildi: %s | Ball: %d | Ishonchli: %s",
                domain, result["score"], trusted)
    return result


def get_security_level(score: int) -> tuple:
    if score >= 75:
        return "🟢", "XAVFSIZ", "green"
    elif score >= 45:
        return "🟡", "SHUBHALI", "yellow"
    else:
        return "🔴", "XAVFLI", "red"
