import ssl
import socket
import logging
import asyncio
import aiohttp
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
]


async def check_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    result = {
        "valid": False,
        "issuer": "",
        "subject": "",
        "expires": "",
        "days_left": 0,
        "details": [],
        "warnings": [],
        "score_impact": 0,
    }

    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _get_cert():
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert()

        cert = await loop.run_in_executor(None, _get_cert)

        if cert:
            result["valid"] = True

            subject = dict(x[0] for x in cert.get('subject', []))
            issuer = dict(x[0] for x in cert.get('issuer', []))

            result["subject"] = subject.get('commonName', '')
            result["issuer"] = issuer.get('organizationName', issuer.get('commonName', ''))

            not_after = cert.get('notAfter', '')
            if not_after:
                expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_date - datetime.utcnow()).days
                result["expires"] = expire_date.strftime('%Y-%m-%d')
                result["days_left"] = days_left

                if days_left < 0:
                    result["warnings"].append("🔴 SSL sertifikat muddati o'tgan!")
                    result["score_impact"] = -25
                elif days_left < 7:
                    result["warnings"].append(f"⚠️ SSL {days_left} kunda tugaydi")
                    result["score_impact"] = -10
                elif days_left < 30:
                    result["warnings"].append(f"⚠️ SSL {days_left} kunda tugaydi")
                    result["score_impact"] = -5
                else:
                    result["details"].append(f"✅ SSL sertifikat: {days_left} kun qoldi")

                result["details"].append(f"🔐 Beruvchi: {result['issuer']}")
        else:
            result["warnings"].append("⚠️ SSL sertifikat olinmadi")
            result["score_impact"] = -15

    except ssl.SSLCertVerificationError as e:
        result["warnings"].append(f"🔴 SSL sertifikat noto'g'ri: {str(e)[:60]}")
        result["score_impact"] = -20
    except (socket.timeout, socket.error):
        result["warnings"].append("⚠️ SSL tekshiruv: Ulanib bo'lmadi")
        result["score_impact"] = -5
    except Exception as e:
        logger.error("SSL tekshiruv xatosi: %s", e)
        result["warnings"].append("⚠️ SSL tekshiruvda xato")
        result["score_impact"] = -5

    return result


async def check_http_headers(url: str) -> Dict[str, Any]:
    result = {
        "headers_found": [],
        "headers_missing": [],
        "server": "",
        "details": [],
        "warnings": [],
        "score_impact": 0,
    }

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.head(url, allow_redirects=True, ssl=False) as resp:
                headers = resp.headers

                result["server"] = headers.get('Server', 'Noma\'lum')

                for header in SECURITY_HEADERS:
                    if header in headers:
                        result["headers_found"].append(header)
                    else:
                        result["headers_missing"].append(header)

                found = len(result["headers_found"])
                total = len(SECURITY_HEADERS)

                if found >= 5:
                    result["details"].append(f"✅ Xavfsizlik headerlari: {found}/{total}")
                elif found >= 3:
                    result["warnings"].append(f"⚠️ Xavfsizlik headerlari: {found}/{total}")
                    result["score_impact"] = -5
                else:
                    result["warnings"].append(f"⚠️ Kam headerlar: {found}/{total}")
                    result["score_impact"] = -10

                if 'X-Powered-By' in headers:
                    result["warnings"].append(
                        f"⚠️ Server texnologiyasi ochiq: {headers['X-Powered-By']}"
                    )
                    result["score_impact"] -= 3

                if result["server"] and result["server"] != "Noma'lum":
                    result["details"].append(f"🖥️ Server: {result['server']}")

    except asyncio.TimeoutError:
        result["warnings"].append("⚠️ Server javob bermadi (timeout)")
        result["score_impact"] = -5
    except Exception as e:
        logger.error("Header tekshiruv xatosi: %s", e)
        result["warnings"].append("⚠️ Header tekshiruvda xato")

    return result


async def check_redirect_chain(url: str) -> Dict[str, Any]:
    result = {
        "chain": [],
        "final_url": url,
        "redirect_count": 0,
        "details": [],
        "warnings": [],
        "score_impact": 0,
    }

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, allow_redirects=False, ssl=False) as resp:
                chain = [url]
                current_url = url
                count = 0

                while resp.status in (301, 302, 303, 307, 308) and count < 10:
                    location = resp.headers.get('Location', '')
                    if not location:
                        break
                    if not location.startswith('http'):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    chain.append(location)
                    current_url = location
                    count += 1
                    async with session.get(current_url, allow_redirects=False, ssl=False) as resp:
                        pass

                result["chain"] = chain
                result["final_url"] = current_url
                result["redirect_count"] = count

                if count == 0:
                    result["details"].append("✅ Redirect: Yo'q")
                elif count <= 2:
                    result["details"].append(f"🔄 Redirect: {count} ta")
                elif count <= 5:
                    result["warnings"].append(f"⚠️ Ko'p redirect: {count} ta")
                    result["score_impact"] = -5
                else:
                    result["warnings"].append(f"🔴 Juda ko'p redirect: {count} ta")
                    result["score_impact"] = -15

                if count > 0:
                    orig_domain = urlparse(url).hostname
                    final_domain = urlparse(current_url).hostname
                    if orig_domain != final_domain:
                        result["warnings"].append(
                            f"⚠️ Boshqa domenga yo'naltirish: {final_domain}"
                        )
                        result["score_impact"] -= 10

    except asyncio.TimeoutError:
        result["warnings"].append("⚠️ Redirect tekshiruv: timeout")
    except Exception as e:
        logger.error("Redirect tekshiruv xatosi: %s", e)
        result["warnings"].append("⚠️ Redirect tekshiruvda xato")

    return result


async def check_page_title(url: str) -> Dict[str, Any]:
    result = {
        "title": "",
        "title_mismatch": False,
        "details": [],
        "warnings": [],
        "score_impact": 0,
    }

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text(errors='ignore')
                    import re
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        title = title_match.group(1).strip()[:100]
                        result["title"] = title
                        result["details"].append(f"📄 Sahifa nomi: {title[:50]}")

                        domain = urlparse(url).hostname or ""
                        root = domain.split('.')[-2] if len(domain.split('.')) >= 2 else domain

                        phishing_brands = [
                            'paypal', 'facebook', 'google', 'apple', 'microsoft',
                            'amazon', 'netflix', 'instagram', 'twitter', 'linkedin',
                            'bank', 'whatsapp', 'telegram', 'binance', 'coinbase',
                        ]

                        title_lower = title.lower()
                        for brand in phishing_brands:
                            if brand in title_lower and brand not in domain.lower():
                                result["title_mismatch"] = True
                                result["warnings"].append(
                                    f"🔴 Sahifa nomi aldov: '{brand}' sahifada bor, lekin domen boshqa!"
                                )
                                result["score_impact"] -= 25
                                break
                    else:
                        result["details"].append("📄 Sahifa nomi: Topilmadi")
                else:
                    result["warnings"].append(f"⚠️ Sahifa javob: HTTP {resp.status}")

    except asyncio.TimeoutError:
        result["warnings"].append("⚠️ Sahifa yuklash: timeout")
    except Exception as e:
        logger.error("Page title xatosi: %s", e)

    return result


async def check_html_trackers(url: str) -> Dict[str, Any]:
    result = {
        "trackers_found": [],
        "details": [],
        "warnings": [],
        "score_impact": 0,
    }

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text(errors='ignore')
                    lower_text = text.lower()
                    
                    trackers = {
                        "Google Analytics": ["google-analytics.com", "gtag("],
                        "Facebook Pixel": ["fbevents.js", "fbq("],
                        "Yandex Metrika": ["mc.yandex.ru", "ym("],
                        "Hotjar": ["static.hotjar.com"],
                        "Mixpanel": ["cdn.mxpnl.com"],
                        "Segment": ["cdn.segment.com"],
                        "Clarity": ["clarity.ms"],
                        "TikTok Pixel": ["analytics.tiktok.com"]
                    }
                    
                    for name, patterns in trackers.items():
                        if any(p in lower_text for p in patterns):
                            result["trackers_found"].append(name)
                            
                    if result["trackers_found"]:
                        count = len(result["trackers_found"])
                        result["details"].append(f"👁️ Trackerlar: {count} ta topildi ({', '.join(result['trackers_found'][:3])})")
                        if count > 3:
                            result["warnings"].append(f"⚠️ Haddan ziyod trackerlar ({count} ta). Maxfiylik xavfi.")
                            result["score_impact"] -= 5
                    else:
                        result["details"].append("✅ Trackerlar: Topilmadi")
                        
    except asyncio.TimeoutError:
        result["warnings"].append("⚠️ HTML Tracker tahlili: timeout")
    except Exception as e:
        logger.error("HTML tracker xatosi: %s", e)

    return result

def check_dns_records(domain: str) -> Dict[str, Any]:
    result = {
        "records": {},
        "details": [],
        "warnings": [],
        "score_impact": 0,
    }

    if not HAS_DNS:
        result["warnings"].append("⚠️ dnspython o'rnatilmagan — DNS tekshiruv cheklangan")
        return result

    try:
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            ips = [r.to_text() for r in a_records]
            result["records"]["A"] = ips
            result["details"].append(f"✅ A record: {', '.join(ips[:3])}")
        except Exception:
            result["warnings"].append("⚠️ A record topilmadi")
            result["score_impact"] -= 5

        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mxs = [r.exchange.to_text() for r in mx_records]
            result["records"]["MX"] = mxs
            result["details"].append(f"📧 MX record: {len(mxs)} ta")
        except Exception:
            pass

        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            nss = [r.to_text() for r in ns_records]
            result["records"]["NS"] = nss
            result["details"].append(f"🌐 NS record: {len(nss)} ta")
        except Exception:
            pass

        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            txts = [r.to_text() for r in txt_records]
            result["records"]["TXT"] = txts
            has_spf = any('spf' in t.lower() for t in txts)
            has_dmarc = any('dmarc' in t.lower() for t in txts)
            if has_spf:
                result["details"].append("✅ SPF: Mavjud")
            if has_dmarc:
                result["details"].append("✅ DMARC: Mavjud")
        except Exception:
            pass

    except Exception as e:
        logger.error("DNS tekshiruv xatosi: %s", e)
        result["warnings"].append("⚠️ DNS tekshiruvda xato")

    return result


def check_whois(domain: str) -> Dict[str, Any]:
    result = {
        "registrar": "",
        "creation_date": "",
        "expiration_date": "",
        "domain_age_days": 0,
        "details": [],
        "warnings": [],
        "score_impact": 0,
    }

    if not HAS_WHOIS:
        result["warnings"].append("⚠️ python-whois o'rnatilmagan — WHOIS cheklangan")
        return result

    try:
        w = whois.whois(domain)

        if w.registrar:
            result["registrar"] = str(w.registrar)
            result["details"].append(f"🏢 Registrar: {result['registrar'][:40]}")

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            result["creation_date"] = str(creation)
            age_days = (datetime.now() - creation).days
            result["domain_age_days"] = age_days

            if age_days < 7:
                result["warnings"].append(f"🔴 Domen juda yangi: {age_days} kun (xavfli!)")
                result["score_impact"] = -25
            elif age_days < 30:
                result["warnings"].append(f"⚠️ Domen yangi: {age_days} kun")
                result["score_impact"] = -15
            elif age_days < 90:
                result["warnings"].append(f"⚠️ Domen yosh: {age_days} kun")
                result["score_impact"] = -5
            else:
                years = age_days // 365
                result["details"].append(f"✅ Domen yoshi: {years} yil {age_days % 365} kun")

        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        if expiration:
            result["expiration_date"] = str(expiration)
            exp_days = (expiration - datetime.now()).days
            if exp_days < 30:
                result["warnings"].append(f"⚠️ Domen tez tugaydi: {exp_days} kun qoldi")

    except Exception as e:
        logger.error("WHOIS xatosi: %s", e)
        result["warnings"].append("⚠️ WHOIS ma'lumot olinmadi")

    return result


async def deep_url_check(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    domain = parsed.hostname or ""

    results = {
        "ssl": {},
        "headers": {},
        "redirects": {},
        "page_title": {},
        "trackers": {},
        "dns": {},
        "whois": {},
        "all_details": [],
        "all_warnings": [],
        "total_score_impact": 0,
    }

    ssl_task = check_ssl_certificate(domain) if parsed.scheme == 'https' else None
    headers_task = check_http_headers(url)
    redirects_task = check_redirect_chain(url)
    title_task = check_page_title(url)
    trackers_task = check_html_trackers(url)

    tasks = []
    task_names = []

    if ssl_task:
        tasks.append(ssl_task)
        task_names.append("ssl")
    tasks.append(headers_task)
    task_names.append("headers")
    tasks.append(redirects_task)
    task_names.append("redirects")
    tasks.append(title_task)
    task_names.append("page_title")
    tasks.append(trackers_task)
    task_names.append("trackers")

    completed = await asyncio.gather(*tasks, return_exceptions=True)

    for name, res in zip(task_names, completed):
        if isinstance(res, Exception):
            logger.error("Deep check %s xatosi: %s", name, res)
            continue
        results[name] = res
        results["all_details"].extend(res.get("details", []))
        results["all_warnings"].extend(res.get("warnings", []))
        results["total_score_impact"] += res.get("score_impact", 0)

    loop = asyncio.get_event_loop()
    try:
        dns_result = await loop.run_in_executor(None, check_dns_records, domain)
        results["dns"] = dns_result
        results["all_details"].extend(dns_result.get("details", []))
        results["all_warnings"].extend(dns_result.get("warnings", []))
        results["total_score_impact"] += dns_result.get("score_impact", 0)
    except Exception as e:
        logger.error("DNS xatosi: %s", e)

    try:
        whois_result = await loop.run_in_executor(None, check_whois, domain)
        results["whois"] = whois_result
        results["all_details"].extend(whois_result.get("details", []))
        results["all_warnings"].extend(whois_result.get("warnings", []))
        results["total_score_impact"] += whois_result.get("score_impact", 0)
    except Exception as e:
        logger.error("WHOIS xatosi: %s", e)

    return results
