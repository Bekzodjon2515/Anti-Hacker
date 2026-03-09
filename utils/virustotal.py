import logging
import aiohttp
import asyncio
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    async def check_url(self, url: str) -> Dict[str, Any]:
        result = {
            "detected": False,
            "positives": 0,
            "total": 0,
            "details": [],
            "warnings": [],
            "score_impact": 0,
        }

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

                async with session.get(
                    f"{VT_API_BASE}/urls/{url_id}",
                    headers=self.headers,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        undetected = stats.get("undetected", 0)
                        harmless = stats.get("harmless", 0)
                        total = malicious + suspicious + undetected + harmless

                        result["positives"] = malicious + suspicious
                        result["total"] = total
                        result["detected"] = malicious > 0

                        if malicious > 5:
                            result["warnings"].append(
                                f"🔴 VirusTotal: {malicious}/{total} dvigatel xavfli deb topdi!"
                            )
                            result["score_impact"] = -30
                        elif malicious > 0:
                            result["warnings"].append(
                                f"⚠️ VirusTotal: {malicious}/{total} dvigatel shubhali"
                            )
                            result["score_impact"] = -15
                        elif suspicious > 0:
                            result["warnings"].append(
                                f"⚠️ VirusTotal: {suspicious} ta shubhali natija"
                            )
                            result["score_impact"] = -5
                        else:
                            result["details"].append(f"✅ VirusTotal: Toza ({total} dvigatel)")

                    elif resp.status == 404:
                        result["details"].append("ℹ️ VirusTotal: URL hali tekshirilmagan")
                    else:
                        result["warnings"].append(f"⚠️ VirusTotal API: HTTP {resp.status}")

        except asyncio.TimeoutError:
            result["warnings"].append("⚠️ VirusTotal: timeout")
        except Exception as e:
            logger.error("VirusTotal xatosi: %s", e)
            result["warnings"].append("⚠️ VirusTotal tekshiruvda xato")

        return result

    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        result = {
            "detected": False,
            "positives": 0,
            "total": 0,
            "details": [],
            "warnings": [],
            "score_impact": 0,
        }

        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    f"{VT_API_BASE}/files/{file_hash}",
                    headers=self.headers,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        undetected = stats.get("undetected", 0)
                        harmless = stats.get("harmless", 0)
                        total = malicious + suspicious + undetected + harmless

                        result["positives"] = malicious + suspicious
                        result["total"] = total
                        result["detected"] = malicious > 0

                        if malicious > 5:
                            result["warnings"].append(
                                f"🔴 VirusTotal: {malicious}/{total} dvigatel zararli!"
                            )
                            result["score_impact"] = -30
                        elif malicious > 0:
                            result["warnings"].append(
                                f"⚠️ VirusTotal: {malicious}/{total} dvigatel shubhali"
                            )
                            result["score_impact"] = -15
                        else:
                            result["details"].append(f"✅ VirusTotal: Toza ({total} dvigatel)")

                    elif resp.status == 404:
                        result["details"].append("ℹ️ VirusTotal: Fayl hali tekshirilmagan")
                    else:
                        result["warnings"].append(f"⚠️ VirusTotal API: HTTP {resp.status}")

        except asyncio.TimeoutError:
            result["warnings"].append("⚠️ VirusTotal: timeout")
        except Exception as e:
            logger.error("VirusTotal fayl xatosi: %s", e)
            result["warnings"].append("⚠️ VirusTotal tekshiruvda xato")

        return result


def get_vt_checker() -> Optional[VirusTotalChecker]:
    from config import VT_API_KEY
    if VT_API_KEY:
        return VirusTotalChecker(VT_API_KEY)
    return None
