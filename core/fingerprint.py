"""
Browser Fingerprint Engine - 浏览器指纹管理
解决Python请求JA3/JA4指纹与真实浏览器不一致的问题
"""
import random
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger("strixpro.fingerprint")

# 真实浏览器指纹数据库
BROWSER_FINGERPRINTS = {
    "chrome_131": {
        "name": "Chrome 131",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br",
        "tls": {
            "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513-2570,29-23-24,0",
            "signature_algorithms": "ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha384,rsa_pkcs1_sha384,rsa_pss_rsae_sha512,rsa_pkcs1_sha512,rsa_pkcs1_sha1",
            "supported_groups": "X25519,secp256r1,secp384r1",
        },
    },
    "chrome_130": {
        "name": "Chrome 130",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="130", "Chromium";v="130", "Not_A Brand";v="24"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br",
        "tls": {
            "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513-2570,29-23-24,0",
            "signature_algorithms": "ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha384,rsa_pkcs1_sha384,rsa_pss_rsae_sha512,rsa_pkcs1_sha512,rsa_pkcs1_sha1",
            "supported_groups": "X25519,secp256r1,secp384r1",
        },
    },
    "firefox_133": {
        "name": "Firefox 133",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "sec_ch_ua": "",
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "accept_language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
        "accept_encoding": "gzip, deflate, br",
        "tls": {
            "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49200-49196-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-17513-2570-21,29-23-24,0",
            "signature_algorithms": "ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha384,rsa_pkcs1_sha384,rsa_pss_rsae_sha512,rsa_pkcs1_sha512,rsa_pkcs1_sha1",
            "supported_groups": "X25519,secp256r1,secp384r1",
        },
    },
    "edge_131": {
        "name": "Edge 131",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br",
        "tls": {
            "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513-2570,29-23-24,0",
            "signature_algorithms": "ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha384,rsa_pkcs1_sha384,rsa_pss_rsae_sha512,rsa_pkcs1_sha512,rsa_pkcs1_sha1",
            "supported_groups": "X25519,secp256r1,secp384r1",
        },
    },
    "safari_17": {
        "name": "Safari 17",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "sec_ch_ua": "",
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br",
        "tls": {
            "ja3": "771,4865-4866-4867-49196-49200-52393-52392-49195-49199-158-159-49171-49172-51-57-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513-2570,29-23-24,0",
            "signature_algorithms": "ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256,ecdsa_secp384r1_sha384,rsa_pss_rsae_sha384,rsa_pkcs1_sha384",
            "supported_groups": "X25519,secp256r1,secp384r1",
        },
    },
}


@dataclass
class FingerprintProfile:
    """完整的浏览器指纹配置"""
    name: str
    ua: str
    sec_ch_ua: str
    sec_ch_ua_mobile: str
    sec_ch_ua_platform: str
    accept_language: str
    accept_encoding: str
    tls: Dict[str, str]

    def to_headers(self) -> Dict[str, str]:
        """生成完整的请求头，确保一致性"""
        headers = {
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": self.accept_language,
            "Accept-Encoding": self.accept_encoding,
        }
        if self.sec_ch_ua:
            headers["Sec-Ch-Ua"] = self.sec_ch_ua
        if self.sec_ch_ua_mobile:
            headers["Sec-Ch-Ua-Mobile"] = self.sec_ch_ua_mobile
        if self.sec_ch_ua_platform:
            headers["Sec-Ch-Ua-Platform"] = self.sec_ch_ua_platform
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "none"
        headers["Sec-Fetch-User"] = "?1"
        headers["Upgrade-Insecure-Requests"] = "1"
        return headers

    def to_curl_cffi_session(self):
        """返回curl_cffi的session配置"""
        try:
            from curl_cffi import requests as curl_req
            browser_map = {
                "chrome_131": "chrome131",
                "chrome_130": "chrome130",
                "firefox_133": "firefox133",
                "edge_131": "edge131",
                "safari_17": "safari17",
            }
            return {
                "session": curl_req.Session(),
                "impersonate": browser_map.get(self.name.lower().replace(" ", "_"), "chrome131"),
            }
        except ImportError:
            logger.warning("curl_cffi not installed, falling back to requests")
            return None


class FingerprintManager:
    """指纹管理器 - 管理浏览器指纹的获取、轮换和使用"""

    def __init__(self):
        self._profiles = {}
        for key, data in BROWSER_FINGERPRINTS.items():
            self._profiles[key] = FingerprintProfile(**data)
        self._current = None

    def get(self, name: str = "") -> FingerprintProfile:
        """获取指定指纹，不指定则返回Chrome 131"""
        if name and name in self._profiles:
            return self._profiles[name]
        return self._profiles.get(name, self._profiles["chrome_131"])

    def random(self) -> FingerprintProfile:
        """随机返回一个浏览器指纹"""
        return random.choice(list(self._profiles.values()))

    def rotate(self) -> FingerprintProfile:
        """轮换指纹 - 每次调用返回不同的指纹"""
        keys = list(self._profiles.keys())
        if self._current and len(keys) > 1:
            others = [k for k in keys if k != self._current]
            self._current = random.choice(others)
        else:
            self._current = random.choice(keys)
        return self._profiles[self._current]

    def list_profiles(self) -> list:
        """列出所有可用指纹"""
        return [{"id": k, "name": v.name} for k, v in self._profiles.items()]

    def get_vipertls_config(self, profile: str = "") -> dict:
        """获取vipertls库的配置"""
        fp = self.get(profile)
        return {
            "ja3": fp.tls.get("ja3", ""),
            "headers": fp.to_headers(),
        }


# 全局单例
manager = FingerprintManager()
