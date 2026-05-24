"""
Scanner Engine - 核心扫描引擎
整合指纹、WAF绕过、请求发送于一体
"""
import json
import time
import random
import logging
import requests
from typing import Optional, Dict, Any, List, Callable, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

logger = logging.getLogger("strixpro.scanner")


@dataclass
class ScanResult:
    """扫描结果"""
    target: str
    status_code: int = 0
    headers: Dict = field(default_factory=dict)
    body: str = ""
    elapsed: float = 0.0
    error: str = ""
    payload: str = ""
    payload_type: str = ""
    vulnerability: str = ""
    severity: str = "info"
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "status_code": self.status_code,
            "elapsed": round(self.elapsed, 3),
            "error": self.error,
            "payload_type": self.payload_type,
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "evidence": self.evidence[:500] if self.evidence else "",
        }


class Scanner:
    """多功能扫描器"""

    def __init__(self, config=None):
        from .config import StrixProConfig
        self.config = config or StrixProConfig.load()
        self.session = None
        self._init_session()

    def _init_session(self):
        """初始化HTTP会话"""
        try:
            from curl_cffi import requests as curl_req
            self._use_curl = True
            self.session = curl_req.Session()
            logger.info("Using curl_cffi for HTTP requests (JA3 spoofing enabled)")
        except ImportError:
            self._use_curl = False
            self.session = requests.Session()
            self.session.verify = False
            logger.info("Using requests library (JA3 signature will be detected)")

    def _get_headers(self, url: str = "") -> dict:
        """获取带浏览器指纹的请求头"""
        from .fingerprint import manager
        profile = manager.rotate() if self.config.fingerprint.rotate_per_request else manager.get(self.config.fingerprint.browser)
        return profile.to_headers()

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """发送请求（自动处理指纹）"""
        headers = kwargs.pop("headers", {})
        fp_headers = self._get_headers(url)
        fp_headers.update(headers)
        kwargs["headers"] = fp_headers

        kwargs.setdefault("timeout", self.config.scan.timeout)
        kwargs.setdefault("allow_redirects", self.config.scan.follow_redirects)
        kwargs.setdefault("verify", self.config.scan.verify_ssl)

        for attempt in range(self.config.scan.max_retries):
            try:
                resp = self.session.request(method, url, **kwargs)
                # 随机延迟模拟人类行为
                if attempt < self.config.scan.max_retries - 1:
                    delay = random.uniform(self.config.scan.delay_min, self.config.scan.delay_max)
                    time.sleep(delay)
                return resp
            except Exception as e:
                logger.warning(f"Request failed (attempt {attempt+1}/{self.config.scan.max_retries}): {e}")
                if attempt == self.config.scan.max_retries - 1:
                    return None
                time.sleep(2 ** attempt)  # 指数退避

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def check_security_headers(self, url: str) -> Dict:
        """检查安全头部"""
        resp = self.get(url)
        if not resp:
            return {"error": "Failed to reach target", "url": url}

        headers_to_check = {
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "Content-Security-Policy": [],
            "Strict-Transport-Security": [],
            "X-Content-Type-Options": ["nosniff"],
            "X-XSS-Protection": ["1; mode=block"],
            "Referrer-Policy": [],
            "Permissions-Policy": [],
        }

        results = {"url": url, "status": resp.status_code, "headers": {}}
        for header, expected_values in headers_to_check.items():
            value = resp.headers.get(header, "")
            if not value:
                results["headers"][header] = {
                    "present": False,
                    "value": "",
                    "severity": "medium",
                    "note": f"Missing {header} header",
                }
            elif expected_values and value not in expected_values:
                results["headers"][header] = {
                    "present": True,
                    "value": value,
                    "severity": "low",
                    "note": f"Should be one of: {', '.join(expected_values)}",
                }
            else:
                results["headers"][header] = {
                    "present": True,
                    "value": value,
                    "severity": "info",
                    "note": "OK",
                }

        return results

    def check_cors(self, url: str) -> Dict:
        """检查CORS配置"""
        results = {"url": url, "findings": []}

        # 测试Origin反射
        test_origins = [
            "https://evil.com",
            "null",
            "https://evil.com.evil.com",
            "https://evil",
        ]

        for origin in test_origins:
            resp = self.get(url, headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == origin or acao == "*":
                finding = {
                    "origin": origin,
                    "acao": acao,
                    "credentials": acac == "true",
                    "severity": "critical" if acac == "true" else "high",
                }
                results["findings"].append(finding)

        return results

    def concurrent_scan(self, targets: List[str], worker_fn: Callable, max_workers: int = 10) -> List[Any]:
        """并发扫描多个目标"""
        results = []
        max_workers = min(max_workers, self.config.scan.max_concurrent)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(worker_fn, target): target for target in targets}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append({"error": str(e), "target": futures[future]})

        return results
