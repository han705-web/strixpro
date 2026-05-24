"""
API Scanner - 专项API安全扫描器
支持REST/GraphQL/gRPC API安全测试
"""
import json
import time
import random
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, quote

logger = logging.getLogger("strixpro.pro.api_scanner")


class APIScanner:
    """API安全扫描器"""

    def __init__(self, scanner):
        self.scanner = scanner

    def scan_endpoint(self, method: str, url: str, headers: Dict = None, body: Any = None) -> List[Dict]:
        """全面扫描单个API端点"""
        findings = []

        # 1. HTTP方法测试
        findings.extend(self._test_http_methods(url, headers))

        # 2. 认证绕过测试
        findings.extend(self._test_auth_bypass(url, headers))

        # 3. 参数注入测试
        findings.extend(self._test_parameter_injection(method, url, headers, body))

        # 4. Content-Type绕过
        findings.extend(self._test_content_type_bypass(url, headers, body))

        # 5. 速率限制测试
        findings.extend(self._test_rate_limit(url, headers))

        return findings

    def _test_http_methods(self, url: str, headers: Dict = None) -> List[Dict]:
        """测试HTTP方法是否过度开放"""
        findings = []
        methods = ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"]

        for method in methods:
            resp = self.scanner.request(method, url, headers=headers or {})
            if resp and resp.status_code not in (403, 405, 404, 400):
                findings.append({
                    "title": f"HTTP方法过度开放: {method}",
                    "type": "http_method",
                    "severity": "medium",
                    "target": url,
                    "evidence": f"方法 {method} 返回 {resp.status_code}",
                })

        return findings

    def _test_auth_bypass(self, url: str, headers: Dict = None) -> List[Dict]:
        """测试认证绕过"""
        findings = []
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Origin-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"Authorization": "Bearer admin"},
            {"Authorization": "Bearer root"},
            {"Cookie": "admin=true"},
            {"X-Role": "admin"},
        ]

        # First get baseline
        baseline = self.scanner.get(url, headers=headers or {})
        baseline_status = baseline.status_code if baseline else 0

        for bypass in bypass_headers:
            combined = {**(headers or {}), **bypass}
            resp = self.scanner.get(url, headers=combined)
            if resp and resp.status_code != baseline_status and resp.status_code < 400:
                findings.append({
                    "title": "认证绕过可能",
                    "type": "auth_bypass",
                    "severity": "critical",
                    "target": url,
                    "evidence": f"使用 {list(bypass.keys())[0]}: {list(bypass.values())[0]} 返回 {resp.status_code}（基线: {baseline_status}）",
                })

        return findings

    def _test_parameter_injection(self, method: str, url: str, headers: Dict = None, body: Any = None) -> List[Dict]:
        """测试参数注入"""
        findings = []
        test_payloads = ["'", "\"", "../../etc/passwd", "{{7*7}}", "${7*7}", "<script>", "true", "1=1"]

        for payload in test_payloads:
            test_url = f"{url}?id={quote(payload)}&q={quote(payload)}"
            resp = self.scanner.get(test_url, headers=headers or {})
            if resp:
                body_lower = (resp.text or "").lower()
                if any(err in body_lower for err in ["sql syntax", "stack trace", "unexpected"]):
                    findings.append({
                        "title": "参数注入可能",
                        "type": "injection",
                        "severity": "high",
                        "target": url,
                        "evidence": f"Payload: {payload} → 状态码: {resp.status_code}",
                    })
                    break

        return findings

    def _test_content_type_bypass(self, url: str, headers: Dict = None, body: Any = None) -> List[Dict]:
        """测试Content-Type绕过"""
        findings = []
        content_types = [
            "application/x-www-form-urlencoded",
            "application/json",
            "application/xml",
            "text/plain",
            "multipart/form-data; boundary=----test",
        ]

        for ct in content_types:
            test_headers = {**(headers or {}), "Content-Type": ct}
            resp = self.scanner.post(url, headers=test_headers, data='{"test":"test"}')
            if resp and resp.status_code not in (400, 415, 404):
                if resp.status_code < 500:
                    findings.append({
                        "title": "Content-Type绕过",
                        "type": "content_type_bypass",
                        "severity": "low",
                        "target": url,
                        "evidence": f"Content-Type: {ct} → {resp.status_code}",
                    })

        return findings

    def _test_rate_limit(self, url: str, headers: Dict = None) -> List[Dict]:
        """测试速率限制"""
        findings = []
        statuses = []

        for i in range(20):
            resp = self.scanner.get(url, headers=headers or {})
            if resp:
                statuses.append(resp.status_code)
                if resp.status_code in (429, 503):
                    break
            time.sleep(0.1)

        # Check if all requests succeeded (no rate limiting)
        if len(statuses) >= 10 and all(s == statuses[0] for s in statuses):
            findings.append({
                "title": "缺少速率限制",
                "type": "rate_limiting",
                "severity": "medium",
                "target": url,
                "evidence": f"{len(statuses)} 次连续请求均成功（状态码: {statuses[0]}），无速率限制",
            })

        return findings

    def scan_graphql(self, url: str) -> List[Dict]:
        """扫描GraphQL端点"""
        findings = []

        # Introspection query
        introspection = """{"query":"query { __schema { types { name fields { name } } } }"}"""
        headers = {"Content-Type": "application/json"}

        resp = self.scanner.post(url, headers=headers, data=introspection)
        if resp and resp.status_code == 200 and "__schema" in (resp.text or ""):
            findings.append({
                "title": "GraphQL Introspection 未禁用",
                "type": "graphql_introspection",
                "severity": "high",
                "target": url,
                "evidence": "Schema introspection query returned schema data",
            })

        return findings
