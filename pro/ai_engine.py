"""
AI Engine - AI增强检测引擎
利用AI能力提升漏洞检测准确率、降低误报
"""
import json
import logging
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger("strixpro.pro.ai_engine")


class AIAnalysisEngine:
    """AI分析引擎 - 增强漏洞检测"""

    def __init__(self, ai_provider: str = "builtin"):
        self.provider = ai_provider
        self.ai_func: Optional[Callable] = None

    def analyze_response(self, url: str, response_data: Dict) -> Dict:
        """分析响应是否存在漏洞特征"""
        findings = []

        # Rule-based pre-filtering
        body = response_data.get("body", "")
        headers = response_data.get("headers", {})
        status = response_data.get("status_code", 0)

        checks = [
            ("SQL Error", self._check_sql_error(body)),
            ("XSS Reflection", self._check_xss_reflection(body)),
            ("Path Disclosure", self._check_path_disclosure(body)),
            ("Stack Trace", self._check_stack_trace(body)),
            ("Server Info", self._check_server_info(headers)),
            ("Default Creds", self._check_default_creds(body)),
            ("Debug Enabled", self._check_debug(body)),
        ]

        for check_name, result in checks:
            if result:
                findings.append({"type": check_name, "evidence": result})

        return {
            "url": url,
            "status": status,
            "findings": findings,
            "risk_score": len(findings) * 10,
        }

    def prioritize_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """自动优先排序漏洞"""
        severity_weights = {"critical": 100, "high": 60, "medium": 30, "low": 10}

        scored = []
        for v in vulns:
            base = severity_weights.get(v.get("severity", "low"), 5)
            # Bonus for exploitable findings
            if v.get("has_public_exploit"):
                base += 20
            if v.get("requires_auth", False) == False:
                base += 10
            if v.get("has_evidence"):
                base += 15
            scored.append({"score": base, **v})

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    def generate_remediation(self, vuln_type: str, context: Dict = None) -> str:
        """生成修复建议"""
        remediation_map = {
            "SQL Error": self._remediate_sqli,
            "XSS Reflection": self._remediate_xss,
            "CORS": self._remediate_cors,
            "Missing Security Headers": self._remediate_headers,
            "Sensitive Data": self._remediate_secrets,
        }
        func = remediation_map.get(vuln_type)
        if func:
            return func(context or {})
        return "请参考OWASP官方修复指南"

    def _check_sql_error(self, body: str) -> str:
        sql_errors = [
            "SQL syntax", "MySQL", "ORA-", "PostgreSQL", "SQLite",
            "Unclosed quotation mark", "ODBC SQL Server Driver",
            "Microsoft OLE DB", "mysql_fetch", "pg_query",
        ]
        for err in sql_errors:
            if err.lower() in body.lower():
                return f"SQL错误信息泄露: {err}"
        return ""

    def _check_xss_reflection(self, body: str) -> str:
        xss_patterns = ["<script>", "alert(", "onerror=", "onload="]
        for pat in xss_patterns:
            if pat.lower() in body.lower():
                return f"XSS反射可能: 检测到 {pat}"
        return ""

    def _check_path_disclosure(self, body: str) -> str:
        paths = ["root:", "www-data", "www/site", "DocumentRoot", "SERVER_SIGNATURE"]
        for p in paths:
            if p.lower() in body.lower():
                return f"路径泄露: {p}"
        return ""

    def _check_stack_trace(self, body: str) -> str:
        trace_patterns = ["Traceback", "at line", "in <module>", "Stack Trace", "System.Exception"]
        for pat in trace_patterns:
            if pat.lower() in body.lower():
                return "堆栈跟踪信息泄露"
        return ""

    def _check_server_info(self, headers: Dict) -> str:
        info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-version"]
        leaks = []
        for h in info_headers:
            val = headers.get(h, "")
            if val and val not in ("", "nginx", "Apache"):
                leaks.append(f"{h}: {val}")
        return "; ".join(leaks) if leaks else ""

    def _check_default_creds(self, body: str) -> str:
        creds = ["admin/admin", "root/root", "test/test", "admin/password"]
        for c in creds:
            if c.lower() in body.lower():
                return f"默认凭据可能: {c}"
        return ""

    def _check_debug(self, body: str) -> str:
        debug_patterns = ["debug=True", "DEBUG=1", "app.debug", "X-Debug"]
        for pat in debug_patterns:
            if pat.lower() in body.lower():
                return "调试模式可能开启"
        return ""

    def _remediate_sqli(self, ctx: Dict) -> str:
        return """1. 使用参数化查询（Prepared Statements）替代字符串拼接
2. 对用户输入进行严格的类型验证和白名单过滤
3. 最小化数据库权限，使用独立的只读账户
4. 关闭数据库错误详情展示"""

    def _remediate_xss(self, ctx: Dict) -> str:
        return """1. 对输出进行HTML实体编码（使用OWASP Java Encoder或类似库）
2. 实施Content-Security-Policy（CSP）策略
3. 对用户输入进行输入验证和过滤
4. 使用HttpOnly和Secure标记Cookie"""

    def _remediate_cors(self, ctx: Dict) -> str:
        return """1. 避免使用Access-Control-Allow-Origin: *
2. 验证Origin头部的白名单
3. 避免在Access-Control-Allow-Credentials: true时使用通配符Origin
4. 严格限制允许的HTTP方法和头部"""

    def _remediate_headers(self, ctx: Dict) -> str:
        return """1. 添加X-Frame-Options: DENY/SAMEORIGIN
2. 添加Strict-Transport-Security: max-age=31536000
3. 添加X-Content-Type-Options: nosniff
4. 实施Content-Security-Policy策略"""

    def _remediate_secrets(self, ctx: Dict) -> str:
        return """1. 立即轮换已泄露的凭证和API密钥
2. 使用环境变量或密钥管理服务（Vault/KMS）管理敏感信息
3. 在CI/CD流程中增加密钥扫描步骤
4. 禁用前端调试模式和错误详情"""
