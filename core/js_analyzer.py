"""
JS Bundle Analyzer - JavaScript Bundle深度分析
自动挖掘API端点、硬编码凭证、隐藏路由
"""
import re
import json
import gzip
import logging
from pathlib import Path
from typing import List, Dict, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("strixpro.js_analyzer")

# 敏感信息正则
PATTERNS = {
    "api_key": [
        r'(?i)(?:api[_-]?key|apikey|api_key)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,})',
    ],
    "access_key": [
        r'(?i)(?:access[_-]?key|accesskey|access_key)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:AKIA[0-9A-Z]{16})',
    ],
    "secret_key": [
        r'(?i)(?:secret[_-]?key|secretkey|secret_key)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:secret[_-]?token|secret)\s*[=:]\s*["\']([^"\']+)["\']',
    ],
    "jwt_token": [
        r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
    ],
    "password": [
        r'(?i)(?:password|pwd|passwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
    ],
    "oauth_client": [
        r'(?i)(?:client[_-]?id|client_id|clientid)\s*[=:]\s*["\']([^"\']+)["\']',
        r'(?i)(?:client[_-]?secret|client_secret)\s*[=:]\s*["\']([^"\']+)["\']',
    ],
    "auth_token": [
        r'(?i)(?:token|bearer|authorization)\s*[=:]\s*["\']([^"\']{10,})["\']',
    ],
    "endpoint": [
        r'(?i)(?:https?://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?::\d+)?(?:/[^\s"\'<>{}|^`\\\[\]]*)?)',
    ],
    "internal_ip": [
        r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})',
        r'(?:192\.168\.\d{1,3}\.\d{1,3})',
        r'(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    ],
    "route": [
        r'(?i)(?:path|route|endpoint|api)\s*[=:]\s*["\']([/][^"\']+)["\']',
        r'(?i)(?:router\.(?:get|post|put|delete|patch|options))\s*[(]\s*["\']([^"\']+)["\']',
    ],
    "s3_bucket": [
        r'(?i)(?:[a-z0-9.-]+\.s3\.amazonaws\.com)',
        r'(?i)(?:s3://[a-z0-9.-]+)',
    ],
    "cloud_service": [
        r'(?i)(?:[a-z0-9-]+\.oss-cn-[a-z0-9-]+\.aliyuncs\.com)',
        r'(?i)(?:[a-z0-9-]+\.cos\.[a-z0-9-]+\.myqcloud\.com)',
    ],
}


class JSBundleAnalyzer:
    """JavaScript Bundle深度分析器"""

    def __init__(self):
        self.findings: Dict[str, List[Dict]] = {}
        self._api_endpoints: Set[str] = set()
        self._sensitive_data: List[Dict] = []

    def analyze_file(self, file_path: str) -> Dict:
        """分析单个JS文件"""
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {file_path}"}

        content = self._read_file(path)
        if not content:
            return {"error": f"Could not read file: {file_path}"}

        return self._analyze_content(content, str(path))

    def analyze_text(self, content: str, source: str = "inline") -> Dict:
        """分析JS文本内容"""
        return self._analyze_content(content, source)

    def _analyze_content(self, content: str, source: str) -> Dict:
        """核心分析逻辑"""
        result = {
            "source": source,
            "size": len(content),
            "findings": {},
            "api_endpoints": [],
            "sensitive_data": [],
            "routes": [],
            "summary": {},
        }

        for category, patterns in PATTERNS.items():
            matches = []
            for pattern in patterns:
                try:
                    for m in re.finditer(pattern, content):
                        value = m.group(0) if m.lastindex is None else m.group(1)
                        position = m.start()
                        matches.append({
                            "value": value[:200],  # 截断过长的值
                            "position": position,
                            "context": self._get_context(content, position, 50),
                        })
                except re.error as e:
                    logger.warning(f"Regex error for pattern {category}: {e}")

            if matches:
                result["findings"][category] = matches
                # 归类
                if category in ("endpoint", "route"):
                    for m in matches:
                        val = m["value"]
                        if val.startswith("http"):
                            result["api_endpoints"].append(val)
                        elif val.startswith("/"):
                            result["routes"].append(val)
                else:
                    result["sensitive_data"].extend(matches)

        result["summary"] = {
            "total_findings": sum(len(v) for v in result["findings"].values()),
            "categories_found": list(result["findings"].keys()),
            "endpoint_count": len(result["api_endpoints"]),
            "secrets_count": len(result["sensitive_data"]),
        }

        self.findings[source] = result
        self._api_endpoints.update(result["api_endpoints"])
        self._sensitive_data.extend(result["sensitive_data"])

        return result

    def analyze_bundle(self, js_content: str, base_url: str = "") -> Dict:
        """增强分析：反混淆+端点提取"""
        result = self._analyze_content(js_content, "bundle")
        endpoints = result["api_endpoints"]

        # 补全相对路径
        if base_url:
            resolved = []
            for ep in endpoints:
                if ep.startswith("/"):
                    resolved.append(urljoin(base_url, ep))
                else:
                    resolved.append(ep)
            result["api_endpoints"] = resolved

        # 查找潜在的路由配置
        route_patterns = [
            r'(?:path|url|to|uri)[:=]\s*["\']([^"\']+)["\']',
            r'(?:routes|router)\s*[:=]\s*(\[[^\]]+\])',
        ]
        for pat in route_patterns:
            try:
                for m in re.finditer(pat, js_content):
                    result["routes"].append(m.group(1)[:200])
            except re.error:
                continue

        return result

    def extract_api_structure(self, js_content: str) -> List[Dict]:
        """尝试重构API结构（路径参数、方法等）"""
        apis = []
        # 匹配常见的API定义模式: this.$http.get('/api/...')
        patterns = [
            r'(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'(?:axios|fetch|ajax|request|http)\s*\.\s*(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']\s*,\s*method\s*:\s*["\'](\w+)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, js_content, re.IGNORECASE):
                groups = m.groups()
                if len(groups) >= 2:
                    method = groups[0].upper()
                    path = groups[1]
                    apis.append({"method": method, "path": path, "source": "pattern_match"})

        return apis

    def scan_directory(self, dir_path: str, recursive: bool = True) -> List[Dict]:
        """扫描目录下所有JS文件"""
        path = Path(dir_path)
        if not path.is_dir():
            return [{"error": f"Not a directory: {dir_path}"}]

        results = []
        glob_pattern = "**/*.js" if recursive else "*.js"
        for js_file in path.glob(glob_pattern):
            logger.info(f"Analyzing: {js_file}")
            result = self.analyze_file(str(js_file))
            results.append(result)
        return results

    def _read_file(self, path: Path) -> Optional[str]:
        """读取文件，支持解压"""
        try:
            # Try gzip first
            with gzip.open(path, "rt", errors="ignore") as f:
                return f.read()
        except Exception:
            try:
                with open(path, "r", errors="ignore") as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Error reading {path}: {e}")
                return None

    def _get_context(self, content: str, position: int, window: int = 50) -> str:
        """获取匹配位置的上下文"""
        start = max(0, position - window)
        end = min(len(content), position + window)
        ctx = content[start:end]
        if start > 0:
            ctx = "..." + ctx
        if end < len(content):
            ctx = ctx + "..."
        return ctx

    def report(self) -> Dict:
        """生成汇总报告"""
        return {
            "total_files_analyzed": len(self.findings),
            "unique_endpoints": sorted(self._api_endpoints),
            "unique_secrets": len(self._sensitive_data),
            "findings_by_file": {k: v["summary"] for k, v in self.findings.items()},
        }
