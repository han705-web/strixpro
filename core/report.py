"""
Report Generator - 智能报告生成器
支持Markdown/HTML/JSON格式，中文优先
"""
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger("strixpro.report")


class ReportGenerator:
    """报告生成器"""

    def __init__(self, language: str = "zh", output_dir: str = "./output"):
        self.language = language
        self.output_dir = Path(output_dir)

    def generate(self, data: Dict, fmt: str = "markdown") -> str:
        """生成报告"""
        generators = {
            "markdown": self._to_markdown,
            "html": self._to_html,
            "json": self._to_json,
        }
        generator = generators.get(fmt, self._to_markdown)
        return generator(data)

    def save(self, data: Dict, fmt: str = "markdown", filename: str = "") -> str:
        """生成并保存报告"""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"strixpro_report_{timestamp}"

        ext_map = {"markdown": "md", "html": "html", "json": "json"}
        ext = ext_map.get(fmt, "md")
        filepath = self.output_dir / f"{filename}.{ext}"

        content = self.generate(data, fmt)
        filepath.write_text(content, encoding="utf-8")
        logger.info(f"Report saved: {filepath}")
        return str(filepath)

    def _to_markdown(self, data: Dict) -> str:
        """生成Markdown格式报告（中文）"""
        lines = []
        lines.append(f"# 安全测试报告\n")
        lines.append(f"**生成时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        lines.append(f"**工具:** StrixPro v1.0.0\n")
        lines.append(f"**语言:** {'中文' if self.language == 'zh' else 'English'}\n")

        if "target" in data:
            lines.append(f"\n## 目标信息\n")
            lines.append(f"- **目标:** {data['target']}")
            if "targets" in data:
                lines.append(f"- **子目标数:** {len(data['targets'])}")

        if "summary" in data:
            s = data["summary"]
            lines.append(f"\n## 执行摘要\n")
            lines.append(f"本次测试共发现 **{s.get('total_findings', 0)}** 个安全问题，其中:")
            severity_map = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
            for sev, count in s.get("severity_counts", {}).items():
                cn_name = severity_map.get(sev, sev)
                lines.append(f"- **{cn_name}:** {count} 个")

        if "vulnerabilities" in data:
            lines.append(f"\n## 漏洞详情\n")
            for i, vuln in enumerate(data["vulnerabilities"], 1):
                severity = vuln.get("severity", "info")
                lines.append(f"- **严重性:** {severity}")
                lines.append(f"- **类型:** {vuln.get('type', 'N/A')}")
                lines.append(f"- **目标:** {vuln.get('target', 'N/A')}")
                if "description" in vuln:
                    lines.append(f"\n**描述:**\n{vuln['description']}")
                if "evidence" in vuln:
                    lines.append(f"\n**证据:**\n```\n{vuln['evidence']}\n```")
                if "remediation" in vuln:
                    lines.append(f"\n**修复建议:**\n{vuln['remediation']}")

        if "security_headers" in data:
            lines.append(f"\n## 安全头部审计\n")
            lines.append(f"| 头部 | 状态 | 值 |")
            lines.append(f"|------|------|-----|")
            for header, info in data["security_headers"].items():
                status = "缺失" if not info.get("present") else info.get('value', '存在')
                lines.append(f"| {header} | {'MISSING' if not info.get('present') else 'OK'} | {status} |")

        if "api_endpoints" in data:
            lines.append(f"\n## 发现的API端点\n")
            for ep in data["api_endpoints"]:
                lines.append(f"- `{ep}`")

        if "secrets" in data:
            lines.append(f"\n## 发现的敏感信息\n")
            for secret in data["secrets"]:
                lines.append(f"- **{secret.get('type', 'unknown')}:** `{secret.get('value', '')}`")
                if "context" in secret:
                    lines.append(f"  - 上下文: `{secret['context']}`")

        lines.append(f"\n---\n")
        lines.append(f"*本报告由 StrixPro 自动生成 | StrixPro - AI驱动的安全测试平台*\n")

        return "\n".join(lines)

    def _to_html(self, data: Dict) -> str:
        """生成HTML格式报告"""
        md_content = self._to_markdown(data)

        html = f"""<!DOCTYPE html>
<html lang="{self.language}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全测试报告</title>
    <style>
        body {{ font-family: -apple-system, 'Microsoft YaHei', sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        h3 {{ color: #0f3460; }}
        pre {{ background: #f8f9fa; padding: 12px; border-radius: 4px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background: #16213e; color: white; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .info {{ color: #6c757d; }}
        .footer {{ text-align: center; color: #999; margin-top: 40px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        {self._md_to_simple_html(md_content)}
        <div class="footer">
            <p>由 StrixPro 自动生成 | StrixPro - AI驱动的安全测试平台</p>
        </div>
    </div>
</body>
</html>"""
        return html

    def _md_to_simple_html(self, md: str) -> str:
        """简单的MD到HTML转换"""
        import html as html_mod
        lines = md.split("\n")
        result = []
        in_code_block = False
        code_content = []

        for line in lines:
            if line.startswith("```"):
                if in_code_block:
                    result.append(f"<pre><code>{html_mod.escape('\n'.join(code_content))}</code></pre>")
                    code_content = []
                in_code_block = not in_code_block
                continue
            if in_code_block:
                code_content.append(line)
                continue

            if line.startswith("# "):
                result.append(f"<h1>{html_mod.escape(line[2:])}</h1>")
            elif line.startswith("## "):
                result.append(f"<h2>{html_mod.escape(line[3:])}</h2>")
            elif line.startswith("### "):
                result.append(f"<h3>{html_mod.escape(line[4:])}</h3>")
            elif line.startswith("| "):
                result.append(f"<div>{html_mod.escape(line)}</div>")
            elif line.startswith("- ") or line.startswith("  - "):
                result.append(f"<li>{html_mod.escape(line.lstrip('- '))}</li>")
            elif line.startswith("**"):
                result.append(f"<p>{html_mod.escape(line)}</p>")
            elif line.strip():
                result.append(f"<p>{html_mod.escape(line)}</p>")
            else:
                result.append("<br>")

        return "\n".join(result)

    def _to_json(self, data: Dict) -> str:
        """生成JSON格式报告"""
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "StrixPro v1.0.0",
                "language": self.language,
            },
            **data
        }
        return json.dumps(report, ensure_ascii=False, indent=2, default=str)
