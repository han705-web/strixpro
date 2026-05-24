# StrixPro 🛡️

> AI驱动的自动化安全测试平台 | Automated Security Testing Platform

[![License](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![Version](https://img.shields.io/badge/Version-1.0.0-green)]()

---

## 📋 概述

**StrixPro** 是一个面向安全研究人员的综合安全测试平台，解决了渗透测试中的三个核心痛点：

1. **浏览器指纹绕过** — Python请求的JA3/JA4指纹与真实浏览器完全不同，容易被安全设备识别
2. **WAF绕过** — 自动生成编码混淆的绕过payload，支持多种编码方式随机组合
3. **JS Bundle深度分析** — 从JavaScript包中自动提取API端点、硬编码凭证、隐藏路由

### 为什么选择 StrixPro？

| 功能 | StrixPro | Burp Suite | 传统脚本 |
|------|----------|------------|---------|
| 浏览器指纹轮换 | ✅ 内置 | ❌ 需要插件 | ❌ 手动实现 |
| WAF绕过引擎 | ✅ 智能生成 | ⚠️ 需扩展 | ⚠️ 手动拼凑 |
| JS敏感信息扫描 | ✅ 深度分析 | ⚠️ 需插件 | ✅ 可写 |
| 中文报告 | ✅ 原生支持 | ❌ 英文 | ⚠️ 需自定义 |
| 插件系统 | ✅ 可扩展 | ✅ 有 | ❌ 无 |
| Web API | ✅ FastAPI | ❌ 无 | ❌ 无 |
| 定价 | **免费/¥199起** | $449/年 | 时间成本 |

---

## 🚀 快速开始

### 一键安装

```bash
pip install strixpro

# 初始化工作目录
strixpro init

# 查看帮助
strixpro --help
```

### 从源码安装

```bash
git clone https://github.com/strixpro/strixpro.git
cd strixpro
pip install -e .
```

### Docker 部署

```bash
docker run -p 8765:8765 strixpro/strixpro:latest
```

---

## 💻 命令行使用

### 基础命令

```bash
# 查看系统信息
strixpro info

# 列出可用指纹
strixpro fingerprint list

# 查看指纹详情
strixpro fingerprint show chrome_131
```

### WAF绕过Payload生成

```bash
# 生成XSS绕过payload
strixpro waf generate --type xss --count 20

# 生成SQL注入绕过payload并保存
strixpro waf generate --type sqli --count 50 -o payloads.txt
```

### JS Bundle分析

```bash
# 分析单个JS文件
strixpro js analyze ./static/js/app.bundle.js

# 从URL获取并分析
strixpro js analyze https://example.com/js/app.js --base-url https://example.com

# 扫描目录下所有JS文件
strixpro js analyze ./webapp/static/
```

### 目标扫描

```bash
# 快速扫描（安全头部+CORS）
strixpro scan quick https://target.com --check-headers --check-cors

# 全面安全审计
strixpro audit https://target.com -o report.md
```

---

## 🌐 Web服务

启动Web服务后，通过浏览器访问:

```bash
strixpro serve --port 8765
```

API文档: http://localhost:8765/docs

### API示例

```bash
# 获取浏览器指纹
curl http://localhost:8765/api/v1/fingerprints

# 生成WAF绕过payload
curl -X POST http://localhost:8765/api/v1/waf/bypass \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "xss", "count": 10}'

# 分析JS代码
curl -X POST http://localhost:8765/api/v1/js/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "var apiKey = \"sk-1234567890abcdef\";"}'
```

---

## 🧩 插件开发

创建一个插件只需继承 `BasePlugin`:

```python
# plugins/my_plugin.py
from core.plugin_system import BasePlugin

class MyScanner(BasePlugin):
    name = "my-scanner"
    version = "1.0.0"
    description = "自定义扫描插件"
    plugin_type = "scanner"

    def initialize(self) -> bool:
        print(f"插件 {self.name} 加载中...")
        return True

    def scan(self, url: str) -> dict:
        # 自定义扫描逻辑
        return {"url": url, "result": "ok"}
```

---

## 📊 许可与定价

| 版本 | 价格 | 功能 |
|------|------|------|
| **社区版** | **免费** | 基础扫描、指纹管理、WAF绕过、JS分析 |
| **专业版** | **¥199/年** | 全部功能 + AI引擎 + 高级API扫描 + Web服务 |
| **企业版** | **¥1,999/年** | 全部功能 + 团队协作 + SAML + 审计日志 + 定制插件 |

### 激活专业版

```bash
strixpro license activate STRIXPRO-XXXX-XXXX-XXXX
```

---

## 🤝 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

---

## 📄 许可证

本项目采用 AGPL-3.0 许可证。详情见 [LICENSE](LICENSE) 文件。

商业许可证请联系: team@strixpro.dev

---

## ⚠️ 免责声明

本工具仅用于授权的安全测试和教育目的。使用者需遵守当地法律法规，对违规使用造成的后果自行承担责任。

---

**StrixPro** — 让安全测试更高效 🔒
