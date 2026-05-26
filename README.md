<p align="center">
  <img src="https://img.shields.io/badge/StrixPro-v1.0.0-06b6d4?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/github/license/han705-web/strixpro?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/github/actions/workflow/status/han705-web/strixpro/ci.yml?style=for-the-badge" alt="CI">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge" alt="Python">
</p>

# StrixPro — AI 驱动的自动化 Web 安全测试平台

StrixPro 是一款开源的 Web 安全测试平台，集成**浏览器指纹模拟、WAF 绕过、JS 资产分析、API 安全扫描、智能报告生成**等核心功能，帮助安全研究人员和渗透测试人员自动化重复性工作。

## 功能特性

### 浏览器指纹引擎
- 5 种浏览器指纹（Chrome/Firefox/Safari/Edge/随机）
- 12 个自定义 HTTP Header
- JA3 TLS 指纹伪造
- 自动轮换绕过基于指纹的检测

### WAF 绕过引擎
- 11 种编码方式：URL、Unicode、双重编码、Base64、HEX、注释污染、大小写混合、换行注入、通配符、参数污染、分块传输
- 7 种攻击类型：SQLi、XSS、Command Injection、SSRF、LFI、XXE、NoSQLi
- 自动组合多层 bypass chain

### JS 资产分析
- 提取 API 端点、路径参数
- 检测 10+ 种敏感信息（AccessKey、JWT、OSS 域名、内网 IP 等）
- 自动分类和优先级排序

### API 安全扫描
- 认证鉴权绕过测试
- 参数注入（SQL/NoSQL/Command）
- 速率限制测试
- GraphQL introspection + 深度查询

### 报告系统
- Markdown / HTML / JSON 格式
- 漏洞优先级排序和修复建议
- 一键生成

## 快速开始

### 在线体验（无需安装）
访问 [StrixPro 在线 Demo](https://occurred-hear-cycling-craps.trycloudflare.com)

### 下载独立 exe
从 [GitHub Releases](https://github.com/han705-web/strixpro/releases) 下载 29MB 独立 exe，解压即用。

### pip 安装
```bash
pip install strixpro
```

### 源码运行
```bash
git clone https://github.com/han705-web/strixpro.git
cd strixpro
pip install -r requirements.txt
python -m uvicorn web.app:app --host 0.0.0.0 --port 8769
```

## CLI 使用

```bash
# 查看帮助
strixpro --help

# 信息搜集
strixpro info https://example.com

# WAF 绕过测试
strixpro waf --url https://example.com --type xss

# JS 分析
strixpro js --url https://example.com

# 全面扫描
strixpro scan --url https://example.com

# 启动 Web 界面
strixpro serve
```

## 项目结构

```
strixpro/
├── web/          # FastAPI Web 服务（24 个页面）
├── core/         # 核心引擎（指纹/WAF/扫描/JS分析）
├── pro/          # Pro 版功能（AI分析/API扫描/授权）
├── cli/          # Click 命令行工具
├── deploy/       # Docker 部署
├── scripts/      # 运维脚本
└── dist/         # 构建产物
```

## 定价

| 版本 | 价格 | 功能 |
|------|------|------|
| Community | 免费 | 开源核心功能 |
| Pro | ¥199/年 | AI分析 + API深度扫描 + 优先支持 |
| Enterprise | ¥1999/年 | 私有化部署 + 定制开发 |

## 许可证

AGPL-3.0 License
