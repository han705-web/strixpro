"""
StrixPro Web Service - Web服务
提供RESTful API、用户管理、支付集成、前端界面
"""
import os
import json
import time
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

logger = logging.getLogger("strixpro.web")

try:
    from fastapi import FastAPI, HTTPException, Depends, Query, Body, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse
    from fastapi.templating import Jinja2Templates
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
    import uvicorn

    FASTAPI_AVAILABLE = True

    # Setup templates
    _templates_dir = Path(__file__).parent / "templates"
    templates = Jinja2Templates(directory=str(_templates_dir))
except ImportError:
    FASTAPI_AVAILABLE = False
    templates = None
    logger.warning("FastAPI not available, web server disabled")


# ============ API Models ============

class ScanRequest(BaseModel):
    url: str
    check_headers: bool = True
    check_cors: bool = True
    js_analysis: bool = True
    depth: str = "quick"  # quick, standard, deep

class ScanResponse(BaseModel):
    task_id: str
    status: str
    message: str

class LicenseActivateRequest(BaseModel):
    license_key: str

class JSRequest(BaseModel):
    content: str
    source: str = "api"

class WAFGenerateRequest(BaseModel):
    attack_type: str = "xss"
    count: int = 10

# ============ App ============

if FASTAPI_AVAILABLE:

    app = FastAPI(
        title="StrixPro API",
        description="StrixPro - AI驱动的自动化安全测试平台",
        version="1.0.0",
    )

    # Custom 404 handler
    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # In-memory task store
    tasks = {}

    # ============ Page Routes ============

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        from core.fingerprint import manager as fp_mgr
        from core.waf_bypass import engine as waf_eng, AttackType, PAYLOAD_TEMPLATES
        from core.plugin_system import PluginManager

        stats = {
            "fingerprints": len(fp_mgr.list_profiles()),
            "waf_payloads": sum(len(t) for t in PAYLOAD_TEMPLATES.values()),
            "plugins": len(PluginManager().discover()),
        }
        return templates.TemplateResponse("dashboard.html", {"request": request, "stats": stats})

    @app.get("/sitemap.xml", response_class=HTMLResponse)
    async def sitemap():
        return templates.TemplateResponse("sitemap.xml", {"request": {}})

    @app.get("/robots.txt", response_class=HTMLResponse)
    async def robots():
        return HTMLResponse("User-agent: *\nAllow: /\nSitemap: https://pieces-ali-song-broadcasting.trycloudflare.com/sitemap.xml\n")

    @app.get("/checkout", response_class=HTMLResponse)
    async def checkout_page(request: Request):
        from web.payment import PRODUCTS
        return templates.TemplateResponse("checkout.html", {"request": request, "products": PRODUCTS})

    @app.get("/scan", response_class=HTMLResponse)
    async def scan_page(request: Request):
        return templates.TemplateResponse("scan.html", {"request": request})

    @app.get("/waf", response_class=HTMLResponse)
    async def waf_page(request: Request):
        return templates.TemplateResponse("waf.html", {"request": request})

    @app.get("/js-analyzer", response_class=HTMLResponse)
    async def js_analyzer_page(request: Request):
        return templates.TemplateResponse("js_analyzer.html", {"request": request})

    @app.get("/fingerprints", response_class=HTMLResponse)
    async def fingerprints_page(request: Request):
        from core.fingerprint import manager as fp_mgr
        fps = [{"id": k, "name": v.name, "ua": v.ua, "accept_language": v.accept_language,
                "sec_ch_ua": v.sec_ch_ua, "tls": v.tls} for k, v in fp_mgr._profiles.items()]
        return templates.TemplateResponse("fingerprints.html", {"request": request, "fingerprints": fps})

    @app.get("/reportcard", response_class=HTMLResponse)
    async def reportcard_page(request: Request):
        return templates.TemplateResponse("reportcard.html", {"request": request})

    @app.get("/examples", response_class=HTMLResponse)
    async def examples_page(request: Request):
        return templates.TemplateResponse("examples.html", {"request": request})

    @app.get("/live-demo", response_class=HTMLResponse)
    async def live_demo_page(request: Request):
        return templates.TemplateResponse("live_demo.html", {"request": request})

    @app.get("/changelog", response_class=HTMLResponse)
    async def changelog_page(request: Request):
        return templates.TemplateResponse("changelog.html", {"request": request})

    @app.get("/blog", response_class=HTMLResponse)
    async def blog_page(request: Request):
        return templates.TemplateResponse("blog.html", {"request": request})

    @app.get("/blog/waf-bypass-techniques", response_class=HTMLResponse)
    async def blog_waf(request: Request):
        return templates.TemplateResponse("blog_waf_bypass.html", {"request": request})

    @app.get("/blog/js-bundle-analysis", response_class=HTMLResponse)
    async def blog_js(request: Request):
        return templates.TemplateResponse("blog_js_analysis.html", {"request": request})

    @app.get("/blog/browser-fingerprint-testing", response_class=HTMLResponse)
    async def blog_fingerprint(request: Request):
        return templates.TemplateResponse("blog_fingerprint.html", {"request": request})

    @app.get("/blog/api-security-scanning", response_class=HTMLResponse)
    async def blog_api(request: Request):
        return templates.TemplateResponse("blog_api.html", {"request": request})

    @app.get("/blog/security-report-card-guide", response_class=HTMLResponse)
    async def blog_reportcard(request: Request):
        return templates.TemplateResponse("blog_reportcard.html", {"request": request})

    @app.get("/blog/getting-started", response_class=HTMLResponse)
    async def blog_getting_started(request: Request):
        return templates.TemplateResponse("blog_getting_started.html", {"request": request})

    @app.get("/blog/src-automation", response_class=HTMLResponse)
    async def blog_src_automation(request: Request):
        return templates.TemplateResponse("blog/src-automation.html", {"request": request})

    @app.get("/blog/rss.xml", response_class=HTMLResponse)
    async def blog_rss():
        return HTMLResponse('''<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
    <title>StrixPro Blog - 安全测试技术</title>
    <link>https://occurred-hear-cycling-craps.trycloudflare.com/blog</link>
    <description>Web 安全测试技术分享、工具使用指南</description>
    <language>zh-CN</language>
    <atom:link href="https://occurred-hear-cycling-craps.trycloudflare.com/blog/rss.xml" rel="self" type="application/rss+xml"/>
    <item>
        <title>SRC 自动化漏洞挖掘实战：用 StrixPro 把效率提升 10 倍</title>
        <link>https://occurred-hear-cycling-craps.trycloudflare.com/blog/src-automation</link>
        <description>实战分享如何用 StrixPro 自动化平台提升 SRC 挖洞效率，从指纹识别到报告生成全流程自动化</description>
        <pubDate>Tue, 26 May 2026 00:00:00 GMT</pubDate>
    </item>
    <item>
        <title>WAF 绕过技术与 Payload 编码实战</title>
        <link>https://occurred-hear-cycling-craps.trycloudflare.com/blog/waf-bypass-techniques</link>
        <description>深入浅出 WAF 检测原理，掌握 URL 编码、Base64、Unicode 等 11 种绕过编码方式</description>
        <pubDate>Mon, 25 May 2026 00:00:00 GMT</pubDate>
    </item>
    <item>
        <title>JS Bundle 分析：从 JavaScript 中发现 API 与敏感信息</title>
        <link>https://occurred-hear-cycling-craps.trycloudflare.com/blog/js-bundle-analysis</link>
        <description>现代 Web 应用的前端代码中隐藏着大量 API 端点、硬编码密钥和内网地址</description>
        <pubDate>Sun, 24 May 2026 00:00:00 GMT</pubDate>
    </item>
    <item>
        <title>浏览器指纹技术在安全测试中的应用</title>
        <link>https://occurred-hear-cycling-craps.trycloudflare.com/blog/browser-fingerprint-testing</link>
        <description>JA3/JA4 TLS 指纹原理、主流浏览器的指纹特征差异及在渗透测试中的应用</description>
        <pubDate>Sat, 23 May 2026 00:00:00 GMT</pubDate>
    </item>
    <item>
        <title>API 安全扫描：从认证绕过到 GraphQL 注入</title>
        <link>https://occurred-hear-cycling-craps.trycloudflare.com/blog/api-security-scanning</link>
        <description>REST API 和 GraphQL 接口的安全性评估方法论</description>
        <pubDate>Fri, 22 May 2026 00:00:00 GMT</pubDate>
    </item>
    <item>
        <title>Security Report Card：快速评估网站安全等级</title>
        <link>https://occurred-hear-cycling-craps.trycloudflare.com/blog/security-report-card-guide</link>
        <description>使用 StrixPro Report Card 一键生成 A-F 安全评分报告</description>
        <pubDate>Thu, 21 May 2026 00:00:00 GMT</pubDate>
    </item>
    <item>
        <title>StrixPro 快速上手：从安装到第一次扫描</title>
        <link>https://occurred-hear-cycling-craps.trycloudflare.com/blog/getting-started</link>
        <description>5 分钟内完成 StrixPro 安装配置并完成第一次安全扫描</description>
        <pubDate>Wed, 20 May 2026 00:00:00 GMT</pubDate>
    </item>
</channel>
</rss>''')

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return templates.TemplateResponse("login.html", {"request": request})

    @app.get("/register", response_class=HTMLResponse)
    async def register_page(request: Request):
        return templates.TemplateResponse("register.html", {"request": request})

    @app.get("/profile", response_class=HTMLResponse)
    async def profile_page(request: Request):
        return templates.TemplateResponse("profile.html", {"request": request})

    @app.get("/pricing", response_class=HTMLResponse)
    async def pricing_page(request: Request):
        return templates.TemplateResponse("pricing.html", {"request": request})

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(request: Request):
        return templates.TemplateResponse("admin.html", {"request": request})

    # ============ API Routes ============

    @app.get("/api")
    async def root():
        return {
            "name": "StrixPro API",
            "version": "1.0.0",
            "status": "running",
            "endpoints": {
                "api": "/api/v1",
                "docs": "/docs",
            }
        }

    @app.get("/api/v1/status")
    async def status():
        return {
            "status": "healthy",
            "version": "1.0.0",
            "uptime": "N/A",
            "features": {
                "fingerprint": True,
                "waf_bypass": True,
                "js_analyzer": True,
                "scanner": True,
                "report": True,
            }
        }

    @app.get("/api/v1/fingerprints")
    async def list_fingerprints():
        from core.fingerprint import manager
        return {"fingerprints": manager.list_profiles()}

    @app.post("/api/v1/fingerprints/generate")
    async def generate_headers(profile_id: str = Query("chrome_131")):
        from core.fingerprint import manager
        fp = manager.get(profile_id)
        return {
            "profile": fp.name,
            "headers": fp.to_headers(),
            "tls": fp.tls,
        }

    @app.post("/api/v1/waf/bypass")
    async def generate_waf_payloads(req: WAFGenerateRequest):
        from core.waf_bypass import engine, AttackType
        try:
            at = AttackType(req.attack_type)
        except ValueError:
            raise HTTPException(400, f"Invalid attack type: {req.attack_type}")

        payloads = engine.generate(at, count=req.count)
        return {"attack_type": req.attack_type, "count": len(payloads), "payloads": payloads}

    @app.post("/api/v1/js/analyze")
    async def analyze_js(req: JSRequest):
        from core.js_analyzer import JSBundleAnalyzer
        analyzer = JSBundleAnalyzer()
        result = analyzer.analyze_bundle(req.content, req.source)
        return result

    @app.post("/api/v1/scan")
    async def start_scan(req: ScanRequest):
        import uuid
        task_id = str(uuid.uuid4())[:8]
        tasks[task_id] = {"status": "running", "progress": 0, "result": None}

        # Simple async scan
        try:
            from core.scanner import Scanner
            from core.config import StrixProConfig

            scanner = Scanner(StrixProConfig.load())
            result = {"target": req.url, "vulnerabilities": [], "security_headers": {}, "summary": {"total_findings": 0}}

            if req.check_headers:
                header_result = scanner.check_security_headers(req.url)
                result["security_headers"] = header_result.get("headers", {})

            if req.check_cors:
                cors_result = scanner.check_cors(req.url)
                if cors_result.get("findings"):
                    result["vulnerabilities"].extend(cors_result["findings"])

            if req.js_analysis:
                resp = scanner.get(req.url)
                if resp:
                    from core.js_analyzer import JSBundleAnalyzer
                    analyzer = JSBundleAnalyzer()
                    js_result = analyzer.analyze_bundle(resp.text, req.url)
                    result["api_endpoints"] = js_result.get("api_endpoints", [])
                    result["secrets"] = js_result.get("sensitive_data", [])

            result["summary"]["total_findings"] = len(result["vulnerabilities"])
            tasks[task_id] = {"status": "completed", "progress": 100, "result": result}

        except Exception as e:
            tasks[task_id] = {"status": "failed", "error": str(e), "result": None}

        return ScanResponse(task_id=task_id, status="running", message="扫描已启动")

    @app.get("/api/v1/scan/{task_id}")
    async def get_scan_result(task_id: str):
        if task_id not in tasks:
            raise HTTPException(404, "Task not found")
        return {"task_id": task_id, **tasks[task_id]}

    @app.post("/api/v1/license/activate")
    async def activate_license(req: LicenseActivateRequest):
        from pro.license import LicenseManager
        lm = LicenseManager()
        result = lm.activate(req.license_key)
        if not result.get("success"):
            raise HTTPException(400, result.get("message", "激活失败"))
        return result

    @app.get("/api/v1/license/status")
    async def license_status():
        from pro.license import LicenseManager
        lm = LicenseManager()
        lm.load()
        return lm.validate()

    @app.get("/api/v1/report/generate")
    async def generate_report(target: str = Query(...), format: str = Query("markdown")):
        from core.report import ReportGenerator
        from core.scanner import Scanner
        from core.config import StrixProConfig

        scanner = Scanner(StrixProConfig.load())
        reporter = ReportGenerator()

        data = {"target": target, "vulnerabilities": [], "security_headers": {}, "summary": {"total_findings": 0}}

        header_result = scanner.check_security_headers(target)
        data["security_headers"] = header_result.get("headers", {})

        cors_result = scanner.check_cors(target)
        if cors_result.get("findings"):
            data["vulnerabilities"].extend(cors_result["findings"])

        data["summary"]["total_findings"] = len(data["vulnerabilities"])

        content = reporter.generate(data, fmt=format)

        return {"target": target, "format": format, "content": content}


    # ============ Auth API ============

    @app.post("/api/v1/auth/register")
    async def auth_register(data: dict = Body(...)):
        from web.users import register_user
        email = data.get("email", "").strip()
        password = data.get("password", "")
        username = data.get("username", "").strip()
        result = register_user(email, password, username)
        if "error" in result:
            raise HTTPException(400, result["error"])
        return result

    @app.post("/api/v1/auth/login")
    async def auth_login(data: dict = Body(...)):
        from web.users import login_user
        email = data.get("email", "").strip()
        password = data.get("password", "")
        result = login_user(email, password)
        if "error" in result:
            raise HTTPException(401, result["error"])
        return result

    @app.get("/api/v1/auth/profile")
    async def auth_profile(request: Request):
        from web.users import get_user_from_token
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(401, "未登录")
        user = get_user_from_token(auth[7:])
        if not user:
            raise HTTPException(401, "登录已过期")

        # Enrich with orders and licenses
        from web.payment import order_system
        orders_data = []
        for oid in user["orders"]:
            o = order_system.orders.get(oid)
            if o:
                orders_data.append({"order_id": o["order_id"], "product_id": o["product_id"],
                    "product_name": o.get("product_name", ""), "price_cny": o["price_cny"],
                    "status": o["status"], "created_at": o["created_at"]})

        licenses_data = []
        for lkey in user["licenses"]:
            l = order_system.keys.get(lkey)
            if l:
                licenses_data.append({"license_key": l["license_key"],
                    "product_id": l["product_id"], "expires_at": l["expires_at"],
                    "product_name": l.get("product_name", "")})

        return {**user, "orders": orders_data, "licenses": licenses_data}

    # ============ Payment & Order API ============

    @app.get("/api/v1/pricing")
    async def api_pricing():
        from web.payment import PRODUCTS
        return {"products": {k: {**v, "features": v["features"]} for k, v in PRODUCTS.items()}}

    @app.post("/api/v1/order/create")
    async def create_order(request: Request, product_id: str = Query(...), email: str = Query(""), method: str = Query("alipay")):
        from web.payment import order_system
        from web.users import get_user_from_token

        user_id = ""
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            u = get_user_from_token(auth[7:])
            if u:
                user_id = u["user_id"]
                if not email:
                    email = u["email"] or email

        order = order_system.create_order(product_id, email, method)
        if "error" in order:
            raise HTTPException(400, order["error"])

        if user_id and email:
            from web.users import update_user_orders
            update_user_orders(email, order["order_id"], "")

        if user_id:
            order["user_id"] = user_id
            order_system.orders[order["order_id"]]["user_id"] = user_id

        return order

    @app.get("/api/v1/order/{order_id}")
    async def get_order(order_id: str):
        from web.payment import order_system
        order = order_system.orders.get(order_id)
        if not order:
            raise HTTPException(404, "订单不存在")
        return order

    @app.post("/api/v1/order/{order_id}/confirm")
    async def confirm_order(order_id: str):
        from web.payment import order_system
        result = order_system.confirm_payment(order_id)
        if result.get("success"):
            order = order_system.orders.get(order_id)
            if order and order.get("email"):
                from web.users import update_user_orders
                update_user_orders(order["email"], order_id, result.get("license_key", ""))
                # Send email notification
                try:
                    from web.email import send_license_email, send_order_confirmation_email, load_smtp_config
                    cfg = load_smtp_config()
                    if cfg.get("enabled"):
                        username = order.get("email", "").split("@")[0]
                        send_license_email(order["email"], username,
                            result["license_key"], result.get("product_name", ""),
                            result.get("expires_at", 0))
                        send_order_confirmation_email(order["email"], username,
                            order_id, result.get("product_name", ""), order["price_cny"])
                except Exception as e:
                    logger.warning("Send email failed for order %s: %s", order_id, e)
        return result

    @app.get("/api/v1/license/verify")
    async def verify_license(license_key: str = Query(...), machine_id: str = Query("")):
        from web.payment import order_system
        return order_system.verify_license(license_key, machine_id)

    @app.get("/api/v1/admin/stats")
    async def admin_stats():
        from web.payment import order_system
        return order_system.get_stats()

    @app.get("/api/v1/admin/orders")
    async def admin_orders(status: str = Query("")):
        from web.payment import order_system
        return {"orders": order_system.list_orders(status)}

    @app.get("/api/v1/admin/keys")
    async def admin_keys():
        from web.payment import order_system
        return {"keys": order_system.list_keys()}

    # ============ PayJS Payment Integration ============

    @app.get("/api/v1/admin/payjs-config")
    async def get_payjs_config():
        from web.payjs import load_config
        cfg = load_config()
        # Never expose the key in full
        if cfg.get("key"):
            cfg["key_masked"] = cfg["key"][:4] + "****" + cfg["key"][-4:]
        return cfg

    @app.post("/api/v1/admin/payjs-config")
    async def update_payjs_config(data: dict = Body(...)):
        from web.payjs import save_config
        cfg = {
            "mchid": data.get("mchid", ""),
            "key": data.get("key", ""),
            "notify_url": data.get("notify_url", ""),
        }
        save_config(cfg)
        return {"success": True}

    @app.post("/api/v1/payment/payjs/native")
    async def payjs_native(order_id: str = Query(...)):
        """创建 PayJS 扫码支付"""
        from web.payment import order_system
        from web.payjs import create_native_qrcode

        order = order_system.orders.get(order_id)
        if not order:
            raise HTTPException(404, "订单不存在")
        if order["status"] != "pending":
            raise HTTPException(400, "订单状态异常")

        # total_fee in 分 (cents)
        total_fee = int(order["price_cny"] * 100)

        # Determine notify URL
        from web.payjs import load_config
        cfg = load_config()
        base_url = cfg.get("notify_url", "").rstrip("/")
        notify_url = f"{base_url}/api/v1/payment/payjs/notify" if base_url else ""

        result = create_native_qrcode(order_id, total_fee, notify_url)
        if "error" in result:
            raise HTTPException(502, result["error"])
        return result

    @app.post("/api/v1/payment/payjs/notify")
    async def payjs_notify(data: dict = Body(...)):
        """PayJS 异步通知 - 支付结果回调"""
        from web.payment import order_system
        from web.payjs import load_config, verify_sign

        cfg = load_config()
        if not cfg.get("key"):
            logger.error("PayJS notify: no key configured")
            return {"return_code": 0, "return_msg": "config error"}

        # 验证签名
        if not verify_sign(data, cfg["key"]):
            logger.warning("PayJS notify: invalid signature %s", data)
            return {"return_code": 0, "return_msg": "sign error"}

        out_trade_no = data.get("out_trade_no", "")
        payjs_order_id = data.get("payjs_order_id", "")
        total_fee = data.get("total_fee", 0)
        transaction_id = data.get("transaction_id", "")

        logger.info("PayJS payment callback: order=%s, payjs_id=%s, fee=%s",
                     out_trade_no, payjs_order_id, total_fee)

        # 确认订单
        if out_trade_no and data.get("return_code") == 1:
            order = order_system.orders.get(out_trade_no)
            if order and order["status"] == "pending":
                result = order_system.confirm_payment(out_trade_no, {
                    "payjs_order_id": payjs_order_id,
                    "transaction_id": transaction_id,
                    "total_fee": total_fee,
                })
                logger.info("Order %s confirmed: %s", out_trade_no, result.get("success"))
                if result.get("success"):
                    return {"return_code": 1, "return_msg": "ok"}

        return {"return_code": 0, "return_msg": "fail"}

    @app.get("/api/v1/payment/payjs/check/{order_id}")
    async def payjs_check(order_id: str):
        """主动查询订单支付状态"""
        from web.payment import order_system
        from web.payjs import query_order

        order = order_system.orders.get(order_id)
        if not order:
            raise HTTPException(404, "订单不存在")

        result = query_order(out_trade_no=order_id)
        if result and result.get("paid"):
            # 如果PayJS显示已支付但本地未确认，自动确认
            if order["status"] == "pending":
                order_system.confirm_payment(order_id, {"payjs_auto": True})
            return {"paid": True, "order_id": order_id}

        return {"paid": False, "order_id": order_id}

    # Payment config
    PAYMENT_CONFIG_FILE = Path(__file__).parent.parent / "data" / "payment_config.json"

    def _load_payment_config():
        try:
            if PAYMENT_CONFIG_FILE.exists():
                return json.loads(PAYMENT_CONFIG_FILE.read_text())
        except: pass
        return {"alipay_qr": "", "wechat_qr": "", "alipay_account": "", "wechat_account": ""}

    def _save_payment_config(cfg):
        PAYMENT_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

    @app.get("/api/v1/admin/payment-config")
    async def get_payment_config():
        return _load_payment_config()

    @app.post("/api/v1/admin/payment-config")
    async def update_payment_config(data: dict = Body(...)):
        cfg = _load_payment_config()
        cfg.update(data)
        _save_payment_config(cfg)
        return {"success": True, "config": cfg}

    # SMTP / Email config
    @app.get("/api/v1/admin/smtp-config")
    async def get_smtp_config():
        from web.email import load_smtp_config
        cfg = load_smtp_config()
        if cfg.get("password"):
            cfg["password"] = "******"
        return cfg

    @app.post("/api/v1/admin/smtp-config")
    async def update_smtp_config(data: dict = Body(...)):
        from web.email import load_smtp_config, save_smtp_config
        cfg = load_smtp_config()
        for k in ("enabled", "host", "port", "user", "password", "from_addr", "from_name"):
            if k in data:
                cfg[k] = data[k]
        save_smtp_config(cfg)
        return {"success": True}

    @app.post("/api/v1/admin/smtp-test")
    async def test_smtp():
        from web.email import send_email
        result = send_email("test@strixpro.io", "StrixPro 邮件测试", "这是一封测试邮件。如果收到，说明 SMTP 配置正常。")
        return result

    # ============ Examples / Static Demo Data ============

    DEMO_JS_ANALYSIS = {
        "url": "https://example.com/app.bundle.js",
        "findings": {
            "api_endpoints": [
                "https://api.example.com/v1/users",
                "https://api.example.com/v1/orders",
                "wss://ws.example.com/events",
                "https://api.example.com/graphql",
            ],
            "sensitive_data": [
                {"type": "API Key", "value": "sk_live_xxxxxxxxxxxxx", "risk": "high"},
                {"type": "JWT Token", "value": "eyJhbGciOiJIUzI1NiIs...", "risk": "high"},
                {"type": "Internal IP", "value": "10.0.1.25", "risk": "medium"},
                {"type": "AWS Key", "value": "AKIAIOSFODNN7EXAMPLE", "risk": "high"},
            ],
            "routes": [
                "/dashboard", "/admin/users", "/api/v2/export",
                "/internal/health", "/debug/status",
            ],
            "libraries": [
                {"name": "axios", "version": "1.6.0"},
                {"name": "lodash", "version": "4.17.21"},
                {"name": "react", "version": "18.2.0"},
            ],
        },
        "summary": {
            "total_endpoints": 4,
            "total_secrets": 4,
            "total_routes": 5,
        },
    }

    DEMO_REPORT = {
        "target": "https://example.com",
        "scan_date": "2026-05-25T00:00:00Z",
        "summary": {
            "total_findings": 7,
            "critical": 1,
            "high": 2,
            "medium": 3,
            "low": 1,
        },
        "security_headers": {
            "Strict-Transport-Security": {"status": "missing", "risk": "medium", "description": "缺少 HSTS 头，存在中间人攻击风险"},
            "Content-Security-Policy": {"status": "missing", "risk": "high", "description": "缺少 CSP，存在 XSS 攻击风险"},
            "X-Frame-Options": {"status": "present", "value": "DENY", "risk": "none"},
            "X-Content-Type-Options": {"status": "present", "value": "nosniff", "risk": "none"},
            "X-XSS-Protection": {"status": "present", "value": "1; mode=block", "risk": "none"},
        },
        "cors_findings": [
            {"issue": "Credentials allowed with wildcard origin", "risk": "high"},
            {"issue": "Exposed internal API paths in JS bundles", "risk": "medium"},
        ],
        "vulnerabilities": [
            {"type": "Missing CSP Header", "severity": "high", "endpoint": "/", "remediation": "添加 Content-Security-Policy 头"},
            {"type": "CORS Wildcard Origin", "severity": "high", "endpoint": "/api/*", "remediation": "限制允许的 Origin 列表"},
            {"type": "Missing HSTS", "severity": "medium", "endpoint": "/", "remediation": "添加 Strict-Transport-Security 头"},
            {"type": "Sensitive Data in JS", "severity": "critical", "endpoint": "/app.js", "remediation": "移除前端代码中的硬编码凭证"},
        ],
    }

    @app.get("/api/v1/examples/js-analysis")
    async def example_js_analysis():
        return DEMO_JS_ANALYSIS

    @app.get("/api/v1/examples/report")
    async def example_report():
        return DEMO_REPORT

    # ============ Download ============

    @app.get("/download")
    async def download_page(request: Request):
        return templates.TemplateResponse("download.html", {"request": request})

    @app.get("/api/v1/download")
    async def download_exe():
        exe_path = Path(__file__).parent.parent / "dist" / "strixpro.exe"
        if not exe_path.exists():
            raise HTTPException(404, "可执行文件未找到，请先运行 build 命令")
        from fastapi.responses import FileResponse
        return FileResponse(
            path=str(exe_path),
            filename="strixpro.exe",
            media_type="application/octet-stream",
        )

    def start_server(host: str = "0.0.0.0", port: int = 8765):
        """启动Web服务"""
        uvicorn.run(app, host=host, port=port, log_level="info")

else:
    def start_server(host: str = "0.0.0.0", port: int = 8765):
        logger.error("Cannot start web server: FastAPI not installed")
        print("❌ FastAPI is not installed. Install with: pip install fastapi uvicorn")
