"""
StrixPro Web Service - Web服务
提供RESTful API、用户管理、支付集成
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
    from fastapi import FastAPI, HTTPException, Depends, Query, Body
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
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

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # In-memory task store
    tasks = {}

    @app.get("/")
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


    def start_server(host: str = "0.0.0.0", port: int = 8765):
        """启动Web服务"""
        uvicorn.run(app, host=host, port=port, log_level="info")

else:
    def start_server(host: str = "0.0.0.0", port: int = 8765):
        logger.error("Cannot start web server: FastAPI not installed")
        print("❌ FastAPI is not installed. Install with: pip install fastapi uvicorn")
