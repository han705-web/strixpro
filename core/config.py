"""全局配置管理"""
import os
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class ProxyConfig:
    http: str = ""
    https: str = ""
    socks5: str = ""


@dataclass
class ScanConfig:
    timeout: int = 30
    max_concurrent: int = 10
    delay_min: float = 1.0
    delay_max: float = 3.0
    max_retries: int = 3
    follow_redirects: bool = True
    verify_ssl: bool = False


@dataclass
class FingerprintConfig:
    browser: str = "chrome"  # chrome, firefox, edge, safari, random
    rotate_per_request: bool = False
    custom_ja3: str = ""
    tls_version: str = "auto"


@dataclass
class WAFBypassConfig:
    enabled: bool = True
    encoding: str = "auto"  # auto, url, base64, unicode, mixed
    random_case: bool = True
    insert_junk: bool = True
    max_payload_length: int = 8192


@dataclass
class ReportConfig:
    format: str = "markdown"  # markdown, html, json, pdf
    language: str = "zh"  # zh, en
    include_evidence: bool = True
    include_remediation: bool = True
    template: str = "default"


@dataclass
class StrixProConfig:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    fingerprint: FingerprintConfig = field(default_factory=FingerprintConfig)
    waf: WAFBypassConfig = field(default_factory=WAFBypassConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    output_dir: str = "./output"
    plugins_dir: str = "./plugins"
    log_level: str = "INFO"
    license_key: str = ""

    @classmethod
    def load(cls, path: str = "") -> "StrixProConfig":
        cfg = cls()
        if not path:
            path = os.environ.get("STRIXPRO_CONFIG", "")
        if not path:
            # Look in standard locations
            for p in [
                "./strixpro.json",
                os.path.expanduser("~/.strixpro/config.json"),
                "/etc/strixpro/config.json",
            ]:
                if os.path.exists(p):
                    path = p
                    break
        if path and os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            cfg._merge(data)
        return cfg

    def _merge(self, data: dict):
        for section, values in data.items():
            if hasattr(self, section):
                sub = getattr(self, section)
                if isinstance(sub, (ProxyConfig, ScanConfig, FingerprintConfig, WAFBypassConfig, ReportConfig)):
                    for k, v in values.items():
                        if hasattr(sub, k):
                            setattr(sub, k, v)

    def save(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)

    @property
    def is_pro(self) -> bool:
        return bool(self.license_key)
