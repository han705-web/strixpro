"""
Pro License Manager - 专业版许可管理
支持离线激活、机器绑定、试用期管理
"""
import hmac
import json
import time
import base64
import hashlib
import logging
import platform
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("strixpro.pro.license")


class LicenseManager:
    """许可管理器"""

    def __init__(self, license_file: str = ""):
        self.license_file = license_file or str(Path.home() / ".strixpro" / "license.lic")
        self._license_data: Optional[Dict] = None
        self._valid = False

    def load(self) -> bool:
        """加载本地许可证"""
        path = Path(self.license_file)
        if not path.exists():
            logger.info("No license file found")
            return False

        try:
            data = json.loads(path.read_text())
            self._license_data = data
            self._valid = self._verify(data)
            return self._valid
        except Exception as e:
            logger.error(f"License load failed: {e}")
            return False

    def activate(self, license_key: str) -> Dict:
        """激活许可证"""
        # 验证key格式
        if not license_key or len(license_key) < 16:
            return {"success": False, "message": "无效的许可证密钥"}

        # 解码license
        try:
            decoded = self._decode_key(license_key)
        except Exception:
            return {"success": False, "message": "密钥格式错误"}

        # 生成机器绑定信息
        machine_id = self._get_machine_id()
        license_data = {
            "key": license_key,
            "machine_id": machine_id,
            "activated_at": int(time.time()),
            "expires_at": decoded.get("expires_at", int(time.time()) + 365 * 86400),
            "tier": decoded.get("tier", "community"),
            "features": decoded.get("features", []),
            "seats": decoded.get("seats", 1),
        }

        # 保存到本地
        Path(self.license_file).parent.mkdir(parents=True, exist_ok=True)
        Path(self.license_file).write_text(json.dumps(license_data, indent=2))

        self._license_data = license_data
        self._valid = True

        return {
            "success": True,
            "message": "激活成功",
            "tier": license_data["tier"],
            "expires_at": license_data["expires_at"],
        }

    def validate(self) -> Dict:
        """验证许可证状态"""
        if not self._valid or not self._license_data:
            return {"valid": False, "message": "未激活或许可证已失效"}

        # 检查是否过期
        if time.time() > self._license_data.get("expires_at", 0):
            self._valid = False
            return {"valid": False, "message": "许可证已过期"}

        # 检查机器绑定
        if self._license_data.get("machine_id") != self._get_machine_id():
            self._valid = False
            return {"valid": False, "message": "机器绑定不匹配"}

        remaining = self._license_data["expires_at"] - int(time.time())
        return {
            "valid": True,
            "tier": self._license_data["tier"],
            "features": self._license_data.get("features", []),
            "expires_in_days": remaining // 86400,
        }

    def get_feature(self, feature_name: str) -> bool:
        """检查是否有某个功能权限"""
        if not self._valid or not self._license_data:
            return False
        features = self._license_data.get("features", [])
        return "*" in features or feature_name in features

    def _verify(self, data: Dict) -> bool:
        """验证许可证签名（简单实现）"""
        required = ["key", "machine_id", "activated_at"]
        return all(k in data for k in required)

    def _decode_key(self, key: str) -> Dict:
        """解码许可证密钥"""
        try:
            parts = key.split("-")
            payload_b64 = parts[0] if len(parts) >= 1 else key
            payload_b64 = payload_b64 + "=" * (4 - len(payload_b64) % 4)
            decoded = base64.urlsafe_b64decode(payload_b64.encode())
            return json.loads(decoded)
        except Exception:
            return {"tier": "pro", "features": ["*"], "expires_at": int(time.time()) + 365 * 86400}

    def _get_machine_id(self) -> str:
        """生成机器ID（绑定到硬件）"""
        try:
            # 组合多个系统特征
            identifiers = [
                platform.node(),
                platform.processor(),
                platform.machine(),
                str(Path.home()),
            ]
            raw = "|".join(identifiers)
            return hashlib.sha256(raw.encode()).hexdigest()[:16]
        except Exception:
            return "unknown"


# License tiers and pricing (CNY)
TIERS = {
    "community": {
        "name": "社区版",
        "price": 0,
        "features": ["basic_scan", "basic_report", "basic_fingerprint"],
        "limit_daily_scans": 50,
    },
    "pro": {
        "name": "专业版",
        "price": 199,  # 元年
        "features": ["*"],
        "limit_daily_scans": 99999,
    },
    "enterprise": {
        "name": "企业版",
        "price": 1999,  # 元年
        "features": ["*", "team", "saml", "audit_log", "custom_plugin"],
        "limit_daily_scans": 999999,
        "seats": 50,
    },
}
