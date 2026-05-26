"""
StrixPro Payment System - 支付与许可管理
支持支付宝/微信支付，自动发Key
"""
import json
import hmac
import uuid
import time
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger("strixpro.web.payment")

ORDERS_FILE = Path(__file__).parent.parent / "data" / "orders.json"
KEYS_FILE = Path(__file__).parent.parent / "data" / "license_keys.json"

ORDERS_FILE.parent.mkdir(parents=True, exist_ok=True)

# ====== 产品定价 ======
PRODUCTS = {
    "pro_monthly": {
        "name": "专业版 - 月付",
        "price_cny": 29,
        "price_usd": 4,
        "days": 30,
        "features": ["*"],
        "description": "全部功能，按月订阅",
    },
    "pro_yearly": {
        "name": "专业版 - 年付",
        "price_cny": 199,
        "price_usd": 28,
        "days": 365,
        "features": ["*"],
        "description": "全部功能，按年订阅（省42%）",
    },
    "enterprise_yearly": {
        "name": "企业版 - 年付",
        "price_cny": 1999,
        "price_usd": 280,
        "days": 365,
        "features": ["*", "team", "saml", "audit_log"],
        "description": "50席位，团队协作，私有部署",
    },
}


class OrderSystem:
    """订单与许可管理系统"""

    def __init__(self):
        self.orders = self._load(ORDERS_FILE)
        self.keys = self._load(KEYS_FILE)

    def create_order(self, product_id: str, email: str = "", payment_method: str = "alipay") -> Dict:
        """创建订单"""
        product = PRODUCTS.get(product_id)
        if not product:
            return {"error": "无效的产品ID"}

        order = {
            "order_id": self._gen_order_id(),
            "product_id": product_id,
            "product_name": product["name"],
            "price_cny": product["price_cny"],
            "price_usd": product["price_usd"],
            "email": email,
            "payment_method": payment_method,
            "status": "pending",  # pending, paid, expired, cancelled
            "created_at": int(time.time()),
            "paid_at": 0,
            "license_key": "",
        }

        self.orders[order["order_id"]] = order
        self._save(ORDERS_FILE, self.orders)
        return order

    def confirm_payment(self, order_id: str, payment_data: Dict = None) -> Dict:
        """确认支付 - 生成License Key"""
        order = self.orders.get(order_id)
        if not order:
            return {"error": "订单不存在"}
        if order["status"] != "pending":
            return {"error": "订单状态异常: %s" % order["status"]}

        # 生成License Key
        product = PRODUCTS[order["product_id"]]
        license_key = self._generate_license_key(order, product)

        # 更新订单
        order["status"] = "paid"
        order["paid_at"] = int(time.time())
        order["license_key"] = license_key

        # 保存许可信息
        key_info = {
            "license_key": license_key,
            "order_id": order_id,
            "product_id": order["product_id"],
            "product_name": product["name"],
            "email": order["email"],
            "created_at": int(time.time()),
            "expires_at": int(time.time()) + product["days"] * 86400,
            "features": product["features"],
            "activations": [],
            "max_activations": 3,
        }
        self.keys[license_key] = key_info

        self._save(ORDERS_FILE, self.orders)
        self._save(KEYS_FILE, self.keys)

        return {
            "success": True,
            "license_key": license_key,
            "expires_at": key_info["expires_at"],
            "product_name": product["name"],
        }

    def verify_license(self, license_key: str, machine_id: str = "") -> Dict:
        """验证许可Key"""
        key_info = self.keys.get(license_key)
        if not key_info:
            return {"valid": False, "message": "无效的License Key"}

        if int(time.time()) > key_info.get("expires_at", 0):
            return {"valid": False, "message": "License已过期"}

        # 记录激活
        if machine_id and machine_id not in key_info["activations"]:
            if len(key_info["activations"]) < key_info["max_activations"]:
                key_info["activations"].append(machine_id)
                self._save(KEYS_FILE, self.keys)

        days_left = (key_info["expires_at"] - int(time.time())) // 86400
        return {
            "valid": True,
            "product": key_info["product_id"],
            "features": key_info["features"],
            "expires_in_days": days_left,
        }

    def list_orders(self, status: str = "") -> list:
        """列出订单"""
        items = list(self.orders.values())
        if status:
            items = [o for o in items if o["status"] == status]
        return sorted(items, key=lambda x: x["created_at"], reverse=True)

    def list_keys(self) -> list:
        """列出所有License Key"""
        return [
            {
                "key": k["license_key"],
                "product": k["product_id"],
                "created": datetime.fromtimestamp(k["created_at"]).strftime("%Y-%m-%d"),
                "expires": datetime.fromtimestamp(k["expires_at"]).strftime("%Y-%m-%d"),
                "activations": len(k["activations"]),
            }
            for k in self.keys.values()
        ]

    def get_stats(self) -> Dict:
        """获取销售统计"""
        total_revenue = sum(
            o["price_cny"] for o in self.orders.values() if o["status"] == "paid"
        )
        paid_count = sum(1 for o in self.orders.values() if o["status"] == "paid")
        pending_count = sum(1 for o in self.orders.values() if o["status"] == "pending")
        return {
            "total_revenue_cny": total_revenue,
            "total_orders_paid": paid_count,
            "total_orders_pending": pending_count,
            "license_keys_issued": len(self.keys),
        }

    def _generate_license_key(self, order: Dict, product: Dict) -> str:
        """生成License Key"""
        raw = "%s-%s-%s-%s" % (
            order["order_id"],
            order["product_id"],
            order["created_at"],
            str(uuid.uuid4()),
        )
        h = hashlib.sha256(raw.encode()).hexdigest().upper()
        # Format: XXXX-XXXX-XXXX-XXXX
        key = "-".join([h[i:i+4] for i in range(0, 16, 4)])
        return "STRIXPRO-" + key

    def _gen_order_id(self) -> str:
        return "ORD-%s-%04d" % (datetime.now().strftime("%Y%m%d"), len(self.orders) + 1)

    def _load(self, path: Path) -> Dict:
        try:
            if path.exists():
                return json.loads(path.read_text())
        except Exception as e:
            logger.error("Load failed: %s", e)
        return {}

    def _save(self, path: Path, data: Dict):
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


# ====== Alipay/WeChat Pay Integration ======
# 以下代码是支付宝和微信支付集成模板
# 使用时需替换 YOUR_APP_ID, YOUR_PRIVATE_KEY 等参数

"""
## 支付宝支付集成

def create_alipay_qrcode(order_id: str, amount: float, subject: str) -> str:
    "生成支付宝付款二维码"
    import alipay

    app_private_key = open("config/alipay_private_key.pem").read()
    alipay_public_key = open("config/alipay_public_key.pem").read()

    a = alipay.AliPay(
        appid="YOUR_APP_ID",
        app_notify_url="https://your-domain.com/api/payment/alipay/notify",
        app_private_key_string=app_private_key,
        alipay_public_key_string=alipay_public_key,
    )

    # 生成支付二维码
    qr_code = a.api_alipay_trade_precreate(
        out_trade_no=order_id,
        total_amount=amount,
        subject=subject,
    )
    return qr_code.get("qr_code", "")


## 微信支付集成

def create_wechat_qrcode(order_id: str, amount: float, description: str) -> str:
    "生成微信支付二维码"
    import requests

    url = "https://api.mch.weixin.qq.com/v3/pay/transactions/native"
    headers = {
        "Authorization": "WECHATPAY2-SHA256-RSA2048 YOUR_SIGNATURE",
        "Content-Type": "application/json",
    }
    data = {
        "mchid": "YOUR_MCH_ID",
        "out_trade_no": order_id,
        "appid": "YOUR_APP_ID",
        "description": description,
        "notify_url": "https://your-domain.com/api/payment/wechat/notify",
        "amount": {"total": int(amount * 100), "currency": "CNY"},
    }
    resp = requests.post(url, json=data, headers=headers)
    return resp.json().get("code_url", "")
"""


# 全局实例
order_system = OrderSystem()
