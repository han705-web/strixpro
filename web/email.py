"""
StrixPro Email Service - 邮件发送
支持 SMTP 配置，通过后台管理界面设置
"""
import smtplib
import json
import logging
from email.mime.text import MIMEText
from pathlib import Path

logger = logging.getLogger("strixpro.web.email")

SMTP_CONFIG_FILE = Path(__file__).parent.parent / "data" / "smtp_config.json"


def load_smtp_config() -> dict:
    try:
        if SMTP_CONFIG_FILE.exists():
            return json.loads(SMTP_CONFIG_FILE.read_text())
    except Exception as e:
        logger.error("Load SMTP config failed: %s", e)
    return {
        "enabled": False,
        "host": "",
        "port": 587,
        "user": "",
        "password": "",
        "from_addr": "",
        "from_name": "StrixPro",
    }


def save_smtp_config(cfg: dict):
    SMTP_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))


def send_email(to: str, subject: str, body_text: str) -> dict:
    cfg = load_smtp_config()
    if not cfg.get("enabled") or not cfg.get("host"):
        return {"success": False, "error": "SMTP 未配置"}

    try:
        msg = MIMEText(body_text, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = f"{cfg.get('from_name', 'StrixPro')} <{cfg['from_addr']}>"
        msg["To"] = to

        with smtplib.SMTP(cfg["host"], int(cfg.get("port", 587))) as server:
            server.starttls()
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["from_addr"], [to], msg.as_string())

        logger.info("Email sent to %s: %s", to, subject)
        return {"success": True}

    except Exception as e:
        logger.error("Send email failed: %s", e)
        return {"success": False, "error": str(e)}


def send_license_email(to: str, username: str, license_key: str, product_name: str, expires_at: int) -> dict:
    import time
    expire_date = time.strftime("%Y-%m-%d", time.localtime(expires_at))
    body = f"""尊敬的 {username}，

感谢您购买 StrixPro {product_name}！

您的 License Key 已生成，请妥善保管：

━━━━━━━━━━━━━━━━━━━
License Key: {license_key}
产品: {product_name}
有效期至: {expire_date}
━━━━━━━━━━━━━━━━━━━

激活说明：
1. 下载 StrixPro: https://occurred-hear-cycling-craps.trycloudflare.com/download
2. 运行 StrixPro 后，在设置中输入 License Key 激活
3. 激活后即可享用全部 Pro 功能

您也可以随时在个人中心查看您的 License：
https://occurred-hear-cycling-craps.trycloudflare.com/profile

如有任何问题，请联系我们。

StrixPro 团队
"""
    return send_email(to, f"StrixPro {product_name} - License Key 已生成", body)


def send_order_confirmation_email(to: str, username: str, order_id: str, product_name: str, price: float) -> dict:
    body = f"""尊敬的 {username}，

您的订单已确认！

━━━━━━━━━━━━━━━━━━━
订单编号: {order_id}
产品: {product_name}
金额: ¥{price}
状态: 已支付
━━━━━━━━━━━━━━━━━━━

License Key 已通过另一封邮件发送给您，请注意查收。

您可以在个人中心查看所有订单和 License 信息：
https://occurred-hear-cycling-craps.trycloudflare.com/profile

StrixPro 团队
"""
    return send_email(to, f"StrixPro 订单确认 - {product_name}", body)
