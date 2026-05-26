"""
StrixPro User System - 用户注册/登录/会话管理
"""
import json
import uuid
import time
import hashlib
import secrets
import logging
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger("strixpro.web.users")

USERS_FILE = Path(__file__).parent.parent / "data" / "users.json"
USERS_FILE.parent.mkdir(parents=True, exist_ok=True)

JWT_SECRET = None
SECRET_FILE = Path(__file__).parent.parent / "data" / ".jwt_secret"


def _get_jwt_secret():
    global JWT_SECRET
    if JWT_SECRET:
        return JWT_SECRET
    if SECRET_FILE.exists():
        JWT_SECRET = SECRET_FILE.read_text().strip()
    else:
        JWT_SECRET = secrets.token_hex(32)
        SECRET_FILE.write_text(JWT_SECRET)
    return JWT_SECRET


def _hash_password(password: str, salt: str = None) -> tuple:
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, h


def _create_token(user_id: str) -> str:
    import jwt
    payload = {
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 86400 * 7,  # 7 days
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm="HS256")


def _decode_token(token: str) -> dict:
    import jwt
    try:
        return jwt.decode(token, _get_jwt_secret(), algorithms=["HS256"])
    except:
        return None


def _load_users() -> dict:
    try:
        if USERS_FILE.exists():
            return json.loads(USERS_FILE.read_text())
    except Exception as e:
        logger.error("Load users failed: %s", e)
    return {}


def _save_users(users: dict):
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))


def register_user(email: str, password: str, username: str = "") -> dict:
    if not email or not password:
        return {"error": "邮箱和密码不能为空"}
    if len(password) < 6:
        return {"error": "密码至少6位"}

    users = _load_users()

    if email in users:
        return {"error": "该邮箱已注册"}

    user_id = "U" + datetime.now().strftime("%Y%m%d") + "-" + secrets.token_hex(4).upper()
    salt, pwd_hash = _hash_password(password)

    users[email] = {
        "user_id": user_id,
        "email": email,
        "username": username or email.split("@")[0],
        "salt": salt,
        "password_hash": pwd_hash,
        "created_at": int(time.time()),
        "orders": [],
        "licenses": [],
    }

    _save_users(users)
    token = _create_token(user_id)

    return {
        "success": True,
        "user_id": user_id,
        "token": token,
        "username": users[email]["username"],
    }


def login_user(email: str, password: str) -> dict:
    if not email or not password:
        return {"error": "邮箱和密码不能为空"}

    users = _load_users()
    user = users.get(email)
    if not user:
        return {"error": "邮箱或密码错误"}

    _, expected_hash = _hash_password(password, user["salt"])
    if user["password_hash"] != expected_hash:
        return {"error": "邮箱或密码错误"}

    token = _create_token(user["user_id"])
    return {
        "success": True,
        "user_id": user["user_id"],
        "token": token,
        "username": user["username"],
        "email": email,
    }


def get_user_from_token(token: str) -> dict:
    payload = _decode_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    if not user_id:
        return None

    users = _load_users()
    for email, user in users.items():
        if user["user_id"] == user_id:
            return {
                "user_id": user["user_id"],
                "email": email,
                "username": user["username"],
                "created_at": user["created_at"],
                "orders": user.get("orders", []),
                "licenses": user.get("licenses", []),
            }
    return None


def update_user_orders(email: str, order_id: str, license_key: str):
    users = _load_users()
    user = users.get(email)
    if user:
        if order_id not in user["orders"]:
            user["orders"].append(order_id)
        if license_key and license_key not in user["licenses"]:
            user["licenses"].append(license_key)
        _save_users(users)


def get_user_by_email(email: str) -> dict:
    users = _load_users()
    user = users.get(email)
    if user:
        return {
            "user_id": user["user_id"],
            "email": email,
            "username": user["username"],
            "created_at": user["created_at"],
            "orders": user.get("orders", []),
            "licenses": user.get("licenses", []),
        }
    return None
