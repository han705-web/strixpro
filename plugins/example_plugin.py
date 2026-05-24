"""
示例插件 - 自定义指纹插件
展示如何扩展StrixPro的指纹数据库
"""
from core.plugin_system import BasePlugin


class CustomFingerprintPlugin(BasePlugin):
    name = "custom-fingerprints"
    version = "1.0.0"
    description = "自定义浏览器指纹集"
    plugin_type = "fingerprint"

    def __init__(self, config=None):
        super().__init__(config)
        self.custom_profiles = {}

    def initialize(self) -> bool:
        # 注册自定义指纹
        self.custom_profiles = {
            "chrome_mobile": {
                "name": "Chrome Mobile 131",
                "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.39 Mobile Safari/537.36",
                "accept_language": "zh-CN,zh;q=0.9",
            },
            "wechat_browser": {
                "name": "微信内置浏览器",
                "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6778.39 Mobile MQQBrowser/15.0 Safari/537.36",
                "accept_language": "zh-CN,zh;q=0.9",
            },
        }
        return True

    def get_profile(self, name: str) -> dict:
        return self.custom_profiles.get(name)

    def list_custom(self) -> list:
        return [{"id": k, "name": v["name"]} for k, v in self.custom_profiles.items()]
