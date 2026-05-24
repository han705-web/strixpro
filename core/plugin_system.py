"""
Plugin System - 插件系统
支持第三方扩展，构建生态
"""
import os
import sys
import json
import importlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger("strixpro.plugins")


class PluginMeta(type):
    """Plugin metaclass for auto-registration"""
    registry = {}

    def __new__(mcs, name, bases, attrs):
        cls = super().__new__(mcs, name, bases, attrs)
        if name != "BasePlugin":
            mcs.registry[name] = cls
        return cls


class BasePlugin(metaclass=PluginMeta):
    """所有插件必须继承的基类"""

    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    plugin_type: str = "generic"  # scanner, reporter, fingerprint, payload
    requires: List[str] = []
    license: str = "MIT"

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.enabled = True

    def initialize(self) -> bool:
        """插件初始化，返回False表示加载失败"""
        return True

    def cleanup(self):
        """清理资源"""
        pass

    def on_load(self):
        """加载时回调"""
        logger.info(f"Plugin loaded: {self.name} v{self.version}")
        pass

    def on_unload(self):
        """卸载时回调"""
        logger.info(f"Plugin unloaded: {self.name}")
        pass


class PluginManager:
    """插件管理器"""

    def __init__(self, plugins_dir: str = "./plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins: Dict[str, BasePlugin] = {}
        self._loaded = False

    def discover(self) -> List[Dict]:
        """发现所有可用插件"""
        available = []
        if not self.plugins_dir.exists():
            return available

        for path in self.plugins_dir.iterdir():
            if path.suffix == ".py" and not path.name.startswith("_"):
                available.append({
                    "path": str(path),
                    "name": path.stem,
                    "type": "script",
                })
            elif path.is_dir() and (path / "__init__.py").exists():
                available.append({
                    "path": str(path),
                    "name": path.name,
                    "type": "package",
                })

        # Check registered plugins
        for name, cls in PluginMeta.registry.items():
            if name != "BasePlugin" and name not in [p["name"] for p in available]:
                available.append({
                    "path": f"core.plugins.{name}",
                    "name": name,
                    "type": "builtin",
                })

        return available

    def load_all(self) -> int:
        """加载所有插件"""
        count = 0
        available = self.discover()
        for info in available:
            try:
                self._load_plugin(info)
                count += 1
            except Exception as e:
                logger.error(f"Failed to load plugin {info['name']}: {e}")
        self._loaded = True
        return count

    def _load_plugin(self, info: Dict):
        """加载单个插件"""
        name = info["name"]

        if info["type"] == "script":
            spec = importlib.util.spec_from_file_location(name, info["path"])
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                # Check if any classes in the module extend BasePlugin
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr != BasePlugin:
                        plugin = attr()
                        self._register(plugin)
        elif info["type"] == "package":
            mod = importlib.import_module(name)
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr != BasePlugin:
                    plugin = attr()
                    self._register(plugin)

    def _register(self, plugin: BasePlugin):
        """注册插件"""
        key = plugin.name or plugin.__class__.__name__
        if key in self.plugins:
            logger.warning(f"Plugin {key} already registered, skipping")
            return
        if plugin.initialize():
            self.plugins[key] = plugin
            plugin.on_load()
            logger.info(f"Plugin registered: {key}")

    def get(self, name: str) -> Optional[BasePlugin]:
        return self.plugins.get(name)

    def get_by_type(self, plugin_type: str) -> List[BasePlugin]:
        return [p for p in self.plugins.values() if p.plugin_type == plugin_type]

    def unload(self, name: str):
        if name in self.plugins:
            self.plugins[name].cleanup()
            self.plugins[name].on_unload()
            del self.plugins[name]

    def unload_all(self):
        for name in list(self.plugins.keys()):
            self.unload(name)

    def list_plugins(self) -> List[Dict]:
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "type": p.plugin_type,
                "enabled": p.enabled,
            }
            for p in self.plugins.values()
        ]
