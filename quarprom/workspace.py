"""工作区目录布局与配置（目标根绑定的持久化锚点）。"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .digest import canonical_json
from .paths import atomic_write, ensure_dir, resolved

CONFIG_NAME = "config.json"
KEYSTORE_NAME = "controllers.keys.json"
LOG_NAME = "decisions.log"
RECEIPTS_DIR = "receipts"
JOURNALS_DIR = "journals"
VIEWS_DIR = "views"
BLOBS_DIR = "blobs"
QUARANTINE_DIR = "quarantine"
ALLOWED_DIR = "allowed"
CRASH_TRACE = "crash_trace.json"
RECOVERY_REPORT = "recovery_report.json"


@dataclass(frozen=True)
class Workspace:
    root: str

    @classmethod
    def create(cls, root: str, quarantine_root: str, allowed_root: str) -> "Workspace":
        ws = cls(resolved(root))
        for d in (
            ws.root, ws.quarantine, ws.allowed, ws.receipts_dir, ws.journals_dir,
            ws.views_dir, ws.blobs_dir,
        ):
            ensure_dir(d)
        ensure_dir(quarantine_root)
        ensure_dir(allowed_root)
        cfg = {
            "version": 1,
            "quarantine_root": resolved(quarantine_root),
            "allowed_root": resolved(allowed_root),
        }
        atomic_write(ws.config_path, canonical_json(cfg))
        return ws

    @classmethod
    def open(cls, root: str) -> "Workspace":
        ws = cls(resolved(root))
        if not os.path.exists(ws.config_path):
            raise FileNotFoundError(f"工作区配置不存在：{ws.config_path}")
        return ws

    def _p(self, name: str) -> str:
        return os.path.join(self.root, name)

    @property
    def config_path(self) -> str:
        return self._p(CONFIG_NAME)

    @property
    def keystore_path(self) -> str:
        return self._p(KEYSTORE_NAME)

    @property
    def log_path(self) -> str:
        return self._p(LOG_NAME)

    @property
    def receipts_dir(self) -> str:
        return self._p(RECEIPTS_DIR)

    @property
    def journals_dir(self) -> str:
        return self._p(JOURNALS_DIR)

    @property
    def views_dir(self) -> str:
        return self._p(VIEWS_DIR)

    @property
    def blobs_dir(self) -> str:
        return self._p(BLOBS_DIR)

    @property
    def quarantine(self) -> str:
        return self._p(QUARANTINE_DIR)

    @property
    def allowed(self) -> str:
        return self._p(ALLOWED_DIR)

    @property
    def crash_trace_path(self) -> str:
        return self._p(CRASH_TRACE)

    @property
    def recovery_report_path(self) -> str:
        return self._p(RECOVERY_REPORT)

    def load_config(self) -> dict:
        with open(self.config_path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))

    def bound_roots(self) -> tuple[str, str]:
        """返回配置绑定的（隔离根，允许根），均为规范形态。"""
        cfg = self.load_config()
        return cfg["quarantine_root"], cfg["allowed_root"]
