"""晋升回执：持久化在最后一步，因此"晋升已持久化但回执丢失"是一个必须被恢复逻辑覆盖的真实状态。"""

from __future__ import annotations

import os
from typing import Any

from .digest import canonical_json, digest_json
from .paths import atomic_write


def receipt_name(relpath: str) -> str:
    safe = relpath.replace("/", "__").replace("\\", "__")
    return f"{safe}.receipt.json"


def build_receipt(*, relpath: str, codename: str, digest_hex: str, target_root: str,
                  approval_digest_hex: str, decision_hash: str, view_version: int) -> dict[str, Any]:
    body = {
        "version": 1,
        "relpath": relpath,
        "codename": codename,
        "digest": digest_hex.lower(),
        "target_root": target_root,
        "approval_digest": approval_digest_hex,
        "decision_hash": decision_hash,
        "view_version": view_version,
    }
    body["receipt_digest"] = digest_json(body)
    return body


def write_receipt(receipts_dir: str, receipt: dict[str, Any]) -> str:
    path = os.path.join(receipts_dir, receipt_name(receipt["relpath"]))
    atomic_write(path, canonical_json(receipt))
    return path


def receipt_exists(receipts_dir: str, relpath: str) -> bool:
    return os.path.exists(os.path.join(receipts_dir, receipt_name(relpath)))
