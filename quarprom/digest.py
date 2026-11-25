"""SHA-256 摘要、HMAC 签名与规范化 JSON（全部标准库）。"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

_CHUNK = 1 << 20


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj: Any) -> bytes:
    """确定性 JSON：sort_keys、无多余空白、不转义非 ASCII、LF 换行。"""
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest_json(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj))


def hmac_sign(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, message: bytes, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature or "")


def b64_random(n: int = 32) -> str:
    import base64
    import secrets

    return base64.urlsafe_b64encode(secrets.token_bytes(n)).decode("ascii").rstrip("=")
