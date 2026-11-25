"""双控制人审批。

审批记录（approval）强绑定四要素：
  1. target_root  目标允许根（规范化路径，逐字节参与签名）
  2. full_digest  制品完整 SHA-256 摘要（不是文件名、不是截断摘要）
  3. codename     代号（业务标识）
  4. source_aliases 声明过的全部来源别名（规范化后参与签名，任何别名都必须解析回同一对象）
并且必须由两个相互独立的控制人分别 HMAC 签署（不同 keyid、不同密钥）。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from .digest import b64_random, canonical_json, digest_json, hmac_verify, hmac_sign
from .errors import ApprovalError
from .paths import atomic_write, resolved

APPROVAL_VERSION = 1


@dataclass(frozen=True)
class Controller:
    keyid: str
    key: bytes

    @classmethod
    def generate(cls, keyid: str) -> "Controller":
        return cls(keyid=keyid, key=b64_random(32).encode("ascii"))


class KeyStore:
    """控制人密钥库（本地合成场景：独立 JSON，访问权限由 OS 文件 ACL 负责）。"""

    def __init__(self, path: str, controllers: dict[str, Controller] | None = None):
        self.path = path
        self._controllers = controllers or {}

    @classmethod
    def create(cls, path: str, keyids: tuple[str, str] = ("alice", "bob")) -> "KeyStore":
        if len(set(keyids)) != 2:
            raise ApprovalError("必须提供两个相互独立的控制人标识")
        controllers = {kid: Controller.generate(kid) for kid in keyids}
        store = cls(path, controllers)
        store.save()
        return store

    @classmethod
    def load(cls, path: str) -> "KeyStore":
        with open(path, "rb") as fh:
            raw = json.loads(fh.read().decode("utf-8"))
        controllers = {
            kid: Controller(keyid=kid, key=entry["key"].encode("ascii"))
            for kid, entry in raw["controllers"].items()
        }
        return cls(path, controllers)

    def save(self) -> None:
        payload = {
            "version": 1,
            "controllers": {kid: {"keyid": kid, "key": c.key.decode("ascii")}
                            for kid, c in self._controllers.items()},
        }
        atomic_write(self.path, canonical_json(payload))

    def get(self, keyid: str) -> Controller:
        if keyid not in self._controllers:
            raise ApprovalError(f"未知控制人：{keyid}")
        return self._controllers[keyid]

    def keyids(self) -> list[str]:
        return sorted(self._controllers)


def approval_binding(
    *, target_root: str, full_digest: str, codename: str, source_aliases: list[str]
) -> dict[str, Any]:
    """参与签名的绑定载荷（不含 signatures，避免自指）。"""
    aliases = sorted({resolved(a) for a in source_aliases})
    return {
        "version": APPROVAL_VERSION,
        "target_root": resolved(target_root),
        "full_digest": full_digest.lower(),
        "codename": codename,
        "source_aliases": aliases,
    }


def issue_approval(
    *, keystore: KeyStore, target_root: str, full_digest: str, codename: str,
    source_aliases: list[str], signers: tuple[str, str],
) -> dict[str, Any]:
    """两个独立控制人对同一份绑定载荷分别签名。"""
    binding = approval_binding(
        target_root=target_root, full_digest=full_digest,
        codename=codename, source_aliases=source_aliases,
    )
    if len(set(signers)) != 2:
        raise ApprovalError("双控制人必须是两个不同的 keyid")
    message = canonical_json(binding)
    signatures = {}
    for keyid in signers:
        ctrl = keystore.get(keyid)
        signatures[keyid] = {
            "keyid": keyid,
            "alg": "HMAC-SHA256",
            "sig": hmac_sign(ctrl.key, message),
        }
    approval = dict(binding)
    approval["signatures"] = signatures
    return approval


def save_approval(approval: dict[str, Any], path: str) -> None:
    atomic_write(path, canonical_json(approval))


def load_approval(path: str) -> dict[str, Any]:
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def _binding_of(approval: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in approval.items() if k != "signatures"}


def verify_approval(
    approval: dict[str, Any], *, keystore: KeyStore
) -> dict[str, Any]:
    """全量校验审批记录，失败即抛 ApprovalError；返回规范化绑定载荷。"""
    required = {"version", "target_root", "full_digest", "codename", "source_aliases", "signatures"}
    missing = required - set(approval)
    if missing:
        raise ApprovalError(f"审批记录缺少字段：{sorted(missing)}")
    if approval["version"] != APPROVAL_VERSION:
        raise ApprovalError(f"不支持的审批版本：{approval['version']}")
    sigs = approval["signatures"]
    if not isinstance(sigs, dict) or len(sigs) != 2:
        raise ApprovalError("必须恰好包含两个控制人签名")
    keyids = set(sigs)
    if len(keyids) != 2:
        raise ApprovalError("两个签名必须来自不同控制人")
    binding = _binding_of(approval)
    expected = approval_binding(
        target_root=approval["target_root"],
        full_digest=approval["full_digest"],
        codename=approval["codename"],
        source_aliases=list(approval["source_aliases"]),
    )
    if canonical_json(binding) != canonical_json(expected):
        raise ApprovalError("审批绑定载荷字段不规范（别名未规范化或被改写）")
    message = canonical_json(binding)
    for keyid, entry in sigs.items():
        if entry.get("keyid") != keyid or entry.get("alg") != "HMAC-SHA256":
            raise ApprovalError(f"签名元数据无效：{keyid}")
        ctrl = keystore.get(keyid)
        if not hmac_verify(ctrl.key, message, entry.get("sig", "")):
            raise ApprovalError(f"控制人 {keyid} 的 HMAC 签名无效")
    return expected


def check_approval_matches(
    binding: dict[str, Any], *, target_root: str, full_digest: str,
    codename: str, actual_source: str,
) -> None:
    """晋升时把审批绑定与本次请求逐项核对（含来源别名必须解析回同一对象）。"""
    if binding["target_root"] != resolved(target_root):
        raise ApprovalError(
            f"审批绑定的目标根 {binding['target_root']} 与实际目标根 {resolved(target_root)} 不一致"
        )
    if binding["full_digest"] != full_digest.lower():
        raise ApprovalError("审批绑定的完整摘要与制品实际摘要不一致")
    if binding["codename"] != codename:
        raise ApprovalError(f"审批代号 {binding['codename']!r} 与请求代号 {codename!r} 不一致")
    canon_actual = resolved(actual_source)
    if canon_actual not in binding["source_aliases"]:
        raise ApprovalError(
            f"实际来源 {canon_actual} 不在审批声明的来源别名集合内：{binding['source_aliases']}"
        )
    # 别名一致性：审批中的每个别名都必须解析到同一个物理文件
    if os.path.exists(canon_actual):
        for alias in binding["source_aliases"]:
            if not os.path.exists(alias):
                raise ApprovalError(f"审批声明的来源别名不存在：{alias}")
            if not os.path.samefile(alias, canon_actual):
                raise ApprovalError(
                    f"来源别名 {alias} 与实际来源 {canon_actual} 不是同一物理对象，别名偷换被拒绝"
                )


def approval_digest(approval: dict[str, Any]) -> str:
    """审批记录自身的摘要（写入决定日志/回执用）。"""
    return digest_json(approval)
