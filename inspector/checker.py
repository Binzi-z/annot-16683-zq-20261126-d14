"""checker.py —— 独立检查器核心 + CLI。

用法：
  python -m inspector.checker --workspace <工作区根> [--json out.json]
退出码：0 全部通过；1 发现违规；2 检查器自身无法完成（日志断裂等致命问题）。
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac as hmac_mod
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- 独立密码学原语（不依赖 quarprom）

def _canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _digest_json(obj: Any) -> str:
    return _sha256_bytes(_canonical(obj))


def _hmac(key: bytes, msg: bytes) -> str:
    return hmac_mod.new(key, msg, hashlib.sha256).hexdigest()


def _resolved(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.realpath(os.path.abspath(path))))


# ---------------------------------------------------------------- Win32 重解析点检测（独立实现）

_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_INVALID_ATTRS = ctypes.c_ulong(-1).value
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
if _kernel32 is not None:
    _kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    _kernel32.GetFileAttributesW.restype = ctypes.c_ulong


def _is_reparse(path: str) -> bool:
    if os.name != "nt":
        return os.path.islink(path)
    if not os.path.lexists(path):
        return False
    attrs = _kernel32.GetFileAttributesW(path)
    if attrs == _INVALID_ATTRS:
        return False
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)


def _scan_reparse(root: str) -> list[str]:
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            if _is_reparse(full):
                hits.append(full)
    return hits


# ---------------------------------------------------------------- 数据结构

@dataclass
class Finding:
    code: str
    severity: str                 # CRITICAL / HIGH / MEDIUM / INFO
    relpath: str | None
    message: str
    first_visible_ts_ns: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code, "severity": self.severity, "relpath": self.relpath,
            "message": self.message, "first_visible_ts_ns": self.first_visible_ts_ns,
            "evidence": self.evidence,
        }


GENESIS = "0" * 64


# ---------------------------------------------------------------- 主检查流程

def run_check(workspace_root: str) -> dict[str, Any]:
    ws = _resolved(workspace_root)
    findings: list[Finding] = []
    fatal = False

    # C1 配置
    cfg_path = os.path.join(ws, "config.json")
    if not os.path.exists(cfg_path):
        return {"ok": False, "fatal": True,
                "findings": [Finding("C1_NO_CONFIG", "CRITICAL", None,
                                     f"工作区配置缺失：{cfg_path}").to_dict()]}
    with open(cfg_path, "rb") as fh:
        cfg = json.loads(fh.read().decode("utf-8"))
    q_root = _resolved(cfg["quarantine_root"])
    a_root = _resolved(cfg["allowed_root"])
    for label, root in (("隔离根", q_root), ("允许根", a_root)):
        if not os.path.isdir(root):
            findings.append(Finding("C1_ROOT_MISSING", "CRITICAL", None,
                                    f"{label}不存在：{root}"))
            fatal = True

    # 控制人密钥库
    keystore_path = os.path.join(ws, "controllers.keys.json")
    keystore: dict[str, str] = {}
    if os.path.exists(keystore_path):
        with open(keystore_path, "rb") as fh:
            ks = json.loads(fh.read().decode("utf-8"))
        keystore = {kid: e["key"].encode("ascii") for kid, e in ks["controllers"].items()}

    # C2 决定日志哈希链
    log_path = os.path.join(ws, "decisions.log")
    records: list[dict[str, Any]] = []
    if os.path.exists(log_path):
        prev = GENESIS
        with open(log_path, "rb") as fh:
            for lineno, raw_line in enumerate(fh, 1):
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    rec = json.loads(raw_line.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    findings.append(Finding("C2_LOG_CORRUPT", "CRITICAL", None,
                                            f"决定日志第 {lineno} 行无法解析：{exc}"))
                    fatal = True
                    break
                if rec.get("seq") != lineno - 1:
                    findings.append(Finding("C2_SEQ_GAP", "CRITICAL", None,
                                            f"日志序号断裂：第 {lineno} 行 seq={rec.get('seq')}"))
                    fatal = True
                if rec.get("prev") != prev:
                    findings.append(Finding("C2_CHAIN_BROKEN", "CRITICAL", None,
                                            f"记录 {rec.get('seq')} 的 prev 不匹配，日志被改写/分叉"))
                    fatal = True
                base = {k: v for k, v in rec.items() if k != "record_hash"}
                if _digest_json(base) != rec.get("record_hash"):
                    findings.append(Finding("C2_HASH_MISMATCH", "CRITICAL", None,
                                            f"记录 {rec.get('seq')} 内容哈希不匹配，被篡改"))
                    fatal = True
                records.append(rec)
                prev = rec.get("record_hash", prev)
    else:
        findings.append(Finding("C2_NO_LOG", "MEDIUM", None, "决定日志不存在（尚无任何晋升）"))

    # C3/C4 审批记录逐条独立重验（只验 PROMOTED 引用的审批）
    approvals_dir = os.path.join(ws, "approvals")
    approval_cache: dict[str, dict[str, Any]] = {}
    promoted_records = [r for r in records if r.get("kind") == "PROMOTED"]
    for rec in promoted_records:
        payload = rec["payload"]
        codename = payload["codename"]
        ap_path = os.path.join(approvals_dir, f"{codename}.approval.json")
        if not os.path.exists(ap_path):
            findings.append(Finding("C3_APPROVAL_MISSING", "HIGH", payload.get("relpath"),
                                    f"PROMOTED 决定 {rec['seq']} 引用的审批文件缺失：{ap_path}",
                                    rec["ts_ns"]))
            continue
        with open(ap_path, "rb") as fh:
            approval = json.loads(fh.read().decode("utf-8"))
        approval_cache[codename] = approval
        sigs = approval.get("signatures", {})
        if len(sigs) != 2 or len(set(sigs)) != 2:
            findings.append(Finding("C3_NOT_DUAL_CONTROL", "CRITICAL", payload.get("relpath"),
                                    f"审批 {codename} 不满足两个独立控制人：{sorted(sigs)}",
                                    rec["ts_ns"]))
            continue
        binding = {k: v for k, v in approval.items() if k != "signatures"}
        msg = _canonical(binding)
        for keyid, entry in sigs.items():
            if keyid not in keystore:
                findings.append(Finding("C3_UNKNOWN_CONTROLLER", "CRITICAL",
                                        payload.get("relpath"),
                                        f"审批 {codename} 含未知控制人 {keyid}", rec["ts_ns"]))
                continue
            if not hmac_mod.compare_digest(_hmac(keystore[keyid], msg), entry.get("sig", "")):
                findings.append(Finding("C3_BAD_SIGNATURE", "CRITICAL", payload.get("relpath"),
                                        f"控制人 {keyid} 对审批 {codename} 的签名无效",
                                        rec["ts_ns"]))
        # C4 四要素绑定
        if _resolved(approval.get("target_root", "")) != a_root:
            findings.append(Finding("C4_ROOT_BINDING", "CRITICAL", payload.get("relpath"),
                                    f"审批目标根 {approval.get('target_root')} 与配置允许根 {a_root} 不一致",
                                    rec["ts_ns"]))
        if approval.get("full_digest", "").lower() != payload.get("digest", "").lower():
            findings.append(Finding("C4_DIGEST_BINDING", "CRITICAL", payload.get("relpath"),
                                    "审批绑定摘要与决定记录摘要不一致", rec["ts_ns"]))
        if approval.get("codename") != codename:
            findings.append(Finding("C4_CODENAME_BINDING", "HIGH", payload.get("relpath"),
                                    "审批代号与决定记录代号不一致", rec["ts_ns"]))
        # 来源别名：每个别名都必须解析回同一物理对象，且对象必须在隔离根内
        declared_src = payload.get("source")
        for alias in approval.get("source_aliases", []):
            canon = _resolved(alias)
            if not canon.startswith(q_root + os.sep) and canon != q_root:
                findings.append(Finding("C4_ALIAS_OUTSIDE_QUARANTINE", "CRITICAL",
                                        payload.get("relpath"),
                                        f"来源别名 {alias} -> {canon} 越出隔离根 {q_root}",
                                        rec["ts_ns"]))
            elif declared_src and os.path.exists(canon) and os.path.exists(declared_src):
                if not os.path.samefile(canon, declared_src):
                    findings.append(Finding("C4_ALIAS_SWAP", "CRITICAL", payload.get("relpath"),
                                            f"别名 {alias} 与实际来源 {declared_src} 非同一物理对象",
                                            rec["ts_ns"]))

    # C5 控制根内部重解析点（别名偷换的直接物证）
    for label, root in (("允许根", a_root), ("隔离根", q_root)):
        if os.path.isdir(root):
            for hit in _scan_reparse(root):
                findings.append(Finding("C5_REPARSE_POINT", "HIGH",
                                        os.path.relpath(hit, root).replace(os.sep, "/"),
                                        f"{label}内部存在重解析点（junction/symlink）：{hit}"))

    # C6 实际目录 vs 决定日志双向对账
    physical: dict[str, str] = {}
    birth_ns: dict[str, int] = {}
    if os.path.isdir(a_root):
        for dirpath, dirnames, filenames in os.walk(a_root):
            dirnames[:] = [d for d in dirnames if d != ".staging"]
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, a_root).replace(os.sep, "/")
                if rel.startswith(".staging/"):
                    continue
                physical[rel] = _sha256_file(full)
                st = os.stat(full)
                # Windows: st_birthtime（Py3.12）；回退 st_ctime（创建时间）
                birth_ns[rel] = getattr(st, "st_birthtime_ns", None) or st.st_ctime_ns

    latest: dict[str, dict[str, Any]] = {}
    first_abort_ns: dict[str, int] = {}
    for rec in records:
        # 只把 PROMOTED/ABORTED 视为决定；VIEW_PUBLISHED/RECOVERED 等事件不得覆盖决定
        if rec.get("kind") not in ("PROMOTED", "ABORTED"):
            continue
        rel = rec.get("payload", {}).get("relpath")
        if rel is None:
            continue
        latest[rel] = rec
        if rec.get("kind") == "ABORTED" and rel not in first_abort_ns:
            first_abort_ns[rel] = rec["ts_ns"]

    for rel, rec in sorted(latest.items()):
        kind = rec["kind"]
        payload = rec["payload"]
        if kind == "PROMOTED":
            if rel not in physical:
                findings.append(Finding("C6_PROMISED_MISSING", "HIGH", rel,
                                        "决定链记录 PROMOTED 但允许区实际文件缺失",
                                        rec["ts_ns"], {"decision_seq": rec["seq"]}))
            elif physical[rel] != payload["digest"]:
                findings.append(Finding("C6_DIGEST_MISMATCH", "CRITICAL", rel,
                                        f"磁盘摘要与晋升决定不符：{physical[rel]} != {payload['digest']}",
                                        rec["ts_ns"], {"decision_seq": rec["seq"]}))
        elif kind == "ABORTED" and rel in physical:
            findings.append(Finding("C6_ABORTED_BUT_VISIBLE", "CRITICAL", rel,
                                    "已撤销（ABORTED）事务的制品仍在允许区可见——最早越权可见",
                                    first_abort_ns.get(rel, rec["ts_ns"]),
                                    {"abort_seq": rec["seq"],
                                     "abort_reason": payload.get("reason"),
                                     "actual_digest": physical[rel]}))
    for rel, digest_hex in sorted(physical.items()):
        if rel not in latest:
            findings.append(Finding("C6_UNDECIDED_VISIBLE", "CRITICAL", rel,
                                    "允许区出现无任何晋升决定的文件——未授权可见",
                                    birth_ns.get(rel),
                                    {"actual_digest": digest_hex,
                                     "birth_time_ns": birth_ns.get(rel)}))

    # C7 回执核对
    receipts_dir = os.path.join(ws, "receipts")
    for rel, rec in sorted(latest.items()):
        if rec["kind"] != "PROMOTED":
            continue
        safe = rel.replace("/", "__").replace("\\", "__")
        rp = os.path.join(receipts_dir, f"{safe}.receipt.json")
        if not os.path.exists(rp):
            findings.append(Finding("C7_RECEIPT_MISSING", "MEDIUM", rel,
                                    "晋升已持久化但回执缺失（恢复程序应已重建）",
                                    rec["ts_ns"], {"decision_seq": rec["seq"]}))
            continue
        with open(rp, "rb") as fh:
            receipt = json.loads(fh.read().decode("utf-8"))
        if receipt.get("decision_hash") != rec["record_hash"]:
            findings.append(Finding("C7_RECEIPT_DRIFT", "HIGH", rel,
                                    "回执引用的决定哈希与日志记录不一致", rec["ts_ns"]))

    # C8 视图 manifest 与 CAS 内容块
    views_dir = os.path.join(ws, "views")
    blobs_dir = os.path.join(ws, "blobs")
    if os.path.isdir(views_dir):
        for name in sorted(os.listdir(views_dir)):
            if not (name.startswith("v") and name[1:].isdigit()):
                continue
            mp = os.path.join(views_dir, name, "manifest.json")
            if not os.path.exists(mp):
                continue
            with open(mp, "rb") as fh:
                manifest = json.loads(fh.read().decode("utf-8"))
            expect = _digest_json({"version": manifest["version"], "files": manifest["files"]})
            if expect != manifest.get("manifest_digest"):
                findings.append(Finding("C8_MANIFEST_TAMPERED", "HIGH", None,
                                        f"视图 {name} 清单自摘要不符"))
                continue
            for rel, entry in manifest["files"].items():
                bp = os.path.join(blobs_dir, entry["digest"][:2], entry["digest"][2:4],
                                  entry["digest"])
                if not os.path.exists(bp):
                    findings.append(Finding("C8_BLOB_MISSING", "HIGH", rel,
                                            f"视图 {name} 引用的内容块缺失：{entry['digest']}"))
                elif _sha256_file(bp) != entry["digest"]:
                    findings.append(Finding("C8_BLOB_CORRUPT", "CRITICAL", rel,
                                            f"视图 {name} 内容块摘要重算不符"))

    # 汇总：最早越权可见证据
    visible = [f for f in findings if f.code in {
        "C6_ABORTED_BUT_VISIBLE", "C6_UNDECIDED_VISIBLE", "C6_DIGEST_MISMATCH",
        "C4_ALIAS_SWAP", "C4_ALIAS_OUTSIDE_QUARANTINE", "C5_REPARSE_POINT",
    }]
    earliest = sorted(
        visible, key=lambda f: (f.first_visible_ts_ns is None, f.first_visible_ts_ns or 0)
    )[0] if visible else None

    severity_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}
    findings.sort(key=lambda f: (-severity_rank[f.severity],
                                 f.first_visible_ts_ns is None,
                                 f.first_visible_ts_ns or 0, f.code))
    return {
        "workspace": ws,
        "ok": not fatal and not any(f.severity in {"CRITICAL", "HIGH"} for f in findings),
        "fatal": fatal,
        "records_checked": len(records),
        "promotions_checked": len(promoted_records),
        "physical_files": len(physical),
        "findings": [f.to_dict() for f in findings],
        "earliest_unauthorized_evidence": earliest.to_dict() if earliest else None,
    }


# ---------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="quarprom 独立事后检查器（仅标准库）")
    parser.add_argument("--workspace", required=True, help="工作区根目录")
    parser.add_argument("--json", dest="json_out", help="把完整 JSON 报告写入该文件")
    args = parser.parse_args(argv)

    report = run_check(args.workspace)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)

    if report["fatal"]:
        return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
