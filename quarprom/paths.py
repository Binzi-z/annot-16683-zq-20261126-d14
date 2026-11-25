"""原生 Windows 路径防御：真实路径解析、重解析点拦截、8.3 短名展开、控制根绑定。

所有函数只使用标准库（os / os.path / ctypes / pathlib）。
设计目标：任何来源别名（junction、符号链接、8.3 短名、大小写、..、尾部分隔符）
都不能把一个受控路径偷换成另一个控制根下的路径。
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import shutil
from pathlib import Path

from .errors import RootAliasError

# Windows 文件属性常量（Win32 API）
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_INVALID_FILE_ATTRIBUTES = ctypes.c_ulong(-1).value
_GET_SHORT_PATH = 0x80001  # GetFullPathNameW 的 flags：8.3 -> 长名（长名优先）
_GET_LONG_PATH = 0x80001

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
if _kernel32 is not None:
    _kernel32.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    _kernel32.GetFileAttributesW.restype = ctypes.c_ulong
    _kernel32.GetFullPathNameW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_wchar_p)
    ]
    _kernel32.GetFullPathNameW.restype = ctypes.c_ulong


def _win32_get_attributes(path: str) -> int:
    attrs = _kernel32.GetFileAttributesW(str(path))
    if attrs == _INVALID_FILE_ATTRIBUTES:
        raise ctypes.WinError(ctypes.get_last_error())
    return attrs


def is_reparse_point(path: str | os.PathLike[str]) -> bool:
    """路径是否为重解析点（junction / 符号链接 / 挂载点）。

    不存在的路径返回 False；Windows 上直接读 Win32 文件属性，
    不依赖 os.path.islink（junction 在 Python 下 islink 行为不稳定）。
    """
    if os.name != "nt":  # 非 Windows 回退到标准库判断
        return os.path.islink(path)
    p = os.path.abspath(os.fspath(path))
    if not os.path.lexists(p):
        return False
    try:
        return bool(_win32_get_attributes(p) & _FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return False


def expand_8_3(path: str | os.PathLike[str]) -> str:
    """把 8.3 短名组件展开成长路径，防止短名别名绕过字符串比较。

    非 Windows 或 API 不可用时原样返回绝对路径。
    """
    p = os.path.abspath(os.fspath(path))
    if os.name != "nt" or _kernel32 is None:
        return p
    buf = ctypes.create_unicode_buffer(32768)
    n = _kernel32.GetFullPathNameW(p, len(buf), buf, None)
    if 0 < n < len(buf):
        return buf.value
    return p


def resolved(path: str | os.PathLike[str]) -> str:
    """受控路径的唯一规范形态：绝对化 -> 8.3 展开 -> realpath 解析全部重解析点 -> normcase。"""
    p = expand_8_3(path)
    p = os.path.realpath(p)  # Windows 上解析 junction/symlink/mount point
    p = os.path.normpath(p)
    return ntpath.normcase(p) if os.name == "nt" else os.path.normcase(p)


def walk_components(path: str) -> list[str]:
    """从根到叶子列出路径的全部前缀组件。"""
    parts: list[str] = []
    drive, rest = ntpath.splitdrive(path) if os.name == "nt" else os.path.splitdrive(path)
    cur = drive + ("\\" if drive and not drive.endswith("\\") else "")
    if not cur:
        cur = os.path.sep
    for component in [c for c in rest.replace("/", os.path.sep).split(os.path.sep) if c]:
        cur = os.path.join(cur, component)
        parts.append(cur)
    return parts


def assert_no_alias_inside(root: str, lexical_target: str) -> None:
    """逐组件检查 root 之下、target 之上不存在重解析点。

    关键：必须扫描"原始词汇路径"（realpath 之前）。realpath 会把 junction 吃掉，
    若先解析再扫描，别名组件已经从路径里消失，检测必然漏报。
    """
    canon_root = resolved(root)
    canon_target = resolved(lexical_target)
    inside = os.path.commonpath([canon_root, canon_target]) == canon_root
    if not inside:
        raise RootAliasError(
            f"目标 {lexical_target!r} 解析后 ({canon_target}) 不在控制根 {root!r} ({canon_root}) 之内"
        )
    # 只扫描控制根"内部"的词汇组件：根之上的系统/用户配置 junction（如 Application Data）
    # 不属于本控制根的管辖范围，不能误伤
    lexical_root = expand_8_3(os.path.abspath(root))
    raw_prefix = expand_8_3(os.path.abspath(lexical_target))
    for component in walk_components(raw_prefix):
        try:
            within = os.path.commonpath([lexical_root, component]) == lexical_root
        except ValueError:
            within = False
        if not within:
            continue
        if is_reparse_point(component):
            raise RootAliasError(
                f"受控根内检测到重解析点别名：{component!r} -> {resolved(component)!r}；"
                f"控制根 {canon_root!r} 不得被别名偷换"
            )


def assert_under_root(root: str, target: str, *, what: str = "路径") -> str:
    """强校验 target 隶属于 root 控制根，返回规范化目标路径。

    三道防线：
      1. 8.3 展开 + realpath 解析后做 commonpath 比较（防 ..、短名、junction 跳出根）；
      2. 对"原始词汇路径"逐组件拒绝重解析点（防根内 junction 偷换；必须在 realpath 之前扫描）；
      3. 同一物理文件的 os.path.samefile 兜底（防硬链接/挂载等价路径混淆）。
    """
    canon_root = resolved(root)
    if not os.path.exists(canon_root):
        raise RootAliasError(f"控制根不存在：{canon_root!r}")
    lexical_abs = expand_8_3(os.path.abspath(target))
    canon_target = resolved(lexical_abs)
    try:
        common = os.path.commonpath([canon_root, canon_target])
    except ValueError:
        raise RootAliasError(f"{what} {target!r} 与控制根 {root!r} 不在同一卷命名空间") from None
    if common != canon_root:
        raise RootAliasError(
            f"{what} {target!r} 解析为 {canon_target}，越出控制根 {canon_root}（commonpath={common!r}）"
        )
    # 传入未被 realpath 处理的词汇路径，保证别名组件仍在
    assert_no_alias_inside(canon_root, lexical_abs)
    if os.path.exists(canon_target) and os.path.exists(canon_root):
        try:
            if os.path.samefile(canon_target, canon_root) and canon_target != canon_root:
                raise RootAliasError(f"{what} 与控制根指向同一物理对象，疑似别名偷换：{canon_target}")
        except OSError:
            pass
    return canon_target


def ensure_dir(path: str | os.PathLike[str]) -> str:
    os.makedirs(path, exist_ok=True)
    return os.fspath(path)


def fsync_dir(path: str | os.PathLike[str]) -> None:
    """目录 fsync：Windows 下目录句柄不支持常规 flush，用 os.O_RDONLY 打开后 fsync，失败则忽略。"""
    fd = None
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY)
        os.fsync(fd)
    except OSError:
        pass
    finally:
        if fd is not None:
            os.close(fd)


def hardlink_or_copy(src: str, dst: str) -> str:
    """优先硬链接（同卷零拷贝、内容不可被单方改名篡改语义），跨卷回退为字节拷贝。"""
    if os.path.exists(dst):
        raise FileExistsError(dst)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)
    return dst


def atomic_write(path: str, data: bytes) -> None:
    """同目录临时文件 + 原子替换 + 落盘，保证读者永远看不到半截文件。"""
    path = os.path.abspath(path)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    fsync_dir(os.path.dirname(path))


def relative_posix(root: str, target: str) -> str:
    """控制根内相对路径，统一用正斜杠作为清单/日志里的稳定标识。"""
    rel = os.path.relpath(target, resolved(root))
    return rel.replace(os.path.sep, "/")
