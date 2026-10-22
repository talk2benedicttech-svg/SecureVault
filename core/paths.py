"""Path validation for restore and logical vault paths."""
import os
import re
from pathlib import Path, PurePosixPath

from .errors import UnsafePathError

_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}
_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


def normalize_logical(path: str) -> str:
    """Normalise a logical (in-vault) path to forward-slash form, rejecting unsafe input."""
    if not path or "\x00" in path:
        raise UnsafePathError("empty or invalid path")
    p = path.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        raise UnsafePathError(f"absolute paths are not allowed: {path!r}")
    parts = PurePosixPath(p).parts
    if not parts:
        raise UnsafePathError("empty path")
    for part in parts:
        if part in ("..", "."):
            raise UnsafePathError(f"path traversal rejected: {path!r}")
        if _BAD_CHARS.search(part):
            raise UnsafePathError(f"illegal characters in {part!r}")
        if part != part.rstrip(" ."):
            raise UnsafePathError(f"trailing dot/space not allowed: {part!r}")
        if part.split(".")[0].upper() in _RESERVED:
            raise UnsafePathError(f"reserved name: {part!r}")
    return "/".join(parts)


def safe_join(dest_root: Path, logical: str) -> Path:
    """Join a logical path under dest_root, guaranteeing it cannot escape."""
    norm = normalize_logical(logical)
    root = Path(dest_root).resolve()
    target = (root / norm).resolve()
    if os.path.commonpath([str(root), str(target)]) != str(root):
        raise UnsafePathError(f"path escapes destination: {logical!r}")
    return target
