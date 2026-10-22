"""Local device allowlist with atomic writes and restrictive POSIX permissions."""
import json
import os
import tempfile
import threading
from pathlib import Path


class DeviceAllowlist:
    """Stores device identifiers only; never stores file contents or credentials."""
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._entries = self._load()

    def _load(self) -> set[str]:
        try:
            obj = json.loads(self.path.read_text(encoding="utf-8"))
            values = obj["devices"]
            if not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values):
                raise ValueError("invalid allowlist")
            return set(values)
        except FileNotFoundError:
            return set()
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError(f"invalid device allowlist at {self.path}") from exc

    def contains(self, identity: str) -> bool:
        with self._lock:
            return identity in self._entries

    def entries(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._entries)

    def add(self, identity: str) -> None:
        if not identity:
            raise ValueError("device identity must not be empty")
        with self._lock:
            self._entries.add(identity)
            self._save()

    def remove(self, identity: str) -> None:
        with self._lock:
            self._entries.discard(identity)
            self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".devices-", suffix=".tmp", dir=self.path.parent)
        tmp = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump({"version": 1, "devices": sorted(self._entries)}, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass  # Windows ACLs are inherited from the user's profile directory.
            os.replace(tmp, self.path)
        finally:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
