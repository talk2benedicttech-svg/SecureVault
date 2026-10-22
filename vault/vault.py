"""Encrypted vault: create / unlock / lock / add / list / restore / verify / change password."""
import hashlib
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Optional

from core.errors import (AuthenticationError, IntegrityError, VaultError,
                         VaultLockedError, WeakPasswordError)
from core.paths import normalize_logical, safe_join
from . import crypto, keyslots
from .kdf import KdfParams, calibrate

HEADER = "vault.header"
INDEX = "index.enc"
OBJECTS = "objects"
MIN_PASSWORD_LEN = 10


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class _Hashing:
    """Read-wrapper computing SHA-256 (integrity) and keyed HMAC (dedupe) as data streams past."""
    def __init__(self, src: BinaryIO, dedupe_key: bytes, on_read=None):
        self.src, self.sha, self.mac, self.size = src, hashlib.sha256(), crypto.content_mac(dedupe_key), 0
        self.on_read = on_read

    def read(self, n: int = -1) -> bytes:
        b = self.src.read(n)
        self.sha.update(b); self.mac.update(b); self.size += len(b)
        if b and self.on_read:
            self.on_read()
        return b


class Vault:
    def __init__(self, path: Path, master: bytearray, header: dict,
                 inactivity_timeout: Optional[float], on_lock: Optional[Callable[[], None]],
                 production_kdf: bool):
        self.path = Path(path)
        self._master: Optional[bytearray] = master
        self._header = header
        self._production = production_kdf
        self._timeout = inactivity_timeout
        self._on_lock = on_lock
        self._lock = threading.RLock()
        self._timer: Optional[threading.Timer] = None
        self._index: dict = {"files": {}, "objects": {}, "metadata": {}}
        self._load_index()
        self._touch()

    # ---------- lifecycle ----------
    @classmethod
    def create(cls, path, password: str, *, kdf: Optional[KdfParams] = None,
               inactivity_timeout: Optional[float] = 300, on_lock=None,
               _allow_weak_kdf_for_tests: bool = False) -> tuple["Vault", str]:
        path = Path(path)
        if (path / HEADER).exists():
            raise VaultError("a vault already exists at this location")
        if len(password) < MIN_PASSWORD_LEN:
            raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LEN} characters")
        params = kdf or calibrate()
        params.validate(production=not _allow_weak_kdf_for_tests)
        (path / OBJECTS).mkdir(parents=True, exist_ok=True)
        master = bytearray(os.urandom(32))
        vault_id = secrets.token_hex(16)
        rec_raw, rec_text = keyslots.new_recovery_key()
        header = {"version": 1, "vault_id": vault_id, "slots": [
            keyslots.make_password_slot(vault_id, bytes(master), password, params),
            keyslots.make_recovery_slot(vault_id, bytes(master), rec_raw)]}
        _atomic_write(path / HEADER, json.dumps(header, indent=1).encode())
        v = cls(path, master, header, inactivity_timeout, on_lock, not _allow_weak_kdf_for_tests)
        v._save_index()
        return v, rec_text

    @classmethod
    def unlock(cls, path, password: Optional[str] = None, recovery_key: Optional[str] = None, *,
               inactivity_timeout: Optional[float] = 300, on_lock=None,
               _allow_weak_kdf_for_tests: bool = False) -> "Vault":
        path = Path(path)
        try:
            header = json.loads((path / HEADER).read_bytes())
            vid, slots = header["vault_id"], header["slots"]
            assert header["version"] == 1
        except Exception as e:
            raise IntegrityError("vault header missing or unreadable") from e
        prod = not _allow_weak_kdf_for_tests
        master = None
        if password is not None:
            for s in slots:
                if s.get("kind") == "password":
                    master = keyslots.open_password_slot(vid, s, password, prod)
        elif recovery_key is not None:
            raw = keyslots.parse_recovery_key(recovery_key)
            for s in slots:
                if s.get("kind") == "recovery":
                    master = keyslots.open_recovery_slot(vid, s, raw)
        else:
            raise AuthenticationError("password or recovery key required")
        if master is None:
            raise AuthenticationError("no matching keyslot")
        return cls(path, bytearray(master), header, inactivity_timeout, on_lock, prod)

    @property
    def locked(self) -> bool:
        return self._master is None

    def lock(self) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
                self._timer = None
            if self._master is not None:
                for i in range(len(self._master)):   # best-effort wipe
                    self._master[i] = 0
                self._master = None
            self._index = {"files": {}, "objects": {}, "metadata": {}}
        if self._on_lock:
            self._on_lock()

    def _touch(self) -> None:
        with self._lock:
            if self._timer:
                self._timer.cancel()
            if self._timeout and self._master is not None:
                self._timer = threading.Timer(self._timeout, self.lock)
                self._timer.daemon = True
                self._timer.start()

    def _key(self, purpose: bytes) -> bytes:
        if self._master is None:
            raise VaultLockedError("vault is locked")
        return crypto.subkey(bytes(self._master), purpose)

    # ---------- encrypted index ----------
    def _load_index(self) -> None:
        p = self.path / INDEX
        if not p.exists():
            return
        blob = crypto.unseal(self._key(b"index"), b"SVINDEX1" + self._header["vault_id"].encode(), p.read_bytes())
        self._index = json.loads(blob)
        self._index.setdefault("metadata", {})

    def _save_index(self) -> None:
        blob = crypto.seal(self._key(b"index"), b"SVINDEX1" + self._header["vault_id"].encode(),
                           json.dumps(self._index).encode())
        _atomic_write(self.path / INDEX, blob)

    # ---------- operations ----------
    def add_stream(self, logical_path: str, src: BinaryIO, mtime: float = 0.0) -> dict:
        with self._lock:
            self._touch()
            logical = normalize_logical(logical_path)
            hs = _Hashing(src, self._key(b"dedupe"), self._touch)
            obj_id = secrets.token_hex(16)
            tmp = self.path / OBJECTS / (obj_id + ".part")
            try:
                with open(tmp, "wb") as out:
                    crypto.encrypt_stream(self._key(b"data"), bytes.fromhex(obj_id), hs, out)
                    out.flush(); os.fsync(out.fileno())
                content_id = hs.mac.hexdigest()
                existing = next((o for o, m in self._index["objects"].items() if m["content_id"] == content_id), None)
                if existing:                       # duplicate content: keep one object
                    tmp.unlink(); obj_id = existing
                else:
                    os.replace(tmp, self.path / OBJECTS / (obj_id + ".bin"))
                    self._index["objects"][obj_id] = {"content_id": content_id, "size": hs.size}
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise
            entry = {"object": obj_id, "size": hs.size, "mtime": mtime,
                     "sha256": hs.sha.hexdigest(), "added": time.time()}
            self._index["files"][logical] = entry
            self._save_index()
            return {"path": logical, **entry}

    def add_file(self, logical_path: str, src_path) -> dict:
        st = os.stat(src_path)
        with open(src_path, "rb") as f:
            return self.add_stream(logical_path, f, st.st_mtime)

    def list_files(self) -> list[dict]:
        with self._lock:
            self._touch(); self._key(b"index")
            return [{"path": p, **e} for p, e in sorted(self._index["files"].items())]

    def get_metadata(self, namespace: str, default=None):
        """Read application metadata from the encrypted vault index."""
        with self._lock:
            self._touch(); self._key(b"index")
            return self._index["metadata"].get(namespace, default)

    def set_metadata(self, namespace: str, value) -> None:
        """Persist application metadata inside the authenticated encrypted index."""
        if not namespace or not isinstance(namespace, str):
            raise ValueError("metadata namespace must be a non-empty string")
        with self._lock:
            self._touch(); self._key(b"index")
            self._index["metadata"][namespace] = value
            self._save_index()

    def _open_object(self, entry: dict) -> Iterator[bytes]:
        obj = self.path / OBJECTS / (entry["object"] + ".bin")
        if not obj.exists():
            raise IntegrityError("backup object missing")
        with open(obj, "rb") as f:
            for chunk in crypto.decrypt_stream(self._key(b"data"), bytes.fromhex(entry["object"]), f):
                self._touch()
                yield chunk

    def read_file(self, logical_path: str) -> bytes:
        """Fully authenticated read into memory (use restore_file for large files)."""
        with self._lock:
            self._touch()
            entry = self._index["files"].get(normalize_logical(logical_path))
            if not entry:
                raise VaultError("file not in vault")
            data = b"".join(self._open_object(entry))
            if hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise IntegrityError("hash mismatch")
            return data

    def restore_file(self, logical_path: str, dest_root) -> Path:
        """Restore to dest_root, verifying every chunk and the final hash; never leaves bad output."""
        with self._lock:
            self._touch()
            logical = normalize_logical(logical_path)
            entry = self._index["files"].get(logical)
            if not entry:
                raise VaultError("file not in vault")
            target = safe_join(Path(dest_root), logical)
            target.parent.mkdir(parents=True, exist_ok=True)
            part = target.with_name(target.name + ".restoring")
            sha = hashlib.sha256()
            try:
                with open(part, "wb") as out:
                    for chunk in self._open_object(entry):
                        sha.update(chunk); out.write(chunk)
                if sha.hexdigest() != entry["sha256"]:
                    raise IntegrityError("hash mismatch after restore")
                os.replace(part, target)
                if entry.get("mtime"):
                    os.utime(target, (entry["mtime"], entry["mtime"]))
            except BaseException:
                part.unlink(missing_ok=True)
                raise
            return target

    def verify(self) -> list[str]:
        """Check every file. Returns list of problem descriptions (empty = all good)."""
        problems = []
        with self._lock:
            self._touch()
            for logical, entry in self._index["files"].items():
                try:
                    sha = hashlib.sha256()
                    for chunk in self._open_object(entry):
                        sha.update(chunk)
                    if sha.hexdigest() != entry["sha256"]:
                        problems.append(f"{logical}: hash mismatch")
                except IntegrityError as e:
                    problems.append(f"{logical}: {e}")
        return problems

    def change_password(self, new_password: str, *, kdf: Optional[KdfParams] = None,
                        _allow_weak_kdf_for_tests: bool = False) -> None:
        """Re-wrap the master key under a new password. Caller must already be unlocked."""
        if len(new_password) < MIN_PASSWORD_LEN:
            raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LEN} characters")
        with self._lock:
            self._touch()
            params = kdf or calibrate()
            params.validate(production=not _allow_weak_kdf_for_tests)
            vid = self._header["vault_id"]
            new_slot = keyslots.make_password_slot(vid, bytes(self._master), new_password, params)
            hdr = dict(self._header)
            hdr["slots"] = [new_slot if s["kind"] == "password" else s for s in self._header["slots"]]
            _atomic_write(self.path / HEADER, json.dumps(hdr, indent=1).encode())
            self._header = hdr

    def rotate_recovery_key(self) -> str:
        with self._lock:
            self._touch()
            raw, text = keyslots.new_recovery_key()
            vid = self._header["vault_id"]
            slot = keyslots.make_recovery_slot(vid, bytes(self._master), raw)
            hdr = dict(self._header)
            hdr["slots"] = [slot if s["kind"] == "recovery" else s for s in self._header["slots"]]
            _atomic_write(self.path / HEADER, json.dumps(hdr, indent=1).encode())
            self._header = hdr
            return text
