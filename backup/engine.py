"""Incremental, resumable folder backup into an unlocked encrypted vault."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from core.errors import VaultError
from core.paths import normalize_logical
from vault.vault import Vault

_MANIFEST_NAMESPACE = "securevault.backup.v1"
_DEFAULT_OMIT_DIRS = {
    "$recycle.bin", "system volume information", "recovery",
    "windows", "program files", "program files (x86)", "programdata",
}


class BackupCancelled(Exception):
    """Raised internally to stop a running backup at a chunk boundary."""


@dataclass(frozen=True)
class BackupProgress:
    current_file: str
    completed_files: int
    total_files: int
    completed_bytes: int
    total_bytes: int
    status: str


@dataclass
class BackupResult:
    run_id: str
    copied: int = 0
    skipped: int = 0
    failed: int = 0
    bytes_copied: int = 0
    cancelled: bool = False
    errors: list[str] = field(default_factory=list)


class _CancellableReader:
    def __init__(self, source, cancel: threading.Event):
        self.source = source
        self.cancel = cancel

    def read(self, size=-1):
        if self.cancel.is_set():
            raise BackupCancelled()
        return self.source.read(size)


class BackupEngine:
    """Back up explicitly selected local folders/files without plaintext staging.

    Each successful file is committed to the vault before its encrypted metadata is
    checkpointed, so a stopped run resumes by skipping committed unchanged files.
    """
    def __init__(self, vault: Vault, *, excluded_dirs: Iterable[str] = _DEFAULT_OMIT_DIRS):
        self.vault = vault
        self.excluded_dirs = {item.casefold() for item in excluded_dirs}
        self._run_lock = threading.Lock()

    def run(self, sources: Iterable[str | Path], *, device_identity: str = "manual",
            cancel_event: threading.Event | None = None,
            on_progress: Callable[[BackupProgress], None] | None = None) -> BackupResult:
        if self.vault.locked:
            raise VaultError("unlock the vault before starting a backup")
        if not self._run_lock.acquire(blocking=False):
            raise VaultError("a backup is already running")
        cancel = cancel_event or threading.Event()
        report = on_progress or (lambda _progress: None)
        run_id = f"{int(time.time())}-{os.urandom(4).hex()}"
        result = BackupResult(run_id)
        try:
            roots = self._normalize_sources(sources)
            if not roots:
                raise ValueError("select at least one existing file or folder")
            root_labels = self._labels(roots)
            candidates, discovery_errors = self._collect_files(roots)
            total_bytes = sum(size for _, _, _, _, size, _ in candidates)
            manifest = self.vault.get_metadata(_MANIFEST_NAMESPACE, {"version": 1, "sources": {}, "runs": []})
            if manifest.get("version") != 1:
                raise VaultError("unsupported backup manifest version")
            file_index = {row["path"]: row for row in self.vault.list_files()}
            result.run_id = run_id
            for error_path, error_type, error_message in discovery_errors:
                result.failed += 1
                result.errors.append(f"{error_path}: {error_type}: {error_message}")
                self._record_error(manifest, run_id, error_path, error_type, error_message)
            completed_bytes = 0
            for position, (root, source_id, relative, source_path, size, stat) in enumerate(candidates, 1):
                logical = normalize_logical(f"{root_labels[source_id]}/{relative}")
                old = manifest["sources"].get(source_id, {}).get("files", {}).get(relative)
                existing = file_index.get(logical)
                if (old and existing and old.get("size") == size and
                        old.get("mtime_ns") == stat.st_mtime_ns and
                        existing.get("size") == size and existing.get("mtime") == stat.st_mtime):
                    result.skipped += 1
                    completed_bytes += size
                    report(BackupProgress(logical, position, len(candidates), completed_bytes,
                                          total_bytes, "unchanged"))
                    continue
                if cancel.is_set():
                    result.cancelled = True
                    break
                try:
                    with source_path.open("rb") as stream:
                        stored = self.vault.add_stream(logical, _CancellableReader(stream, cancel), stat.st_mtime)
                    after = source_path.stat()
                    changed_during_read = (after.st_size != stat.st_size or
                                           after.st_mtime_ns != stat.st_mtime_ns)
                    if changed_during_read:
                        # The authenticated snapshot is valid, but the next run must
                        # retry because the source changed while it was being read.
                        file_record = {"size": -1, "mtime_ns": -1, "sha256": stored["sha256"],
                                       "status": "retry"}
                        result.errors.append(f"{logical}: source changed during backup; queued for retry")
                        result.failed += 1
                        self._record_error(manifest, result.run_id, logical,
                                           "SourceChanged", "source changed during backup")
                    else:
                        file_record = {"size": size, "mtime_ns": stat.st_mtime_ns,
                                       "sha256": stored["sha256"], "status": "saved"}
                        result.copied += 1
                        result.bytes_copied += size
                    source_record = manifest["sources"].setdefault(source_id, {
                        "root": str(root), "device_identity": device_identity, "files": {}})
                    source_record["files"][relative] = file_record
                    self._checkpoint(manifest, result, device_identity)
                    file_index[logical] = stored
                    completed_bytes += size
                    report(BackupProgress(logical, position, len(candidates), completed_bytes,
                                          total_bytes, "saved" if not changed_during_read else "retry needed"))
                except BackupCancelled:
                    result.cancelled = True
                    break
                except (OSError, ValueError, VaultError) as exc:
                    result.failed += 1
                    result.errors.append(f"{logical}: {type(exc).__name__}: {exc}")
                    self._record_error(manifest, result.run_id, logical, type(exc).__name__, str(exc))
                    self._checkpoint(manifest, result, device_identity)
                    report(BackupProgress(logical, position, len(candidates), completed_bytes,
                                          total_bytes, "failed"))
            if result.cancelled:
                pass
            elif not candidates:
                result.skipped = 0
                report(BackupProgress("", 0, 0, 0, 0, "no files found"))
            self._checkpoint(manifest, result, device_identity)
            return result
        finally:
            self._run_lock.release()

    def _checkpoint(self, manifest: dict, result: BackupResult, device_identity: str) -> None:
        run = next((row for row in manifest["runs"] if row.get("run_id") == result.run_id), None)
        if run is None:
            run = {"run_id": result.run_id, "device": device_identity, "started": time.time()}
            manifest["runs"].append(run)
        run.update({"updated": time.time(), "copied": result.copied,
                    "skipped": result.skipped, "failed": result.failed,
                    "cancelled": result.cancelled})
        # Keep encrypted history bounded while preserving enough recent context.
        manifest["runs"] = manifest["runs"][-100:]
        self.vault.set_metadata(_MANIFEST_NAMESPACE, manifest)

    def manifest(self) -> dict:
        """Return the decrypted manifest for use by an already-unlocked UI."""
        return self.vault.get_metadata(_MANIFEST_NAMESPACE,
                                       {"version": 1, "sources": {}, "runs": [], "errors": []})

    @staticmethod
    def _record_error(manifest: dict, run_id: str, logical_path: str,
                      error_type: str, message: str) -> None:
        errors = manifest.setdefault("errors", [])
        errors.append({"run_id": run_id, "path": logical_path, "type": error_type,
                       "message": message[:500], "time": time.time()})
        manifest["errors"] = errors[-500:]

    def _normalize_sources(self, sources: Iterable[str | Path]) -> list[Path]:
        roots = []
        seen = set()
        vault_root = self.vault.path.resolve()
        for item in sources:
            original = Path(item).expanduser()
            if _is_linklike(original):
                raise ValueError(f"symlink sources are not supported: {original}")
            path = original.resolve(strict=True)
            if not path.is_file() and not path.is_dir():
                raise ValueError(f"source is not a regular file or folder: {path}")
            try:
                path.relative_to(vault_root)
            except ValueError:
                pass
            else:
                raise ValueError("the vault folder cannot be backed up into itself")
            marker = os.path.normcase(str(path))
            if marker not in seen:
                seen.add(marker)
                roots.append(path)
        # A selected parent already includes every selected child.
        minimal = []
        for path in sorted(roots, key=lambda p: (len(p.parts), str(p).casefold())):
            if not any(path == parent or _is_child(path, parent) for parent in minimal if parent.is_dir()):
                minimal.append(path)
        return minimal

    @staticmethod
    def _labels(roots: list[Path]) -> dict[str, str]:
        names: dict[str, list[tuple[str, Path]]] = {}
        ids = {}
        for root in roots:
            sid = hashlib.sha256(os.path.normcase(str(root)).encode("utf-8")).hexdigest()[:16]
            ids[sid] = root
            label = root.drive.rstrip(":\\/") if root.anchor and not root.name else root.name
            label = label or "selected"
            names.setdefault(label.casefold(), []).append((label, root))
        labels = {}
        for sid, root in ids.items():
            label = root.drive.rstrip(":\\/") if root.anchor and not root.name else root.name
            label = label or "selected"
            if len(names[label.casefold()]) > 1:
                label = f"{label}-{sid[:6]}"
            labels[sid] = label
        return labels

    def _collect_files(self, roots: list[Path]):
        items = []
        discovery_errors = []
        vault_root = self.vault.path.resolve()
        for root in roots:
            source_id = hashlib.sha256(os.path.normcase(str(root)).encode("utf-8")).hexdigest()[:16]
            if root.is_file():
                candidates = [(root.parent, root)]
            else:
                candidates = []
                for current, dirs, files in os.walk(root, topdown=True, followlinks=False,
                                                     onerror=lambda exc: discovery_errors.append(
                                                         (str(exc.filename or root), type(exc).__name__, str(exc)))):
                    current_path = Path(current)
                    kept = []
                    for directory in dirs:
                        child = current_path / directory
                        is_volume_root_child = bool(child.anchor) and child.parent == Path(child.anchor)
                        if ((directory.casefold() in self.excluded_dirs and is_volume_root_child)
                                or _is_linklike(child)):
                            continue
                        try:
                            child.resolve().relative_to(vault_root)
                            continue
                        except ValueError:
                            pass
                        kept.append(directory)
                    dirs[:] = kept
                    for filename in files:
                        source = current_path / filename
                        if _is_linklike(source):
                            continue
                        try:
                            source.resolve().relative_to(vault_root)
                            continue
                        except ValueError:
                            pass
                        candidates.append((root, source))
            for base, source in candidates:
                try:
                    st = source.stat()
                    if not source.is_file():
                        continue
                    relative = source.name if root.is_file() else source.relative_to(root).as_posix()
                    normalize_logical(relative)
                    items.append((root, source_id, relative, source, st.st_size, st))
                except (OSError, ValueError) as exc:
                    discovery_errors.append((str(source), type(exc).__name__, str(exc)))
                    continue
        items.sort(key=lambda item: (item[1], item[2].casefold()))
        return items, discovery_errors


def _is_child(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return path != parent
    except ValueError:
        return False


def _is_linklike(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())
