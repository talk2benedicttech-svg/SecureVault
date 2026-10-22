"""Safe, read-only exports of browser bookmarks and browsing history.

Only bookmark data and history tables are read. Password databases, cookies, session
stores, and authentication tokens are never opened. Active browsers are skipped.
"""
from __future__ import annotations

import configparser
from contextlib import contextmanager
import io
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from core.paths import normalize_logical
from vault.vault import Vault

_CHROMIUM_EPOCH = 11_644_473_600
_BROWSER_MANIFEST_NAMESPACE = "securevault.browser.v1"


@dataclass
class BrowserExportResult:
    copied: int = 0
    skipped: int = 0
    failed: int = 0
    cancelled: bool = False
    errors: list[str] = field(default_factory=list)


class BrowserExporter:
    """Export bookmarks and history into a vault after confirming a browser is closed."""
    def __init__(self, vault: Vault, *, process_check: Callable[[str], bool] | None = None):
        self.vault = vault
        self.process_check = process_check or _browser_running

    def export(self, *, on_progress: Callable[[str], None] | None = None,
               cancel_event: threading.Event | None = None) -> BrowserExportResult:
        if self.vault.locked:
            raise RuntimeError("unlock the vault before exporting browser data")
        report = on_progress or (lambda _message: None)
        result = BrowserExportResult()
        manifest = self.vault.get_metadata(_BROWSER_MANIFEST_NAMESPACE,
                                           {"version": 1, "runs": [], "errors": []})
        run_id = uuid.uuid4().hex
        for browser, process, profiles in _discover_profiles():
            if cancel_event and cancel_event.is_set():
                result.cancelled = True
                break
            if self.process_check(process):
                result.skipped += 1
                message = "browser is running; close it to export data"
                result.errors.append(f"{browser}: {message}")
                self._record_error(manifest, run_id, browser, message)
                report(f"{browser}: skipped because it is running")
                continue
            version = _browser_version(browser)
            for profile, profile_path in profiles:
                if cancel_event and cancel_event.is_set():
                    result.cancelled = True
                    break
                base = f"Browser Data/{_slug(browser)}/{_slug(profile)}"
                for kind in ("bookmarks", "history"):
                    if cancel_event and cancel_event.is_set():
                        result.cancelled = True
                        break
                    try:
                        if browser == "Firefox":
                            rows = (_firefox_bookmarks(profile_path / "places.sqlite") if kind == "bookmarks"
                                    else _firefox_history(profile_path / "places.sqlite"))
                        else:
                            rows = (_chromium_bookmarks(profile_path / "Bookmarks") if kind == "bookmarks"
                                    else _chromium_history(profile_path / "History"))
                        if rows is None:
                            result.skipped += 1
                            continue
                        payload = json.dumps({"browser": browser, "version": version,
                                              "profile": profile, "exported_at": time.time(),
                                              "data_type": kind, "entries": rows},
                                             ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                        logical = normalize_logical(f"{base}/{kind}.json")
                        self.vault.add_stream(logical, io.BytesIO(payload), time.time())
                        result.copied += 1
                        report(f"Exported {browser} {profile} {kind}")
                    except (OSError, sqlite3.Error, ValueError) as exc:
                        result.failed += 1
                        message = f"{type(exc).__name__}: {exc}"
                        result.errors.append(f"{browser}/{profile}/{kind}: {message}")
                        self._record_error(manifest, run_id, f"{browser}/{profile}/{kind}", message)
        manifest["runs"].append({"run_id": run_id, "time": time.time(),
                                 "copied": result.copied, "skipped": result.skipped,
                                 "failed": result.failed, "cancelled": result.cancelled})
        manifest["runs"] = manifest["runs"][-100:]
        self.vault.set_metadata(_BROWSER_MANIFEST_NAMESPACE, manifest)
        return result

    @staticmethod
    def _record_error(manifest: dict, run_id: str, profile: str, message: str) -> None:
        errors = manifest.setdefault("errors", [])
        errors.append({"run_id": run_id, "profile": profile, "message": message[:500],
                       "time": time.time()})
        manifest["errors"] = errors[-500:]


def _discover_profiles():
    local = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    roaming = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    chromium = [
        ("Chrome", "chrome.exe", local / "Google" / "Chrome" / "User Data"),
        ("Edge", "msedge.exe", local / "Microsoft" / "Edge" / "User Data"),
    ]
    for browser, process, user_data in chromium:
        if not user_data.is_dir():
            continue
        display_names = {}
        try:
            local_state = json.loads((user_data / "Local State").read_text(encoding="utf-8"))
            cache = local_state.get("profile", {}).get("info_cache", {})
            display_names = {name: item.get("name", name) for name, item in cache.items()
                             if isinstance(item, dict)}
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
        found = []
        for profile_path in sorted(user_data.iterdir()):
            if (profile_path.is_dir() and profile_path.name.casefold() not in
                    {"system profile", "guest profile"} and
                    ((profile_path / "Bookmarks").is_file() or (profile_path / "History").is_file())):
                found.append((display_names.get(profile_path.name, profile_path.name), profile_path))
        if found:
            yield browser, process, found

    firefox_root = roaming / "Mozilla" / "Firefox"
    profiles_ini = firefox_root / "profiles.ini"
    if profiles_ini.is_file():
        parser = configparser.ConfigParser()
        parser.read(profiles_ini, encoding="utf-8")
        profiles = []
        for section in parser.sections():
            if not section.casefold().startswith("profile"):
                continue
            relative = parser.get(section, "IsRelative", fallback="1") == "1"
            profile_path = Path(parser.get(section, "Path", fallback=""))
            if not profile_path:
                continue
            if relative:
                profile_path = firefox_root / profile_path
            if (profile_path / "places.sqlite").is_file():
                profiles.append((parser.get(section, "Name", fallback=profile_path.name), profile_path))
        if profiles:
            yield "Firefox", "firefox.exe", profiles


def _chromium_bookmarks(path: Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _chromium_history(path: Path):
    if not path.is_file():
        return None
    rows = []
    with _readonly_database(path) as db:
        for url, title, visit_count, chromium_time in db.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls "
                "WHERE last_visit_time > 0 ORDER BY last_visit_time DESC"):
            rows.append({"url": url, "title": title or "", "visit_count": visit_count,
                         "last_visit_unix": chromium_time / 1_000_000 - _CHROMIUM_EPOCH})
    return rows


def _firefox_bookmarks(path: Path):
    if not path.is_file():
        return None
    rows = []
    with _readonly_database(path) as db:
        query = ("SELECT b.id, b.parent, b.title, p.url, b.type FROM moz_bookmarks b "
                 "LEFT JOIN moz_places p ON p.id = b.fk WHERE b.type IN (1, 2) "
                 "ORDER BY b.parent, b.position")
        for row_id, parent, title, url, item_type in db.execute(query):
            rows.append({"id": row_id, "parent_id": parent, "title": title or "",
                         "url": url, "type": "bookmark" if item_type == 1 else "folder"})
    return rows


def _firefox_history(path: Path):
    if not path.is_file():
        return None
    rows = []
    with _readonly_database(path) as db:
        for url, title, visit_count, last_visit in db.execute(
                "SELECT url, title, visit_count, last_visit_date FROM moz_places "
                "WHERE last_visit_date > 0 ORDER BY last_visit_date DESC"):
            rows.append({"url": url, "title": title or "", "visit_count": visit_count,
                         "last_visit_unix": last_visit / 1_000_000})
    return rows


@contextmanager
def _readonly_database(path: Path):
    uri = path.resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=0.5)
    try:
        db.execute("PRAGMA query_only=ON")
        yield db
    finally:
        db.close()


def _browser_running(process: str) -> bool:
    if os.name == "nt":
        try:
            result = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {process}", "/NH"],
                                    capture_output=True, text=True, timeout=5, check=False)
            # Fail closed if the process query could not be completed.
            if result.returncode != 0:
                return True
            return process.casefold() in result.stdout.casefold()
        except (OSError, subprocess.TimeoutExpired):
            return True
    executable = process.removesuffix(".exe")
    try:
        result = subprocess.run(["pgrep", "-x", executable], capture_output=True,
                                text=True, timeout=5, check=False)
        return result.returncode == 0 or result.returncode not in (0, 1)
    except (OSError, subprocess.TimeoutExpired):
        return True


def _browser_version(browser: str) -> str:
    if os.name != "nt":
        return "unknown"
    import winreg
    key_paths = {
        "Chrome": r"Software\Google\Chrome\BLBeacon",
        "Edge": r"Software\Microsoft\Edge\BLBeacon",
        "Firefox": r"Software\Mozilla\Mozilla Firefox",
    }
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, key_paths[browser]) as key:
                value_name = "CurrentVersion" if browser == "Firefox" else "version"
                return str(winreg.QueryValueEx(key, value_name)[0])
        except OSError:
            continue
    return "unknown"


def _slug(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9._ -]+", "_", value).strip(" .")
    return result or "profile"
