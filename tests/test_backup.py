import json
import sqlite3

from backup import BackupEngine, BrowserExporter
from vault.kdf import KdfParams
from vault.vault import Vault

FAST = KdfParams(1, 64, 1)


def make_vault(path):
    vault, _ = Vault.create(path, "correct horse battery staple", kdf=FAST,
                            inactivity_timeout=None, _allow_weak_kdf_for_tests=True)
    return vault


def test_backup_and_incremental_resume(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.txt").write_text("alpha", encoding="utf-8")
    nested = source / "nested"
    nested.mkdir()
    (nested / "b.txt").write_text("beta", encoding="utf-8")
    vault = make_vault(tmp_path / "vault")

    first = BackupEngine(vault).run([source], device_identity="approved-test-device")
    assert (first.copied, first.skipped, first.failed) == (2, 0, 0)
    assert vault.read_file("source/a.txt") == b"alpha"
    assert vault.read_file("source/nested/b.txt") == b"beta"

    second = BackupEngine(vault).run([source], device_identity="approved-test-device")
    assert (second.copied, second.skipped, second.failed) == (0, 2, 0)

    (source / "a.txt").write_text("updated", encoding="utf-8")
    third = BackupEngine(vault).run([source], device_identity="approved-test-device")
    assert (third.copied, third.skipped, third.failed) == (1, 1, 0)
    assert vault.read_file("source/a.txt") == b"updated"


def test_manifest_and_host_source_path_are_encrypted(tmp_path):
    source = tmp_path / "private-source-folder"
    source.mkdir()
    (source / "private-filename.txt").write_bytes(b"private-content-marker")
    vault_path = tmp_path / "vault"
    vault = make_vault(vault_path)
    BackupEngine(vault).run([source])
    vault.lock()

    on_disk = b"".join(p.read_bytes() for p in vault_path.rglob("*") if p.is_file())
    assert b"private-source-folder" not in on_disk
    assert b"private-filename.txt" not in on_disk
    assert b"private-content-marker" not in on_disk


def test_backup_refuses_vault_as_source(tmp_path):
    vault_path = tmp_path / "vault"
    vault = make_vault(vault_path)
    try:
        BackupEngine(vault).run([vault_path])
        assert False, "expected vault-self-backup rejection"
    except ValueError as exc:
        assert "cannot be backed up into itself" in str(exc)


def test_chromium_bookmarks_and_history_export_only_when_closed(tmp_path, monkeypatch):
    local = tmp_path / "local"
    roaming = tmp_path / "roaming"
    profile = local / "Google" / "Chrome" / "User Data" / "Default"
    profile.mkdir(parents=True)
    (roaming / "Mozilla").mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))
    user_data = profile.parent
    (user_data / "Local State").write_text(
        json.dumps({"profile": {"info_cache": {"Default": {"name": "Test Profile"}}}}),
        encoding="utf-8")
    (profile / "Bookmarks").write_text(json.dumps({"roots": {"bookmark_bar": {"children": []}}}),
                                        encoding="utf-8")
    db = sqlite3.connect(profile / "History")
    db.execute("CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
    db.execute("INSERT INTO urls VALUES (?, ?, ?, ?)", ("https://example.test", "Example", 2, 13300000000000000))
    db.commit()
    db.close()

    vault = make_vault(tmp_path / "vault")
    result = BrowserExporter(vault, process_check=lambda _process: False).export()
    assert (result.copied, result.skipped, result.failed) == (2, 0, 0)
    assert json.loads(vault.read_file("Browser Data/Chrome/Test Profile/bookmarks.json"))["data_type"] == "bookmarks"
    history = json.loads(vault.read_file("Browser Data/Chrome/Test Profile/history.json"))
    assert history["entries"][0]["url"] == "https://example.test"

    active = BrowserExporter(vault, process_check=lambda _process: True).export()
    assert active.copied == 0 and active.skipped == 1


def test_firefox_bookmarks_and_history_export(tmp_path, monkeypatch):
    roaming = tmp_path / "roaming"
    profile_root = roaming / "Mozilla" / "Firefox"
    profile = profile_root / "Profiles" / "test.default-release"
    profile.mkdir(parents=True)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    monkeypatch.setenv("APPDATA", str(roaming))
    (profile_root / "profiles.ini").write_text(
        "[Profile0]\nName=Test Firefox\nIsRelative=1\nPath=Profiles/test.default-release\n",
        encoding="utf-8")
    db = sqlite3.connect(profile / "places.sqlite")
    db.execute("CREATE TABLE moz_places (id INTEGER, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)")
    db.execute("CREATE TABLE moz_bookmarks (id INTEGER, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, position INTEGER)")
    db.execute("INSERT INTO moz_places VALUES (1, 'https://example.test', 'Example', 3, 1700000000000000)")
    db.execute("INSERT INTO moz_bookmarks VALUES (2, 1, 1, 0, 'Example bookmark', 0)")
    db.commit()
    db.close()

    vault = make_vault(tmp_path / "vault")
    result = BrowserExporter(vault, process_check=lambda _process: False).export()
    assert result.copied == 2 and result.failed == 0
    bookmarks = json.loads(vault.read_file("Browser Data/Firefox/Test Firefox/bookmarks.json"))
    assert bookmarks["entries"][0]["url"] == "https://example.test"
    history = json.loads(vault.read_file("Browser Data/Firefox/Test Firefox/history.json"))
    assert history["entries"][0]["visit_count"] == 3
