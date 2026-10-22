import io
import json
import os
import struct
import time
from pathlib import Path

import pytest

from core.errors import (AuthenticationError, IntegrityError, UnsafePathError,
                         VaultError, VaultLockedError, WeakPasswordError)
from core.paths import normalize_logical, safe_join
from vault import crypto
from vault.kdf import KdfParams
from vault.vault import Vault

FAST = KdfParams(1, 64, 1)
PW = "correct horse battery staple"
T = dict(_allow_weak_kdf_for_tests=True)


@pytest.fixture
def vpath(tmp_path):
    return tmp_path / "vault"


@pytest.fixture
def vault(vpath):
    v, rec = Vault.create(vpath, PW, kdf=FAST, inactivity_timeout=None, **T)
    v.recovery = rec
    return v


def objs(vpath):
    return sorted((vpath / "objects").glob("*.bin"))


# ---- 7/8. create with password, reject wrong password ----
def test_create_unlock_roundtrip(vault, vpath):
    vault.add_stream("docs/a.txt", io.BytesIO(b"hello"), 1_600_000_000)
    vault.lock()
    v2 = Vault.unlock(vpath, PW, inactivity_timeout=None, **T)
    assert v2.read_file("docs/a.txt") == b"hello"


def test_wrong_password_rejected(vault, vpath):
    vault.lock()
    with pytest.raises(AuthenticationError):
        Vault.unlock(vpath, "totally wrong password", **T)


def test_weak_password_rejected(vpath):
    with pytest.raises(WeakPasswordError):
        Vault.create(vpath, "short", kdf=FAST, **T)


def test_production_kdf_floor_enforced(vpath):
    with pytest.raises(VaultError):
        Vault.create(vpath, PW, kdf=FAST)   # 64 KiB < 64 MiB floor


def test_no_double_create(vault, vpath):
    with pytest.raises(VaultError):
        Vault.create(vpath, PW, kdf=FAST, **T)


# ---- recovery & password change ----
def test_recovery_key_unlocks(vault, vpath):
    vault.add_stream("a.txt", io.BytesIO(b"data"))
    rec = vault.recovery
    vault.lock()
    v2 = Vault.unlock(vpath, recovery_key=rec, inactivity_timeout=None, **T)
    assert v2.read_file("a.txt") == b"data"


def test_wrong_recovery_key_rejected(vault, vpath):
    vault.lock()
    bad = "AAAA-" * 12 + "AAAA"
    with pytest.raises(AuthenticationError):
        Vault.unlock(vpath, recovery_key=bad, **T)


def test_change_password(vault, vpath):
    vault.add_stream("a.txt", io.BytesIO(b"data"))
    vault.change_password("a brand new long password", kdf=FAST, **T)
    vault.lock()
    with pytest.raises(AuthenticationError):
        Vault.unlock(vpath, PW, **T)
    v2 = Vault.unlock(vpath, "a brand new long password", inactivity_timeout=None, **T)
    assert v2.read_file("a.txt") == b"data"
    # recovery key still works after password change
    v2.lock()
    assert Vault.unlock(vpath, recovery_key=vault.recovery, inactivity_timeout=None, **T).read_file("a.txt") == b"data"


def test_rotate_recovery_key(vault, vpath):
    old = vault.recovery
    new = vault.rotate_recovery_key()
    vault.lock()
    with pytest.raises(AuthenticationError):
        Vault.unlock(vpath, recovery_key=old, **T)
    Vault.unlock(vpath, recovery_key=new, inactivity_timeout=None, **T)


# ---- 9. tamper / corruption detection ----
def test_header_tamper_detected(vault, vpath):
    vault.lock()
    h = json.loads((vpath / "vault.header").read_text())
    h["slots"][0]["kdf"]["time_cost"] = 2          # downgrade/alter params
    (vpath / "vault.header").write_text(json.dumps(h))
    with pytest.raises(AuthenticationError):
        Vault.unlock(vpath, PW, **T)


def test_hostile_header_kdf_dos_rejected(vault, vpath):
    vault.lock()
    h = json.loads((vpath / "vault.header").read_text())
    h["slots"][0]["kdf"]["memory_kib"] = 64 * 1024 * 1024   # 64 GiB
    (vpath / "vault.header").write_text(json.dumps(h))
    with pytest.raises(VaultError):
        Vault.unlock(vpath, PW, **T)


def test_object_bitflip_detected(vault, vpath):
    vault.add_stream("a.bin", io.BytesIO(os.urandom(5000)))
    p = objs(vpath)[0]
    b = bytearray(p.read_bytes()); b[100] ^= 1; p.write_bytes(b)
    with pytest.raises(IntegrityError):
        vault.read_file("a.bin")
    assert vault.verify()


def test_object_truncation_detected(vault, vpath):
    vault.add_stream("a.bin", io.BytesIO(os.urandom(3 * 1024 * 1024 + 10)))
    p = objs(vpath)[0]
    data = p.read_bytes()
    # cut cleanly at a chunk boundary: drop the final chunk
    pos, (n,) = 16, struct.unpack(">I", data[16:20])
    first_end = 16 + 4 + n
    p.write_bytes(data[:first_end])
    with pytest.raises(IntegrityError):
        vault.read_file("a.bin")


def test_object_swap_detected(vault, vpath):
    vault.add_stream("a.bin", io.BytesIO(b"A" * 100))
    vault.add_stream("b.bin", io.BytesIO(b"B" * 100))
    a, b = objs(vpath)
    da, db = a.read_bytes(), b.read_bytes()
    a.write_bytes(db); b.write_bytes(da)
    with pytest.raises(IntegrityError):
        vault.read_file("a.bin")


def test_chunk_reorder_detected():
    key, fid = os.urandom(32), os.urandom(16)
    out = io.BytesIO()
    crypto.encrypt_stream(key, fid, io.BytesIO(b"1111" b"2222" b"3333"), out, chunk_size=4)
    raw = out.getvalue()
    head, body, chunks = raw[:16], raw[16:], []
    while body:
        (n,) = struct.unpack(">I", body[:4]); chunks.append(body[:4 + n]); body = body[4 + n:]
    assert len(chunks) == 3
    swapped = head + chunks[1] + chunks[0] + chunks[2]
    with pytest.raises(IntegrityError):
        list(crypto.decrypt_stream(key, fid, io.BytesIO(swapped)))


def test_trailing_garbage_detected():
    key, fid = os.urandom(32), os.urandom(16)
    out = io.BytesIO()
    crypto.encrypt_stream(key, fid, io.BytesIO(b"hello"), out)
    with pytest.raises(IntegrityError):
        list(crypto.decrypt_stream(key, fid, io.BytesIO(out.getvalue() + b"\x00\x00\x00\x20" + b"x" * 32)))


def test_missing_object_detected(vault, vpath):
    vault.add_stream("a.bin", io.BytesIO(b"x"))
    objs(vpath)[0].unlink()
    assert vault.verify()


def test_index_tamper_detected(vault, vpath):
    vault.lock()
    p = vpath / "index.enc"
    b = bytearray(p.read_bytes()); b[-1] ^= 1; p.write_bytes(b)
    with pytest.raises(IntegrityError):
        Vault.unlock(vpath, PW, **T)


# ---- 10. restore + hashes ----
def test_restore_verifies_hash_and_metadata(vault, tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(2_500_000))      # multi-chunk
    os.utime(src, (1_500_000_000, 1_500_000_000))
    vault.add_file("proj/data/src.bin", src)
    out = vault.restore_file("proj/data/src.bin", tmp_path / "restore")
    assert out.read_bytes() == src.read_bytes()
    assert int(out.stat().st_mtime) == 1_500_000_000
    assert vault.verify() == []


def test_empty_file(vault, tmp_path):
    vault.add_stream("empty.txt", io.BytesIO(b""))
    assert vault.read_file("empty.txt") == b""


def test_tampered_restore_leaves_no_output(vault, vpath, tmp_path):
    vault.add_stream("a.bin", io.BytesIO(os.urandom(3_000_000)))
    p = objs(vpath)[0]
    b = bytearray(p.read_bytes()); b[-5] ^= 1; p.write_bytes(b)
    dest = tmp_path / "restore"
    with pytest.raises(IntegrityError):
        vault.restore_file("a.bin", dest)
    assert not list(dest.rglob("*")) or all(p.is_dir() for p in dest.rglob("*"))


def test_dedupe_single_object(vault, vpath):
    vault.add_stream("a.txt", io.BytesIO(b"same content"))
    vault.add_stream("b.txt", io.BytesIO(b"same content"))
    assert len(objs(vpath)) == 1
    assert vault.read_file("a.txt") == vault.read_file("b.txt") == b"same content"


# ---- paths ----
@pytest.mark.parametrize("bad", ["../evil", "a/../../evil", "/etc/passwd", "C:\\Windows\\x",
                                 "CON", "dir/nul.txt", "bad:name", "trail.", "a\x00b", ""])
def test_unsafe_paths_rejected(bad):
    with pytest.raises(UnsafePathError):
        normalize_logical(bad)


def test_safe_join_stays_inside(tmp_path):
    assert str(safe_join(tmp_path, "a/b.txt")).startswith(str(tmp_path.resolve()))


def test_add_rejects_traversal(vault):
    with pytest.raises(UnsafePathError):
        vault.add_stream("../../x", io.BytesIO(b"x"))


# ---- locking ----
def test_locked_vault_refuses_operations(vault):
    vault.lock()
    assert vault.locked
    with pytest.raises(VaultLockedError):
        vault.list_files()
    with pytest.raises(VaultLockedError):
        vault.add_stream("a", io.BytesIO(b"x"))


def test_auto_lock_after_inactivity(vpath):
    fired = []
    v, _ = Vault.create(vpath, PW, kdf=FAST, inactivity_timeout=0.3, on_lock=lambda: fired.append(1), **T)
    assert not v.locked
    time.sleep(0.8)
    assert v.locked and fired


def test_activity_resets_timer(vpath):
    v, _ = Vault.create(vpath, PW, kdf=FAST, inactivity_timeout=0.6, **T)
    for _ in range(4):
        time.sleep(0.3); v.list_files()
    assert not v.locked
    time.sleep(1.0)
    assert v.locked


# ---- 12. no secrets / plaintext on disk ----
def test_nothing_sensitive_on_disk(vault, vpath):
    secret = b"TOP-SECRET-CONTENT-12345"
    vault.add_stream("tax/confidential-report.txt", io.BytesIO(secret))
    vault.lock()
    blob = b"".join(p.read_bytes() for p in vpath.rglob("*") if p.is_file())
    assert secret not in blob
    assert b"confidential-report" not in blob and b"tax" not in blob
    assert PW.encode() not in blob
    assert vault.recovery.replace("-", "").encode() not in blob
    assert not list(vpath.rglob("*.part")) and not list(vpath.rglob("*.tmp"))
