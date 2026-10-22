"""Keyslots: wrap one random master key under a password or a recovery key."""
import base64
import json
import os

from core.errors import AuthenticationError, IntegrityError, VaultError
from . import crypto
from .kdf import KdfParams, derive_key

SALT_LEN = 16


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as e:
        raise IntegrityError("malformed header encoding") from e


def _aad(vault_id: str, slot: dict) -> bytes:
    fixed = {k: slot[k] for k in sorted(slot) if k not in ("wrapped",)}
    return b"SVSLOT1" + vault_id.encode() + json.dumps(fixed, sort_keys=True).encode()


def make_password_slot(vault_id: str, master: bytes, password: str, params: KdfParams) -> dict:
    salt = os.urandom(SALT_LEN)
    slot = {"kind": "password", "kdf": params.to_dict(), "salt": b64e(salt)}
    kek = derive_key(password, salt, params)
    slot["wrapped"] = b64e(crypto.seal(kek, _aad(vault_id, slot), master))
    return slot


def make_recovery_slot(vault_id: str, master: bytes, recovery_bytes: bytes) -> dict:
    slot = {"kind": "recovery"}
    kek = crypto.subkey(recovery_bytes, b"recovery-kek")
    slot["wrapped"] = b64e(crypto.seal(kek, _aad(vault_id, slot), master))
    return slot


def open_password_slot(vault_id: str, slot: dict, password: str, production: bool) -> bytes:
    params = KdfParams.from_dict(slot.get("kdf", {}))
    params.validate(production=production)
    kek = derive_key(password, b64d(slot["salt"]), params)
    try:
        return crypto.unseal(kek, _aad(vault_id, slot), b64d(slot["wrapped"]))
    except IntegrityError as e:
        raise AuthenticationError("incorrect password (or vault header tampered)") from e


def open_recovery_slot(vault_id: str, slot: dict, recovery_bytes: bytes) -> bytes:
    kek = crypto.subkey(recovery_bytes, b"recovery-kek")
    try:
        return crypto.unseal(kek, _aad(vault_id, slot), b64d(slot["wrapped"]))
    except IntegrityError as e:
        raise AuthenticationError("incorrect recovery key (or vault header tampered)") from e


def new_recovery_key() -> tuple[bytes, str]:
    raw = os.urandom(32)
    s = base64.b32encode(raw).decode().rstrip("=")
    return raw, "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def parse_recovery_key(text: str) -> bytes:
    s = "".join(text.split()).replace("-", "").upper()
    s += "=" * (-len(s) % 8)
    try:
        raw = base64.b32decode(s)
    except Exception as e:
        raise AuthenticationError("malformed recovery key") from e
    if len(raw) != 32:
        raise AuthenticationError("malformed recovery key")
    return raw
