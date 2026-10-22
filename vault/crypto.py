"""Chunked AES-256-GCM streaming encryption.

File layout:  MAGIC(4) | chunk_size u32 | nonce_prefix(8) | { ct_len u32 | ciphertext } ...
Nonce        = nonce_prefix(8) || chunk_counter(4)
AAD          = file_id || chunk_counter u64 || final_flag(1)
So chunks cannot be reordered, dropped, truncated, or moved between files undetected.
"""
import hashlib
import hmac
import os
import struct
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.errors import IntegrityError

MAGIC = b"SVF1"
DEFAULT_CHUNK = 1024 * 1024
MAX_CHUNK = 64 * 1024 * 1024
TAG = 16


def subkey(master: bytes, purpose: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"securevault/v1/" + purpose).derive(master)


def _read_exact(src: BinaryIO, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        b = src.read(n - len(out))
        if not b:
            break
        out += b
    return bytes(out)


def _aad(file_id: bytes, counter: int, final: bool) -> bytes:
    return file_id + struct.pack(">QB", counter, 1 if final else 0)


def encrypt_stream(key: bytes, file_id: bytes, src: BinaryIO, dst: BinaryIO,
                   chunk_size: int = DEFAULT_CHUNK) -> None:
    if not (1 <= chunk_size <= MAX_CHUNK):
        raise ValueError("bad chunk size")
    aes = AESGCM(key)
    prefix = os.urandom(8)
    dst.write(MAGIC + struct.pack(">I", chunk_size) + prefix)
    buf = _read_exact(src, chunk_size)
    counter = 0
    while True:
        nxt = _read_exact(src, chunk_size) if len(buf) == chunk_size else b""
        final = len(nxt) == 0
        if counter >= 2**32:
            raise ValueError("file too large")
        ct = aes.encrypt(prefix + struct.pack(">I", counter), buf, _aad(file_id, counter, final))
        dst.write(struct.pack(">I", len(ct)) + ct)
        if final:
            return
        buf, counter = nxt, counter + 1


def decrypt_stream(key: bytes, file_id: bytes, src: BinaryIO) -> Iterator[bytes]:
    """Yield authenticated plaintext chunks. Raises IntegrityError on any problem.

    Callers writing to disk MUST discard output if this raises (later chunks may fail).
    """
    head = _read_exact(src, 16)
    if len(head) != 16 or head[:4] != MAGIC:
        raise IntegrityError("bad object header")
    (chunk_size,) = struct.unpack(">I", head[4:8])
    if not (1 <= chunk_size <= MAX_CHUNK):
        raise IntegrityError("bad chunk size in object")
    prefix = head[8:16]
    aes = AESGCM(key)
    counter = 0
    lenb = _read_exact(src, 4)
    if len(lenb) != 4:
        raise IntegrityError("object truncated")
    while True:
        (ct_len,) = struct.unpack(">I", lenb)
        if not (TAG <= ct_len <= chunk_size + TAG):
            raise IntegrityError("bad chunk length")
        ct = _read_exact(src, ct_len)
        if len(ct) != ct_len:
            raise IntegrityError("object truncated")
        lenb = _read_exact(src, 4)
        if 0 < len(lenb) < 4:
            raise IntegrityError("object truncated")
        final = len(lenb) == 0
        try:
            pt = aes.decrypt(prefix + struct.pack(">I", counter), ct, _aad(file_id, counter, final))
        except InvalidTag as e:
            raise IntegrityError("authentication failed (corrupted, truncated or tampered)") from e
        yield pt
        if final:
            return
        counter += 1


def seal(key: bytes, aad: bytes, data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def unseal(key: bytes, aad: bytes, blob: bytes) -> bytes:
    if len(blob) < 12 + TAG:
        raise IntegrityError("blob too short")
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as e:
        raise IntegrityError("authentication failed") from e


def content_mac(dedupe_key: bytes) -> "hmac.HMAC":
    return hmac.new(dedupe_key, digestmod=hashlib.sha256)
