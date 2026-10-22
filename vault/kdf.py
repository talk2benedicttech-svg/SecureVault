"""Argon2id key derivation with validated, header-stored parameters."""
import time
import unicodedata
from dataclasses import dataclass, asdict

from argon2.low_level import Type, hash_secret_raw

from core.errors import VaultError

KEY_LEN = 32
PROD_MIN_MEMORY_KIB = 64 * 1024      # 64 MiB floor when creating vaults
MAX_MEMORY_KIB = 2 * 1024 * 1024     # 2 GiB ceiling (DoS guard for hostile headers)
MAX_TIME_COST = 64
MAX_PARALLELISM = 16


@dataclass(frozen=True)
class KdfParams:
    time_cost: int
    memory_kib: int
    parallelism: int

    def validate(self, production: bool = True) -> None:
        if not (1 <= self.time_cost <= MAX_TIME_COST):
            raise VaultError("invalid KDF time cost")
        if not (1 <= self.parallelism <= MAX_PARALLELISM):
            raise VaultError("invalid KDF parallelism")
        floor = PROD_MIN_MEMORY_KIB if production else 8 * self.parallelism
        if not (floor <= self.memory_kib <= MAX_MEMORY_KIB):
            raise VaultError("invalid KDF memory cost")

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "KdfParams":
        try:
            return KdfParams(int(d["time_cost"]), int(d["memory_kib"]), int(d["parallelism"]))
        except (KeyError, TypeError, ValueError) as e:
            raise VaultError("malformed KDF parameters") from e


def normalize_password(password: str) -> bytes:
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    return hash_secret_raw(
        secret=normalize_password(password), salt=salt,
        time_cost=params.time_cost, memory_cost=params.memory_kib,
        parallelism=params.parallelism, hash_len=KEY_LEN, type=Type.ID,
    )


def calibrate(target_seconds: float = 0.7, memory_kib: int = 128 * 1024,
              parallelism: int = 4) -> KdfParams:
    """Pick the time cost that takes roughly target_seconds on this machine."""
    t = 1
    while t < MAX_TIME_COST:
        start = time.perf_counter()
        derive_key("calibration", b"0" * 16, KdfParams(t, memory_kib, parallelism))
        if time.perf_counter() - start >= target_seconds:
            break
        t += 1
    return KdfParams(max(t, 3), memory_kib, parallelism)
