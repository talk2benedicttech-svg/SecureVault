class VaultError(Exception):
    """Base class for all vault errors."""

class AuthenticationError(VaultError):
    """Wrong password or recovery key."""

class IntegrityError(VaultError):
    """Vault data is corrupted, truncated or tampered with."""

class VaultLockedError(VaultError):
    """Operation requires an unlocked vault."""

class UnsafePathError(VaultError):
    """A path failed validation (traversal, reserved name, etc.)."""

class WeakPasswordError(VaultError):
    """Password does not meet the minimum policy."""
