"""Small immutable types shared by device providers and the UI."""
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class DeviceKind(str, Enum):
    USB_STORAGE = "usb_storage"
    ANDROID_MTP = "android_mtp"


class DeviceAction(str, Enum):
    START_BACKUP = "start_backup"
    VIEW_DETAILS = "view_details"
    CANCEL = "cancel"


@dataclass(frozen=True)
class Device:
    """A discovered storage endpoint. Identity is provider-issued, not its path."""
    identity: str
    kind: DeviceKind
    label: str
    mount_path: Path | None = None
    capacity_bytes: int | None = None
    free_bytes: int | None = None

    @property
    def display_name(self) -> str:
        return self.label or (str(self.mount_path) if self.mount_path else self.kind.value)


@dataclass(frozen=True)
class DevicePrompt:
    device: Device
    approved: bool
    first_seen: bool
    message: str

