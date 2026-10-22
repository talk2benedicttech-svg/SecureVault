"""Policy boundary between discovery and a UI's backup actions."""
from .allowlist import DeviceAllowlist
from .models import Device, DeviceAction, DevicePrompt


class DeviceConsent:
    """Builds prompts and enforces explicit authorization before backup can start.

    The UI should show the first-time confirmation screen whenever ``first_seen`` is
    true. Calling ``authorize`` is the affirmative action from that screen.
    Detection itself never starts a backup.
    """
    def __init__(self, allowlist: DeviceAllowlist):
        self.allowlist = allowlist

    def prompt_for(self, device: Device) -> DevicePrompt:
        approved = self.allowlist.contains(device.identity)
        return DevicePrompt(device, approved, not approved,
                            "Approved device detected" if approved else
                            "New device. Review and authorize before backing up.")

    def authorize(self, device: Device, *, remember: bool) -> None:
        """Record explicit user authorization; remember=True adds to local allowlist."""
        if remember:
            self.allowlist.add(device.identity)

    def can_start_backup(self, device: Device, *, confirmed_this_time: bool = False) -> bool:
        return self.allowlist.contains(device.identity) or confirmed_this_time

    def require_action(self, device: Device, action: DeviceAction, *,
                       confirmed_this_time: bool = False) -> None:
        if action is DeviceAction.START_BACKUP and not self.can_start_backup(
                device, confirmed_this_time=confirmed_this_time):
            raise PermissionError("device must be explicitly authorized before backup")
