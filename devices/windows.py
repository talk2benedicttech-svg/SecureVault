"""Windows provider for newly connected removable drive-letter storage.

This deliberately does not enumerate fixed disks or launch anything on a device.
Android phones in MTP mode do not receive drive letters and need a WPD provider.
"""
import ctypes
import os
import string
from pathlib import Path

from .models import Device, DeviceKind

DRIVE_REMOVABLE = 2


class WindowsRemovableDriveProvider:
    def discover(self) -> tuple[Device, ...]:
        if os.name != "nt":
            return ()
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetLogicalDrives.restype = ctypes.c_uint32
        kernel.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
        kernel.GetDriveTypeW.restype = ctypes.c_uint
        kernel.GetVolumeInformationW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p,
            ctypes.c_uint,
        ]
        kernel.GetVolumeInformationW.restype = ctypes.c_int
        kernel.GetDiskFreeSpaceExW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulonglong),
                                              ctypes.POINTER(ctypes.c_ulonglong),
                                              ctypes.POINTER(ctypes.c_ulonglong)]
        kernel.GetDiskFreeSpaceExW.restype = ctypes.c_int
        mask = kernel.GetLogicalDrives()
        result = []
        for index, letter in enumerate(string.ascii_uppercase):
            if not mask & (1 << index):
                continue
            root = f"{letter}:\\"
            if kernel.GetDriveTypeW(root) != DRIVE_REMOVABLE:
                continue
            label = ctypes.create_unicode_buffer(261)
            fs = ctypes.create_unicode_buffer(261)
            serial = ctypes.c_uint32()
            max_component = ctypes.c_uint32()
            flags = ctypes.c_uint32()
            if not kernel.GetVolumeInformationW(root, label, len(label), ctypes.byref(serial),
                                                ctypes.byref(max_component), ctypes.byref(flags),
                                                fs, len(fs)):
                # Fail closed: a drive-letter-based ID could accidentally authorize a
                # different device plugged into the same letter later.
                continue
            identity = f"usb-volume:{serial.value:08x}"
            free_available = ctypes.c_ulonglong()
            total = ctypes.c_ulonglong()
            free_total = ctypes.c_ulonglong()
            if kernel.GetDiskFreeSpaceExW(root, ctypes.byref(free_available), ctypes.byref(total),
                                          ctypes.byref(free_total)):
                capacity, free = total.value, free_available.value
            else:
                capacity = free = None
            result.append(Device(identity, DeviceKind.USB_STORAGE, label.value or f"Removable Drive ({letter}:)",
                                 Path(root), capacity, free))
        return tuple(result)
