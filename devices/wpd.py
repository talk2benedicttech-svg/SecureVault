"""Windows Portable Devices enumeration for phones using MTP/file-transfer mode.

Only device identifiers and friendly names are read. This does not open a phone's
storage or copy files. Windows' WPD manager supplies its connected portable devices.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from ctypes import wintypes

from .models import Device, DeviceKind

CLSID_PORTABLE_DEVICE_MANAGER = "{0AF10CEC-2ECD-4B92-9581-34F6AE0637F3}"
IID_PORTABLE_DEVICE_MANAGER = "{A1567595-4C2F-4574-A6FA-ECEF917B9A40}"
CLSCTX_INPROC_SERVER = 1
COINIT_APARTMENTTHREADED = 2
RPC_E_CHANGED_MODE = 0x80010106


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, value: str) -> "GUID":
        import uuid
        parsed = uuid.UUID(value.strip("{}"))
        return cls(parsed.time_low, parsed.time_mid, parsed.time_hi_version,
                   (ctypes.c_ubyte * 8)(*parsed.bytes[8:]))


class WindowsWpdProvider:
    """Enumerate devices Windows exposes through IPortableDeviceManager/WPD."""

    def discover(self) -> tuple[Device, ...]:
        if os.name != "nt":
            return ()
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        ole32.CoInitializeEx.restype = ctypes.c_long
        ole32.CoUninitialize.argtypes = []
        ole32.CoCreateInstance.argtypes = [ctypes.POINTER(GUID), ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(GUID),
                                           ctypes.POINTER(ctypes.c_void_p)]
        ole32.CoCreateInstance.restype = ctypes.c_long
        ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        ole32.CoTaskMemFree.restype = None

        hr_init = ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
        owns_com = hr_init >= 0
        if hr_init < 0 and (hr_init & 0xFFFFFFFF) != RPC_E_CHANGED_MODE:
            raise OSError(f"COM initialization failed: HRESULT 0x{hr_init & 0xFFFFFFFF:08x}")
        manager = ctypes.c_void_p()
        try:
            clsid = GUID.parse(CLSID_PORTABLE_DEVICE_MANAGER)
            iid = GUID.parse(IID_PORTABLE_DEVICE_MANAGER)
            hr = ole32.CoCreateInstance(ctypes.byref(clsid), None, CLSCTX_INPROC_SERVER,
                                        ctypes.byref(iid), ctypes.byref(manager))
            self._check(hr, "create Windows portable-device manager")
            vtable = ctypes.cast(manager, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
            refresh = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)(vtable[4])
            get_devices = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p,
                                              ctypes.POINTER(ctypes.c_void_p),
                                              ctypes.POINTER(wintypes.DWORD))(vtable[3])
            get_name = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.LPCWSTR,
                                          ctypes.POINTER(ctypes.c_wchar),
                                          ctypes.POINTER(wintypes.DWORD))(vtable[5])
            self._check(refresh(manager), "refresh portable-device list")
            count = wintypes.DWORD(0)
            hr = get_devices(manager, None, ctypes.byref(count))
            if hr < 0 and (hr & 0xFFFFFFFF) != 0x8007007A:  # ERROR_INSUFFICIENT_BUFFER
                self._check(hr, "count portable devices")
            if count.value == 0:
                return ()
            ids = (ctypes.c_void_p * count.value)()
            self._check(get_devices(manager, ids, ctypes.byref(count)), "enumerate portable devices")
            result = []
            try:
                for raw_id in ids[:count.value]:
                    if not raw_id:
                        continue
                    pnp_id = ctypes.wstring_at(raw_id)
                    name = self._friendly_name(get_name, manager, pnp_id, ole32) or "Portable device"
                    # Persist a stable, non-reversible identifier instead of a raw PnP path.
                    identity = "wpd:" + hashlib.sha256(pnp_id.casefold().encode("utf-8")).hexdigest()
                    result.append(Device(identity, DeviceKind.ANDROID_MTP, name))
            finally:
                for raw_id in ids:
                    if raw_id:
                        ole32.CoTaskMemFree(raw_id)
            return tuple(result)
        finally:
            if manager:
                vtable = ctypes.cast(manager, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
                release = ctypes.WINFUNCTYPE(wintypes.ULONG, ctypes.c_void_p)(vtable[2])
                release(manager)
            if owns_com:
                ole32.CoUninitialize()

    @staticmethod
    def _friendly_name(get_name, manager, pnp_id: str, ole32) -> str | None:
        chars = wintypes.DWORD(0)
        get_name(manager, pnp_id, None, ctypes.byref(chars))
        if chars.value == 0:
            return None
        buf = ctypes.create_unicode_buffer(chars.value + 1)
        hr = get_name(manager, pnp_id, buf, ctypes.byref(chars))
        if hr < 0:
            return None
        return buf.value.strip() or None

    @staticmethod
    def _check(hr: int, operation: str) -> None:
        if hr < 0:
            raise OSError(f"Could not {operation}: HRESULT 0x{hr & 0xFFFFFFFF:08x}")
