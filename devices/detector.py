"""Polling device discovery with arrival/removal notifications."""
from __future__ import annotations

import threading
from typing import Callable, Iterable, Protocol

from .models import Device


class DeviceProvider(Protocol):
    def discover(self) -> Iterable[Device]: ...


class DeviceDetector:
    """Poll one or more providers. Callbacks run on the polling thread."""
    def __init__(self, providers: Iterable[DeviceProvider], *, interval: float = 2.0,
                 on_arrival: Callable[[Device], None] | None = None,
                 on_removal: Callable[[Device], None] | None = None,
                 on_error: Callable[[Exception], None] | None = None):
        if interval <= 0:
            raise ValueError("interval must be positive")
        self.providers = tuple(providers)
        self.interval = interval
        self.on_arrival = on_arrival or (lambda _device: None)
        self.on_removal = on_removal or (lambda _device: None)
        self.on_error = on_error or (lambda _error: None)
        self._known: dict[str, Device] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._scan_lock = threading.Lock()

    @property
    def devices(self) -> tuple[Device, ...]:
        return tuple(self._known.values())

    def scan_once(self) -> tuple[tuple[Device, ...], tuple[Device, ...]]:
        """Refresh device snapshot and emit edge callbacks. Useful for GUI/tests."""
        with self._scan_lock:
            found: dict[str, Device] = {}
            for provider in self.providers:
                try:
                    for device in provider.discover():
                        found[device.identity] = device
                except Exception as exc:
                    self.on_error(exc)
            arrived = tuple(found[k] for k in found.keys() - self._known.keys())
            removed = tuple(self._known[k] for k in self._known.keys() - found.keys())
            self._known = found
        for device in arrived:
            self.on_arrival(device)
        for device in removed:
            self.on_removal(device)
        return arrived, removed

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="SecureVaultDeviceDetector", daemon=True)
        self._thread.start()

    def stop(self, timeout: float | None = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout)
        self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(self.interval)
