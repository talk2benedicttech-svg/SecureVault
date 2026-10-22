"""PySide6 dashboard for device consent, vault setup, and encrypted folder backups."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QDialogButtonBox,
                               QFileDialog, QFrame, QHBoxLayout, QInputDialog, QLabel,
                               QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
                               QMessageBox, QProgressBar, QPushButton, QVBoxLayout,
                               QWidget)

from backup import BackupEngine, BackupProgress, BackupResult, BrowserExporter
from devices import (Device, DeviceAllowlist, DeviceConsent, DeviceDetector,
                     DeviceKind, WindowsRemovableDriveProvider, WindowsWpdProvider)
from devices.models import DeviceAction
from vault.vault import Vault

APP_STYLE = """
QMainWindow, QDialog { background: #f4f7fb; color: #17263c; }
QWidget { font-family: 'Segoe UI'; font-size: 10pt; }
QLabel#title { font-size: 23pt; font-weight: 650; color: #12243a; }
QLabel#subtitle, QLabel#muted { color: #53657c; }
QFrame#panel { background: white; border: 1px solid #dbe3ed; border-radius: 12px; }
QListWidget { background: white; border: 1px solid #dbe3ed; border-radius: 8px; padding: 4px; }
QListWidget::item { padding: 12px; border-radius: 6px; }
QListWidget::item:selected { background: #e7f1ff; color: #123b66; }
QPushButton { min-height: 38px; padding: 0 15px; border: 1px solid #c9d4e1;
              border-radius: 7px; background: white; color: #203650; }
QPushButton:hover { background: #edf4fb; }
QPushButton:focus { border: 2px solid #2474c8; }
QPushButton#primary { background: #1769aa; color: white; border: 0; font-weight: 600; }
QPushButton#primary:hover { background: #0d568f; }
QCheckBox { spacing: 8px; }
QProgressBar { min-height: 20px; border: 1px solid #d4deea; border-radius: 6px;
               text-align: center; background: #fff; }
QProgressBar::chunk { background: #55a176; border-radius: 5px; }
"""


def _app_directory() -> Path:
    """Return the directory containing the portable app, or the project root in source mode."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


class FirstUseDialog(QDialog):
    def __init__(self, device: Device, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authorize new device")
        self.setMinimumWidth(440)
        layout = QVBoxLayout(self)
        title = QLabel("First-time device confirmation")
        title.setObjectName("title")
        title.setWordWrap(True)
        layout.addWidget(title)
        info = QLabel(
            f"SecureVault detected <b>{device.display_name}</b>.<br><br>"
            "Confirm that you trust this device. Only the source files and optional "
            "browser bookmarks/history you selected will be read and written into your encrypted vault."
        )
        info.setWordWrap(True)
        layout.addWidget(info)
        self.remember = QCheckBox("Remember this device on this computer")
        layout.addWidget(self.remember)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel |
                                   QDialogButtonBox.StandardButton.Ok)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Authorize and continue")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class BackupWorker(QThread):
    progress = Signal(object)
    browser_progress = Signal(str)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, engine: BackupEngine, sources: list[Path], device_identity: str,
                 include_browser: bool, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.sources = sources
        self.device_identity = device_identity
        self.include_browser = include_browser
        self.cancel_event = threading.Event()

    def run(self):
        try:
            result = self.engine.run(self.sources, device_identity=self.device_identity,
                                     cancel_event=self.cancel_event, on_progress=self.progress.emit)
            if self.include_browser and not result.cancelled:
                browser_result = BrowserExporter(self.engine.vault).export(
                    on_progress=self.browser_progress.emit, cancel_event=self.cancel_event)
                result.copied += browser_result.copied
                result.skipped += browser_result.skipped
                result.failed += browser_result.failed
                result.errors.extend(browser_result.errors)
                result.cancelled = browser_result.cancelled
            self.completed.emit(result)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class DeviceWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureVault — Devices and Backup")
        self.resize(1020, 760)
        app_dir = _app_directory()
        self.allowlist = DeviceAllowlist(app_dir / "data" / "devices.json")
        self.consent = DeviceConsent(self.allowlist)
        settings_path = app_dir / "data" / "settings.ini"
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings = QSettings(str(settings_path), QSettings.Format.IniFormat)
        self.vault: Vault | None = None
        self.vault_path: Path | None = None
        self.sources: list[Path] = []
        self.backup_worker: BackupWorker | None = None
        self._devices: dict[str, Device] = {}
        self._dismissed: set[str] = set()

        root = QWidget()
        page = QVBoxLayout(root)
        page.setContentsMargins(32, 28, 32, 28)
        page.setSpacing(16)
        title = QLabel("Connected devices")
        title.setObjectName("title")
        page.addWidget(title)
        subtitle = QLabel("Choose backup folders once, then approve each new device before its first backup.")
        subtitle.setObjectName("subtitle")
        page.addWidget(subtitle)

        vault_row = QHBoxLayout()
        self.vault_button = QPushButton("Create / Unlock Vault")
        self.vault_button.clicked.connect(self._choose_vault)
        self.vault_label = QLabel("Vault locked")
        self.vault_label.setObjectName("muted")
        vault_row.addWidget(self.vault_button)
        vault_row.addWidget(self.vault_label, 1)
        page.addLayout(vault_row)

        panel = QFrame()
        panel.setObjectName("panel")
        row = QHBoxLayout(panel)
        row.setContentsMargins(20, 20, 20, 20)
        row.setSpacing(20)
        self.device_list = QListWidget()
        self.device_list.setMinimumWidth(310)
        self.device_list.currentItemChanged.connect(self._selection_changed)
        row.addWidget(self.device_list, 1)

        details = QVBoxLayout()
        details.setSpacing(10)
        self.device_name = QLabel("No device selected")
        self.device_name.setFont(QFont("Segoe UI", 16, QFont.Weight.DemiBold))
        details.addWidget(self.device_name)
        self.device_status = QLabel("Connect a USB drive or Android phone in file-transfer mode.")
        self.device_status.setObjectName("muted")
        self.device_status.setWordWrap(True)
        details.addWidget(self.device_status)
        self.device_metadata = QLabel("")
        self.device_metadata.setObjectName("muted")
        self.device_metadata.setWordWrap(True)
        details.addWidget(self.device_metadata)

        source_title = QLabel("Backup folders")
        source_title.setFont(QFont("Segoe UI", 11, QFont.Weight.DemiBold))
        details.addWidget(source_title)
        self.source_list = QListWidget()
        self.source_list.setMaximumHeight(115)
        details.addWidget(self.source_list)
        source_buttons = QHBoxLayout()
        add_source = QPushButton("Add folder")
        add_files = QPushButton("Add files")
        remove_source = QPushButton("Remove selected")
        add_source.clicked.connect(self._add_source)
        add_files.clicked.connect(self._add_files)
        remove_source.clicked.connect(self._remove_source)
        source_buttons.addWidget(add_source)
        source_buttons.addWidget(add_files)
        source_buttons.addWidget(remove_source)
        source_buttons.addStretch(1)
        details.addLayout(source_buttons)
        self.browser_checkbox = QCheckBox("Export bookmarks and history (closed browsers only)")
        self.browser_checkbox.setToolTip(
            "Exports bookmarks and browsing history. Passwords, cookies, and login tokens are never exported.")
        details.addWidget(self.browser_checkbox)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Ready")
        details.addWidget(self.progress_bar)
        details.addStretch(1)

        buttons = QHBoxLayout()
        self.start_button = QPushButton("Start Backup")
        self.start_button.setObjectName("primary")
        self.details_button = QPushButton("View Details")
        self.cancel_button = QPushButton("Cancel")
        self.start_button.clicked.connect(self._start_backup)
        self.details_button.clicked.connect(self._view_details)
        self.cancel_button.clicked.connect(self._cancel_prompt)
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.details_button)
        buttons.addWidget(self.cancel_button)
        details.addLayout(buttons)
        row.addLayout(details, 2)
        page.addWidget(panel, 1)

        footer = QLabel("Device detection is active. No backup starts without your approval.")
        footer.setObjectName("muted")
        page.addWidget(footer)
        self.setCentralWidget(root)
        self.setStyleSheet(APP_STYLE)

        self.detector = DeviceDetector([WindowsRemovableDriveProvider(), WindowsWpdProvider()],
                                       on_error=self._report_error)
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self._scan)
        self.timer.start()
        QTimer.singleShot(0, self._scan)
        saved_vault = self.settings.value("vault_path", "")
        if saved_vault and Path(saved_vault).is_dir():
            self.vault_path = Path(saved_vault)
            self.vault_label.setText(f"Vault locked: {self.vault_path}")

    def closeEvent(self, event):
        self.timer.stop()
        if self.backup_worker and self.backup_worker.isRunning():
            self.backup_worker.cancel_event.set()
            self.backup_worker.wait()
        if self.vault and not self.vault.locked:
            self.vault.lock()
        event.accept()

    def _scan(self):
        arrived, _removed = self.detector.scan_once()
        current = {device.identity: device for device in self.detector.devices}
        old = set(self._devices)
        self._devices = current
        selected = self._selected_identity()
        self.device_list.clear()
        for device in sorted(current.values(), key=lambda item: item.display_name.casefold()):
            approved = self.allowlist.contains(device.identity)
            kind = "Portable device" if device.kind is DeviceKind.ANDROID_MTP else "USB storage"
            status = "Approved" if approved else "Needs first-time approval"
            item = QListWidgetItem(f"{device.display_name}\n{kind} · {status}")
            item.setData(Qt.ItemDataRole.UserRole, device.identity)
            self.device_list.addItem(item)
            if device.identity == selected:
                self.device_list.setCurrentItem(item)
        if self.device_list.count() and not self.device_list.currentItem():
            self.device_list.setCurrentRow(0)
        for device in arrived:
            self._show_arrival(device)
        for identity in old - set(current):
            self._dismissed.discard(identity)
        if not current:
            self.device_name.setText("No device selected")
            self.device_status.setText("Connect a USB drive or Android phone in file-transfer mode.")
            self.device_metadata.clear()
            self._set_actions(False)

    def _show_arrival(self, device: Device):
        if device.identity in self._dismissed:
            return
        self.device_list.setCurrentRow(self._row_for(device.identity))
        approval = "This device is approved." if self.allowlist.contains(device.identity) else \
            "This is a new device and needs first-time confirmation."
        prompt = QMessageBox(self)
        prompt.setWindowTitle("SecureVault device detected")
        prompt.setIcon(QMessageBox.Icon.Information)
        prompt.setText(f"{device.display_name} detected")
        prompt.setInformativeText(f"{approval}\nChoose what to do next.")
        start = prompt.addButton("Start Backup", QMessageBox.ButtonRole.AcceptRole)
        details = prompt.addButton("View Details", QMessageBox.ButtonRole.ActionRole)
        cancel = prompt.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        prompt.setDefaultButton(start)
        prompt.exec()
        clicked = prompt.clickedButton()
        if clicked is start:
            self._start_backup()
        elif clicked is details:
            self._view_details()
        elif clicked is cancel:
            self._dismissed.add(device.identity)
            self.device_status.setText("Prompt dismissed. The device remains connected.")

    def _row_for(self, identity: str) -> int:
        for row in range(self.device_list.count()):
            if self.device_list.item(row).data(Qt.ItemDataRole.UserRole) == identity:
                return row
        return -1

    def _selected_identity(self):
        item = self.device_list.currentItem() if hasattr(self, "device_list") else None
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _selected_device(self):
        identity = self._selected_identity()
        return self._devices.get(identity) if identity else None

    def _selection_changed(self, _current, _previous):
        device = self._selected_device()
        if not device:
            self._set_actions(False)
            return
        approved = self.allowlist.contains(device.identity)
        kind = "Windows Portable Device (WPD/MTP)" if device.kind is DeviceKind.ANDROID_MTP else "USB removable storage"
        self.device_name.setText(device.display_name)
        self.device_status.setText("Approved device" if approved else "New device — first-time confirmation required")
        self.device_metadata.setText(f"Type: {kind}\nIdentifier: {device.identity[:20]}…")
        self._set_actions(True)

    def _set_actions(self, enabled: bool):
        busy = bool(self.backup_worker and self.backup_worker.isRunning())
        self.start_button.setEnabled(enabled and not busy)
        self.details_button.setEnabled(enabled and not busy)
        self.cancel_button.setEnabled(enabled or busy)
        if busy:
            self.cancel_button.setText("Cancel Backup")
        else:
            self.cancel_button.setText("Cancel")

    def _view_details(self):
        device = self._selected_device()
        if not device:
            return
        prompt = self.consent.prompt_for(device)
        kind = "Windows Portable Device / MTP" if device.kind is DeviceKind.ANDROID_MTP else "USB removable storage"
        QMessageBox.information(self, "Device details",
                                f"Name: {device.display_name}\nType: {kind}\n"
                                f"Authorization: {'Approved' if prompt.approved else 'Not approved'}\n\n"
                                f"{prompt.message}\n\nDetection does not read device content.")

    def _start_backup(self):
        device = self._selected_device()
        if not device:
            return
        if not self.vault or self.vault.locked:
            QMessageBox.warning(self, "Vault is locked", "Create or unlock the encrypted vault before starting a backup.")
            return
        if not self.sources:
            QMessageBox.warning(self, "No backup folders", "Add one or more folders to back up first.")
            return
        confirmed = False
        if not self.allowlist.contains(device.identity):
            confirmation = FirstUseDialog(device, self)
            if confirmation.exec() != QDialog.DialogCode.Accepted:
                return
            self.consent.authorize(device, remember=confirmation.remember.isChecked())
            confirmed = True
        try:
            self.consent.require_action(device, DeviceAction.START_BACKUP,
                                        confirmed_this_time=confirmed)
        except PermissionError as exc:
            QMessageBox.warning(self, "Device not authorized", str(exc))
            return
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Starting backup…")
        self.backup_worker = BackupWorker(BackupEngine(self.vault), list(self.sources),
                                          device.identity, self.browser_checkbox.isChecked(), self)
        self.backup_worker.progress.connect(self._backup_progress)
        self.backup_worker.browser_progress.connect(self._browser_progress)
        self.backup_worker.completed.connect(self._backup_complete)
        self.backup_worker.failed.connect(self._backup_failed)
        self.backup_worker.finished.connect(self._worker_finished)
        self._set_actions(True)
        self.backup_worker.start()

    def _cancel_prompt(self):
        if self.backup_worker and self.backup_worker.isRunning():
            self.backup_worker.cancel_event.set()
            self.progress_bar.setFormat("Cancelling after the current encrypted chunk…")
            self.cancel_button.setEnabled(False)
            return
        device = self._selected_device()
        if device:
            self._dismissed.add(device.identity)
            self.device_status.setText("Prompt dismissed. The device remains connected.")

    def _add_source(self):
        directory = QFileDialog.getExistingDirectory(self, "Select a folder to back up", str(Path.home()))
        if not directory:
            return
        source = Path(directory).resolve()
        if source not in self.sources:
            self.sources.append(source)
            self.source_list.addItem(str(source))

    def _remove_source(self):
        row = self.source_list.currentRow()
        if row >= 0:
            self.source_list.takeItem(row)
            del self.sources[row]

    def _add_files(self):
        files, _selected_filter = QFileDialog.getOpenFileNames(
            self, "Select files to back up", str(Path.home()), "All files (*)")
        for name in files:
            source = Path(name).resolve()
            if source not in self.sources:
                self.sources.append(source)
                self.source_list.addItem(str(source))

    def _choose_vault(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose the encrypted vault folder", str(Path.home()))
        if not folder:
            return
        path = Path(folder).resolve()
        if (path / "vault.header").exists():
            password, ok = QInputDialog.getText(self, "Unlock vault", "Vault password:",
                                                QLineEdit.EchoMode.Password)
            if not ok:
                return
            try:
                vault = Vault.unlock(path, password, inactivity_timeout=300)
            except Exception as exc:
                QMessageBox.critical(self, "Could not unlock vault", f"{type(exc).__name__}: {exc}")
                return
            self._set_vault(vault, path)
            return
        if any(path.iterdir()):
            QMessageBox.warning(self, "Folder is not empty", "Choose an empty folder or an existing SecureVault folder.")
            return
        password, ok = QInputDialog.getText(self, "Create vault", "Choose a password (at least 10 characters):",
                                            QLineEdit.EchoMode.Password)
        if not ok:
            return
        confirm, ok = QInputDialog.getText(self, "Confirm password", "Enter the password again:",
                                           QLineEdit.EchoMode.Password)
        if not ok:
            return
        if password != confirm:
            QMessageBox.warning(self, "Passwords do not match", "Enter the same password twice.")
            return
        try:
            vault, recovery = Vault.create(path, password, inactivity_timeout=300)
            self._set_vault(vault, path)
            QMessageBox.information(self, "Save your recovery key",
                                    "Store this recovery key somewhere safe. It will not be shown again:\n\n" + recovery)
        except Exception as exc:
            QMessageBox.critical(self, "Could not create vault", f"{type(exc).__name__}: {exc}")

    def _set_vault(self, vault: Vault, path: Path):
        if self.vault and not self.vault.locked:
            self.vault.lock()
        self.vault, self.vault_path = vault, path
        self.settings.setValue("vault_path", str(path))
        self.vault_label.setText(f"Unlocked vault: {path}")

    def _backup_progress(self, progress: BackupProgress):
        percent = int(progress.completed_bytes * 100 / progress.total_bytes) if progress.total_bytes else 100
        self.progress_bar.setValue(percent)
        self.progress_bar.setFormat(f"{progress.status}: {progress.current_file} ({progress.completed_files}/{progress.total_files})")

    def _browser_progress(self, message: str):
        self.progress_bar.setFormat(message)

    def _backup_complete(self, result: BackupResult):
        self.start_button.setEnabled(True)
        self.details_button.setEnabled(True)
        self.cancel_button.setEnabled(True)
        self.cancel_button.setText("Cancel")
        state = "Cancelled" if result.cancelled else "Backup finished"
        self.progress_bar.setFormat(f"{state}: {result.copied} copied, {result.skipped} unchanged, {result.failed} failed")
        summary = (f"{state}.\n\nCopied: {result.copied}\nUnchanged: {result.skipped}\n"
                   f"Failed: {result.failed}\nEncrypted bytes written: {result.bytes_copied:,}")
        if result.errors:
            summary += "\n\nSome files need attention. Details are kept in the encrypted backup manifest."
        QMessageBox.information(self, state, summary)

    def _backup_failed(self, message: str):
        self.start_button.setEnabled(True)
        self.details_button.setEnabled(True)
        self.cancel_button.setEnabled(True)
        self.cancel_button.setText("Cancel")
        self.progress_bar.setFormat("Backup failed")
        QMessageBox.critical(self, "Backup failed", message)

    def _worker_finished(self):
        self.backup_worker = None
        self._selection_changed(None, None)

    def _report_error(self, error: Exception):
        self.statusBar().showMessage(f"Device scan issue: {type(error).__name__}", 5000)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("SecureVault")
    window = DeviceWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
