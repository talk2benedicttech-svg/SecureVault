# SecureVault AutoBackup

SecureVault is a Windows desktop application for backing up selected local files
and folders into a password-protected encrypted vault. It can detect removable
USB drives and Windows Portable Devices (including phones exposed over MTP), then
ask before starting a backup. The connected device is the trigger; the configured
local folders and files are the backup sources.

> **Project status:** Early development. The Windows portable build has been
> generated, but device detection and backup have not been tested on a range of
> Windows PCs or physical Android phones. Read the limitations below before
> relying on it for important data.

## Features

- **Encrypted vault:** Files are streamed in 1 MiB chunks using AES-256-GCM.
  Authenticated chunk metadata detects modification, reordering, truncation, or
  chunks copied between different files.
- **Password and recovery:** Argon2id derives a wrapping key for a random vault
  master key. A one-time recovery key provides an alternative unlock method.
  Changing the password rewraps the master key; it does not re-encrypt file data.
- **Private metadata:** Names, file lists, and backup records are kept in the
  encrypted vault index. Duplicate detection uses a keyed HMAC rather than a
  public file hash.
- **Incremental backup:** Previously backed-up files are skipped when size and
  modification time are unchanged. A run checkpoints its progress so it can
  resume after interruption. Symbolic links are not followed; common Windows
  system directories at volume roots are excluded.
- **Restore integrity:** Chunks are authenticated during restore and the restored
  file's SHA-256 is checked. A failed restore does not leave a partial destination
  file.
- **Device consent:** USB storage and Windows Portable Devices are detected by
  polling. The UI provides Start Backup, View Details, and Cancel, with a
  first-use confirmation and optional per-computer device remembering.
- **Browser export (optional):** Bookmarks and browsing history from Chrome, Edge,
  and Firefox can be exported when the browser is closed. Passwords, cookies,
  and login tokens are not read.
- **Auto-lock:** The vault locks after inactivity. Vault activity during a backup
  or restore resets the inactivity timer. Key clearing from Python memory is
  best-effort only.

## Windows portable package

The packaged application includes its Python runtime and dependencies. A target
computer does not need a separate Python installation or an internet connection.
The build itself is performed on Windows and needs internet access to download
the packaging tool if it is not installed yet.

1. On the Windows build computer, open PowerShell in this project folder.
2. Run `build_portable.ps1`. By default it uses `.venv\Scripts\python.exe`.
3. Copy the entire `dist\SecureVault` folder to the USB drive.
4. On the target computer, open that folder and run `SecureVault.exe`.

Keep the generated folder structure intact. App settings and the device allowlist
are stored in its `data` folder. To keep the encrypted backup on the USB drive,
create or select the vault on that drive. Windows does not auto-run programs when
a USB drive is inserted; start the executable manually. Unsigned builds may show
a Windows SmartScreen prompt.

The generated portable folder is about 173 MB in this build and is excluded from
Git by `.gitignore`; distribute it separately from the source repository.

## Run from source

Requires Windows and Python 3.12 or later:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m ui.device_window
```

To build the Windows portable folder from the same virtual environment:

```powershell
.\build_portable.ps1
```

The script installs the application requirements and `requirements-build.txt`,
then creates `dist\SecureVault\`.

## First use

1. Choose **Create / Unlock Vault** and select an empty folder to create a vault,
   or an existing vault folder to unlock it.
2. Save the one-time recovery key somewhere safe. It will not be shown again.
3. Add the local folders and files to back up. These selections are made on the
   computer running SecureVault.
4. Connect a supported USB device or phone. Review its details and approve the
   backup prompt. The first use of an unfamiliar device requires confirmation.
5. Optionally enable browser bookmarks/history export. The relevant browser must
   be closed for export.

Backups are encrypted into the selected vault. A newly detected USB drive does
not automatically become the vault destination. For a backup stored on that USB
drive, create or select the vault there before starting the run. MTP phone storage
is currently detection-only; the app does not browse or copy files from Android.

## Device detection and privacy

The Windows removable-drive provider detects removable drive-letter volumes.
The Windows Portable Devices provider enumerates devices exposed by Windows, such
as phones in MTP/file-transfer mode. Detection does not read phone files, install
software on a device, or launch programs from a USB drive.

The interface refreshes the connected-device list every two seconds. Backup does
not start until the user chooses Start Backup and grants consent. Remembered
device identifiers are stored in `data/devices.json` next to the app, with hashes
for WPD identifiers or USB volume serials. USB serials can be duplicated or change
after reformatting; review device details before authorizing unfamiliar hardware.

The backup engine can also be run directly from Python. Its encrypted manifest
and error records are stored within the vault index. Browser export stores only
bookmarks/history in the vault and skips a browser that is still running.

## Security design

- AES-256-GCM authenticates each encrypted chunk. The final chunk marker and
  per-file associated data prevent undetected chunk reorder, deletion, truncation,
  or cross-file substitution.
- Argon2id parameters are validated and bounded when read from a vault header to
  limit hostile memory-exhaustion inputs.
- A random master key protects vault data. Password and recovery-key slots wrap
  that master key.
- Vault file names and the file index are encrypted. Duplicate detection uses a
  keyed digest so the vault does not expose public hashes for comparison.
- Restores validate chunk authentication and the final SHA-256; failed restores
  remove the partial output.
- Python cannot guarantee that key material is erased from process memory. The
  application attempts a best-effort wipe when locking.

## Known limitations

- No physical Android phone or broad range of Windows removable drives has been
  tested yet. WPD friendly names may not identify the phone make or model.
- MTP is detection-only. Files are backed up from user-selected local paths, not
  copied from Android storage.
- Windows blocks automatic execution from USB by default. The user must open and
  run the portable app manually.
- Restoring an older copy of the entire vault folder (rollback) is not detected.
- Device allowlists and app settings belong to the portable app folder. Copying
  that folder to a different drive/computer creates a separate copy of those
  settings.
- The portable distribution has not yet been exercised on a separate clean PC.

## Tests

Run the test suite from the project virtual environment:

```powershell
python -m pytest tests -v
```

If pytest cannot access its default temporary directory on Windows:

```powershell
python -m pytest tests -v --basetemp .pytest-tmp -p no:cacheprovider
```

The suite includes password/recovery, tampering and truncation, hostile header,
path traversal, restore cleanup, encrypted metadata, and backup-engine behavior.

## GitHub repository description

Suggested short description:

> Windows desktop app for consent-based, incremental file backups into an encrypted vault, with USB/MTP device detection and a portable build.

Do not commit vault folders, recovery keys, local device data, `.venv`, or the
generated `dist` bundle. `.gitignore` excludes these local/generated files.

