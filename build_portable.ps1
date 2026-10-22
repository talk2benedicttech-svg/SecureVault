param(
    [string]$Python = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Python executable not found: $Python. Create the project virtual environment and install requirements.txt first."
}

& $Python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Installing application dependencies failed." }
& $Python -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw "Installing the Windows packaging tool failed." }

& $Python -m PyInstaller --noconfirm --clean --windowed --onedir `
    --name SecureVault `
    --collect-all argon2 `
    --collect-all cryptography `
    main.py
if ($LASTEXITCODE -ne 0) { throw "Portable application build failed." }

$PortableDir = Join-Path $ProjectRoot "dist\SecureVault"
New-Item -ItemType Directory -Force -Path (Join-Path $PortableDir "data") | Out-Null
Copy-Item -LiteralPath (Join-Path $ProjectRoot "PORTABLE-README.txt") -Destination $PortableDir -Force
Write-Host "Portable app created at: $PortableDir"
Write-Host "Copy the complete SecureVault folder to the USB drive; run SecureVault.exe from that folder."
