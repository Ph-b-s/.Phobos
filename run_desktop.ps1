$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$venv = Join-Path $root ".phobos-desktop-venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "Creating Phobos desktop environment..."

    $hostPython = Get-Command python -ErrorAction SilentlyContinue
    if (-not $hostPython) {
        throw "Python was not found. Install Python 3.11 or newer and make sure 'python' is available in PATH."
    }

    $version = & $hostPython.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    $versionParts = $version.Trim().Split('.')
    $major = [int]$versionParts[0]
    $minor = [int]$versionParts[1]

    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 11)) {
        throw "Phobos requires Python 3.11 or newer. Detected Python $version."
    }

    & $hostPython.Source -m venv $venv
}

Write-Host "Installing desktop dependencies..."
& $python -m pip install --upgrade pip
& $python -m pip install -e ".[desktop]"

Write-Host "Installing Chromium for the browser runtime..."
& $python -m playwright install chromium

Write-Host "Starting Phobos desktop..."
& $python -m desktop_launcher
