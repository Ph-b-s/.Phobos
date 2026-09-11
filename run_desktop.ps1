$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$venv = Join-Path $root ".phobos-desktop-venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "Creating Phobos desktop environment..."
    py -3.11 -m venv $venv
}

Write-Host "Installing desktop dependencies..."
& $python -m pip install --upgrade pip
& $python -m pip install -e ".[desktop]"

Write-Host "Installing Chromium for the browser runtime..."
& $python -m playwright install chromium

Write-Host "Starting Phobos desktop..."
& $python -m desktop_launcher
