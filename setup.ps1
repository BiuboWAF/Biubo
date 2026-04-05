# Biubo WAF Setup Script (Windows Wrapper)

Write-Host "--- Biubo WAF Setup (Windows Wrapper) ---"

# 1. Dependency Check
if (! (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed. Please install it first from python.org."
    exit 1
}

# 2. Call setup.py
Write-Host "[*] Launching setup.py for interactive configuration..."
python setup.py

if ($LASTEXITCODE -ne 0) {
    Write-Error "Setup failed."
    exit 1
}

Write-Host "--- Setup Finished ---"
