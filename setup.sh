#!/bin/bash

# Biubo WAF Setup Script (Linux Wrapper)

echo "--- Biubo WAF Setup (Linux Wrapper) ---"

# 1. Dependency Check
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install it first."
    exit 1
fi

# 2. Call setup.py
echo "[*] Launching setup.py for interactive configuration..."
python3 setup.py

if [ $? -ne 0 ]; then
    echo "Setup failed."
    exit 1
fi

echo "--- Setup Finished ---"
