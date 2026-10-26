#!/bin/bash
# CyberRakshak Installer for Linux
# "Hacker se pehle - CyberRakshak!"

set -e

INSTALL_DIR="/opt/cyberrakshak"
BIN_LINK="/usr/local/bin/cyberrakshak"

echo "==================================="
echo "  CyberRakshak Installer"
echo "  'Hacker se pehle - CyberRakshak!'"
echo "==================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Installing..."
    sudo apt update && sudo apt install -y python3
fi

echo "[*] Installing to $INSTALL_DIR..."
sudo mkdir -p $INSTALL_DIR
sudo cp -r . $INSTALL_DIR/
sudo chmod +x $INSTALL_DIR/cyberrakshak.py

echo "[*] Creating command link..."
sudo ln -sf $INSTALL_DIR/cyberrakshak.py $BIN_LINK
sudo chmod +x $BIN_LINK

echo ""
echo "[+] CyberRakshak installed successfully!"
echo "[+] Run from anywhere: cyberrakshak --target 127.0.0.1"
echo ""
