#!/bin/bash

# this script strips import strings prefixed by github.com from a go binary
# useful if you want to avoid florian roth's sigs for binject/debug :3
BIN="$1"

if [[ ! -f "$BIN" ]]; then
    echo "[-] File not found: $BIN"
    exit 1
fi

echo "[*] Stripping github.com strings from: $BIN"

strings -a -t x "$BIN" | grep 'github\.com' | grep -v 'https://' | while read -r offset string; do
    offset_dec=$((16#$offset))
    strlen=${#string}
    echo "[*] Patching: $string at offset 0x$offset"
    printf '\x00%.0s' $(seq 1 $strlen) | dd of="$BIN" bs=1 seek=$offset_dec conv=notrunc status=none
done

echo "[+] Done."