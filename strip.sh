#!/bin/bash

# this script strips import strings prefixed by github.com from a go binary
# useful if you want to avoid florian roth's sigs for binject/debug :3
BIN="$1"

if [[ ! -f "$BIN" ]]; then
    echo "[-] File not found: $BIN"
    exit 1
fi

echo "[*] Stripping github.com strings from: $BIN"
patched=0

while read -r offset string; do
    offset_dec=$((16#$offset))
    strlen=${#string}
    echo "[*] Patching: $string at offset 0x$offset"
    printf '\x00%.0s' $(seq 1 $strlen) | dd of="$BIN" bs=1 seek=$offset_dec conv=notrunc status=none
    patched=$((patched + 1))
done < <(strings -a -t x "$BIN" | grep -F 'github.com' | grep -F 'wincall' | grep -Fv -e 'https://')

# Second pass: strip any remaining occurrences of 'wincall'
while read -r offset string; do
    offset_dec=$((16#$offset))
    strlen=${#string}
    echo "[*] Patching: $string at offset 0x$offset"
    printf '\x00%.0s' $(seq 1 $strlen) | dd of="$BIN" bs=1 seek=$offset_dec conv=notrunc status=none
    patched=$((patched + 1))
done < <(strings -a -t x "$BIN" | grep -F 'wincall')

# Third pass: strip any occurrences of 'Encrypt' or 'libcall' (case-insensitive)
while read -r offset string; do
    offset_dec=$((16#$offset))
    strlen=${#string}
    echo "[*] Patching: $string at offset 0x$offset"
    printf '\x00%.0s' $(seq 1 $strlen) | dd of="$BIN" bs=1 seek=$offset_dec conv=notrunc status=none
    patched=$((patched + 1))
done < <(strings -a -t x "$BIN" | grep -Ei 'encrypt|libcall')

echo "[+] Done. Patched $patched string(s)."