#!/usr/bin/env python3
"""
potfile_hex_decode.py
Reads a hashcat potfile (hash:plaintext lines) and converts any
$HEX[...]-encoded plaintexts back to regular characters, writing
hash:plaintext results to an output txt file.

Prompts for: potfile, export file.
Default export is <potfile name>_decoded.txt next to the potfile
(e.g. /path/to/hashes.pot -> /path/to/hashes_decoded.txt).

Notes:
  - Each line is split on the FIRST colon: everything before it is the hash,
    everything after it is the plaintext (so plaintexts containing ':' are kept).
  - $HEX[...] plaintexts are decoded as UTF-8; bytes that aren't valid UTF-8
    become the replacement character (U+FFFD).
  - Blank lines and lines without a colon are skipped.
"""

import os
import re
import sys
import time
from datetime import datetime

HEX_PATTERN = re.compile(r"^\$HEX\[([0-9a-fA-F]+)\]$")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ---------------------------------------------------------------- input helpers

def clean_path(p):
    """Strip whitespace/quotes, expand ~ and env vars."""
    p = p.strip().strip("'\"")
    return os.path.abspath(os.path.expandvars(os.path.expanduser(p))) if p else ""


def enable_tab_completion():
    try:
        import glob
        import readline

        def complete(text, state):
            matches = glob.glob(os.path.expanduser(text) + "*")
            matches = [m + "/" if os.path.isdir(m) else m for m in matches]
            return matches[state] if state < len(matches) else None

        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        readline.set_completer(complete)
    except ImportError:
        pass


# ---------------------------------------------------------------- progress

def progress_bar(done, total, current="", width=40):
    pct = done / total if total else 1
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    label = (current[:45] + "…") if len(current) > 46 else current
    sys.stdout.write(f"\r{CYAN}[{bar}]{RESET} {pct:6.1%}  {label:<47}")
    sys.stdout.flush()


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------- decoding

def decode_line(line):
    """
    Splits a potfile line into (hash, plaintext), decoding $HEX[...]
    plaintexts back to normal characters. Returns (hash, plaintext, was_hex)
    or None if the line has no colon.
    """
    if ":" not in line:
        return None

    hash_part, plain = line.split(":", 1)

    match = HEX_PATTERN.match(plain)
    was_hex = False
    if match:
        plain = bytes.fromhex(match.group(1)).decode("utf-8", errors="replace")
        was_hex = True

    return hash_part, plain, was_hex


# ---------------------------------------------------------------- main

def main():
    enable_tab_completion()
    print(f"{BOLD}Hashcat Potfile $HEX[] Decoder{RESET}\n")

    # --- potfile (full path) ---
    potfile = clean_path(input("Potfile (full path): "))
    while not os.path.isfile(potfile):
        potfile = clean_path(input(f"{RED}Not found.{RESET} Potfile (full path): "))

    # --- export file (full path) ---
    pot_base = os.path.splitext(os.path.basename(potfile))[0]
    default_out = os.path.join(os.path.dirname(potfile), f"{pot_base}_decoded.txt")
    export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    if os.path.isdir(export_file):
        export_file = os.path.join(export_file, os.path.basename(default_out))
    while os.path.abspath(export_file) == potfile:
        print(f"{RED}Export can't be the potfile itself.{RESET}")
        export_file = clean_path(input(f"Export file (full path) [{default_out}]: ")) or default_out
    out_dir = os.path.dirname(export_file)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        print(f"{YELLOW}[*] Created {out_dir}{RESET}")
    if os.path.isfile(export_file):
        print(f"{YELLOW}[!] {export_file} exists and will be overwritten.{RESET}")

    total_bytes = os.path.getsize(potfile)
    print(f"\n{BOLD}[*] Decoding potfile ({fmt_size(total_bytes)}){RESET}")

    start = time.time()
    bytes_read = lines = count = decoded = skipped = 0

    with open(potfile, "rb") as infile, open(export_file, "w", encoding="utf-8") as outfile:
        for raw in infile:
            lines += 1
            bytes_read += len(raw)
            line = raw.decode("utf-8", errors="ignore").rstrip("\r\n")

            if line.strip():
                result = decode_line(line)
                if result is None:
                    skipped += 1
                else:
                    hash_part, plain, was_hex = result
                    outfile.write(f"{hash_part}:{plain}\n")
                    count += 1
                    decoded += was_hex

            if lines % 2000 == 0:
                progress_bar(bytes_read, total_bytes,
                             f"{fmt_size(bytes_read)} / {fmt_size(total_bytes)}")

    progress_bar(total_bytes, total_bytes, "done")
    print("\n")

    print("-" * 80)
    print(f"[*] {count} line(s) written, {GREEN}{decoded} $HEX[...] value(s) decoded{RESET}"
          f" ({time.time() - start:.1f}s)")
    if skipped:
        print(f"{YELLOW}[!] {skipped} line(s) skipped (no colon){RESET}")
    print(f"\n[+] Output: {export_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted.{RESET}")
        sys.exit(130)
