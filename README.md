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
