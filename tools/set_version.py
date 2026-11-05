"""Imposta VERSION in traydrop.py dal tag della Release (usato da GitHub Actions).

Uso:  python tools/set_version.py v1.2.0
"""
import re, sys
from pathlib import Path

tag = sys.argv[1].strip()
m = re.fullmatch(r"v?(\d+\.\d+\.\d+)", tag)
if not m:
    sys.exit(f"Tag non valido: {tag!r} (atteso es. v1.2.0)")
p = Path(__file__).resolve().parent.parent / "traydrop.py"
s = p.read_text(encoding="utf-8")
s, n = re.subn(r'^VERSION = "[^"]*"', f'VERSION = "{m.group(1)}"', s, count=1, flags=re.M)
if n != 1:
    sys.exit("Riga VERSION non trovata in traydrop.py")
p.write_text(s, encoding="utf-8")
print("VERSION =", m.group(1))
