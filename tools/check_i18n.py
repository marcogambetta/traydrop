"""Controlla che ogni testo di TrayDrop abbia le traduzioni (en, fr, es).

Uso:  python tools/check_i18n.py      (esce con errore se manca qualcosa)
Cerca i testi in: tr("...") / item("...") / b("...") nel Python, T('...') nello
script della finestra, testi fissi e attributi placeholder/title dell'HTML.
"""
import ast, re, string, sys
from html.parser import HTMLParser
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "traydrop.py"
src = SRC.read_text(encoding="utf-8")
tree = ast.parse(src)
consts, table = {}, None
for node in ast.walk(tree):
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        name = node.targets[0].id
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            consts[name] = node.value.value
        elif name == "TRANSLATIONS":
            table = ast.literal_eval(node.value)
keys = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("tr", "item", "b") and node.args:
        a = node.args[0]
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            keys.add(a.value)
        elif isinstance(a, ast.Name) and a.id in consts and node.func.id == "tr":
            keys.add(consts[a.id])
keys.update(re.findall(r'"(Preparazione|Compressione|Invio|Ricezione|Caricamento)"', src))
body, script = consts["UI_HTML"].split("<script>", 1)
keys.update(m.group(1) for m in re.finditer(r"T\('((?:[^'\\]|\\.)*)'", script))


class P(HTMLParser):
    def handle_data(self, d):
        if d.strip():
            keys.add(d.strip())

    def handle_starttag(self, tag, attrs):
        keys.update(v for k, v in attrs if k in ("placeholder", "title") and v)


P().feed(body.split("<body>", 1)[1])
keys -= {"Tray", "Drop", "⇅", "⏻", "…", "••••••••••", "·", "Token", "TrayDrop",
         "Italiano", "English", "Français", "Español"}

fmt = string.Formatter()
ph = lambda s: sorted(f for _, f, _, _ in fmt.parse(s) if f)
errors = [f"senza traduzione: {k!r}" for k in sorted(keys) if k not in table]
for k, v in table.items():
    if len(v) != 3:
        errors.append(f"servono 3 traduzioni (en, fr, es): {k!r}")
        continue
    for lang, x in zip(("en", "fr", "es"), v):
        if ph(x) != ph(k):
            errors.append(f"[{lang}] segnaposto diversi: {k!r} -> {x!r}")
        if x.count("\n") != k.count("\n"):
            errors.append(f"[{lang}] a capo diversi: {k!r}")
unused = sorted(set(table) - keys)
for e in errors:
    print("ERRORE", e)
for u in unused:
    print("avviso: traduzione non usata:", repr(u))
print(f"{len(keys)} testi, {len(table)} traduzioni, {len(errors)} errori")
sys.exit(1 if errors else 0)
