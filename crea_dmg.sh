#!/bin/bash
# Crea TrayDrop.dmg: un'app per Mac autonoma (non serve Python ne' conda per usarla).
# Va lanciato SU UN MAC, dalla cartella che contiene traydrop.py:
#     bash crea_dmg.sh
# Il DMG viene creato accanto a questo script. L'app funziona sui Mac con lo stesso
# tipo di processore di quello che la crea (Apple Silicon oppure Intel).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
[[ "$(uname)" == "Darwin" ]] || { echo "Questo script va eseguito su macOS."; exit 1; }
[[ -f "$HERE/traydrop.py" ]] || { echo "traydrop.py non trovato in $HERE"; exit 1; }

# Python da usare per la compilazione (di default quello attivo: conda va bene)
PY="${PYTHON:-python}"
command -v "$PY" >/dev/null 2>&1 || PY=python3
# Lavoro fuori da OneDrive, per non sincronizzare centinaia di MB di file temporanei
B="${TMPDIR:-/tmp}/traydrop_build"
rm -rf "$B"; mkdir -p "$B"

echo "1/5  Preparo un ambiente di compilazione separato..."
"$PY" -m venv "$B/venv"
VPY="$B/venv/bin/python"
"$VPY" -m pip install -q --upgrade pip
"$VPY" -m pip install -q pyinstaller rumps pyobjc-framework-LocalAuthentication

echo "2/5  Creo l'icona..."
ICON_OPT=()
if "$VPY" -c "import sys; sys.path.insert(0, sys.argv[1]); import traydrop as t; sys.exit(0 if t._make_icns(sys.argv[2]) else 1)" \
     "$HERE" "$B/TrayDrop.icns"; then
  ICON_OPT=(--icon "$B/TrayDrop.icns")
else
  echo "     (icona non creata: proseguo senza)"
fi

echo "3/5  Compilo l'app (un paio di minuti)..."
"$B/venv/bin/pyinstaller" --noconfirm --clean --log-level WARN --windowed \
  --name TrayDrop --osx-bundle-identifier com.marco.traydrop.app ${ICON_OPT[@]+"${ICON_OPT[@]}"} \
  --hidden-import LocalAuthentication \
  --distpath "$B/dist" --workpath "$B/work" --specpath "$B" \
  "$HERE/traydrop.py"
APP="$B/dist/TrayDrop.app"
[[ -d "$APP" ]] || { echo "Compilazione non riuscita."; exit 1; }

echo "4/5  Rifinisco l'app..."
PL="$APP/Contents/Info.plist"
plutil -replace LSUIElement -bool true "$PL"                 # solo icona nella barra, niente Dock
plutil -replace CFBundleDisplayName -string "TrayDrop" "$PL"
plutil -replace CFBundleShortVersionString -string "1.0" "$PL"
plutil -replace NSHighResolutionCapable -bool true "$PL"
codesign --force --deep --sign - "$APP"                      # firma locale (necessaria su Apple Silicon)

echo "5/5  Creo il DMG..."
mkdir -p "$B/dmg"
cp -R "$APP" "$B/dmg/"
ln -s /Applications "$B/dmg/Applications"
OUT="$HERE/TrayDrop.dmg"
rm -f "$OUT"
for tentativo in 1 2 3; do   # hdiutil a volte fallisce con "Resource busy": riprova
  if hdiutil create -quiet -volname "TrayDrop" -srcfolder "$B/dmg" -fs HFS+ -format UDZO -ov "$OUT"; then
    break
  fi
  [[ $tentativo == 3 ]] && { echo "hdiutil non riesce a creare il DMG."; exit 1; }
  echo "     hdiutil occupato, riprovo..."; sleep 5
done

rm -rf "$B"
echo
echo "Fatto: $OUT  ($(du -h "$OUT" | cut -f1), per Mac $(uname -m))"
echo "Aprilo e trascina TrayDrop nella cartella Applicazioni."
