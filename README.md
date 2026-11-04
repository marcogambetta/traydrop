# TrayDrop

Invia file, cartelle e appunti (testo e immagini) tra i tuoi computer sulla stessa rete
locale, con un clic dall'icona ⇄ nella barra dei menu (Mac) o nell'area di notifica (Windows).

## Scaricare l'app già pronta

- **Versione ufficiale**: pagina [Releases](../../releases) → `TrayDrop-macOS-AppleSilicon.dmg`,
  `TrayDrop-macOS-Intel.dmg` oppure `TrayDrop-Windows.exe`.
- **Ultima versione di prova**: [Actions](../../actions/workflows/build.yml) → l'esecuzione più
  recente con la spunta verde → in fondo, sezione **Artifacts**.

Mac: apri il DMG e trascina TrayDrop in Applicazioni. La prima volta: tasto destro sull'app →
Apri → Apri (l'app non è firmata da Apple).
Windows: avvia `TrayDrop-Windows.exe`; se SmartScreen avvisa: "Ulteriori informazioni" → "Esegui comunque".

Al primo avvio si apre la finestra **Collega i tuoi computer**: "Cerca" trova l'altro
computer, su uno dei due "Genera nuovo" token, sull'altro "Incolla".

## Pubblicare una nuova versione

    git tag v1.1 && git push origin v1.1

GitHub Actions compila i tre file, li prova e crea la Release.

Istruzioni complete, uso da terminale e note tecniche: [LEGGIMI.md](LEGGIMI.md).
