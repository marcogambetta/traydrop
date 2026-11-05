# TrayDrop (macOS, Windows, Linux)

Invia file tra i tuoi computer sulla stessa LAN con un click dall'icona nella
barra dei menu (Mac) o nell'area di notifica (Windows/Linux).

## Requisiti (su ogni computer)
- Python 3.9+
- macOS:    pip3 install rumps
- Windows:  pip install pystray pillow      (usa "python" invece di "python3")
- Linux:    pip3 install pystray pillow ; sudo apt install python3-tk
            (per l'icona serve un ambiente con tray/AppIndicator, es. GNOME con l'estensione AppIndicator)

## Versioni compilate su GitHub (consigliato)
Il codice e' su github.com/marcogambetta/traydrop (privato). Ad ogni modifica GitHub Actions
compila e prova da solo: DMG per Mac Apple Silicon, DMG per Mac Intel, exe per Windows.
- Ultima versione: pagina Actions > esecuzione con la spunta verde > in fondo "Artifacts".
- Versione ufficiale: crea un tag (git tag v1.1 && git push origin v1.1) e trovi i file in "Releases".
- Non serve piu' lanciare crea_dmg.sh sul Mac (resta utile per provare in locale).

## TrayDrop.dmg (app autonoma, senza Python)
Da creare UNA volta su un Mac, dalla cartella TRAYDROP:
    bash crea_dmg.sh
- Ci vogliono un paio di minuti (scarica PyInstaller e rumps in un ambiente temporaneo,
  fuori da OneDrive). Alla fine trovi TrayDrop.dmg nella cartella TRAYDROP.
- Apri il DMG e trascina TrayDrop in Applicazioni. Da li' la trovi in Launchpad e Spotlight.
- L'app non ha bisogno di Python ne' di conda: puoi usarla anche su un Mac senza Python.
- Funziona sui Mac con lo stesso processore di quello che la crea (Apple Silicon o Intel).
- Avvio automatico: menu ⇄ > "Avvia all'accesso" (spunta = attivo).
- Sull'altro Mac, se macOS dice che non puo' verificare lo sviluppatore (l'app non e'
  firmata da Apple): tasto destro sull'app > Apri > Apri. Basta la prima volta.
  In alternativa:  xattr -dr com.apple.quarantine /Applications/TrayDrop.app
  Su un Mac aziendale la policy potrebbe bloccarla del tutto: in quel caso usa install-app.
- Dopo un aggiornamento di traydrop.py: rilancia crea_dmg.sh e reinstalla l'app.
- La configurazione e' la stessa della versione script (~/.traydrop): non va rifatta.

## App sul Mac senza DMG (usa il Python di conda)
    python traydrop.py install-app
- Crea ~/Applications/TrayDrop.app con la sua icona: la trovi in Launchpad, con Spotlight
  (⌘ Spazio > "TrayDrop") e in Finder > Applicazioni. Puoi trascinarla nel Dock.
- Doppio clic = compare ⇄ nella barra dei menu. Se TrayDrop e' gia' acceso, il doppio clic
  apre solo la finestra (non parte una seconda copia).
- L'app contiene una COPIA di traydrop.py: dopo ogni aggiornamento rilancia install-app.
- Se l'avvio automatico e' attivo, install-app lo aggiorna per usare l'app (TrayDrop si riavvia).
- "Esci" dal menu ora chiude davvero TrayDrop anche con l'avvio automatico (riparte al
  prossimo accesso o con un doppio clic sull'app); se invece si blocca, riparte da solo.
- Per toglierla: trascina ~/Applications/TrayDrop.app nel Cestino.

## Configurazione (una volta, dalla finestra)
1. Avvia TrayDrop su ENTRAMBI i computer (python traydrop.py menubar / tray / gui).
   Al primo avvio la finestra "Collega i tuoi computer" si apre da sola.
2. "Altro computer": premi "Cerca" e clicca il computer trovato (oppure scrivi l'IP:
   sull'altro computer e' indicato in "Questo computer").
3. Token: su UNO dei due scegli "Genera nuovo" e premi "Copia";
   sull'altro scegli "Incolla" e incollalo.
4. "Salva e prova": se compare "Collegato ✓" hai finito. Altrimenti il messaggio dice cosa
   controllare (token diverso, TrayDrop spento, IP sbagliato, firewall / Netskope).
- Per cambiare in seguito: pannello "Collegamento" > "Modifica", oppure menu ⇄ > "Collegamento…".
  I cambiamenti valgono subito, senza riavviare.
- "Avanzate": porta (la stessa su entrambi) e cartella dei ricevuti.
- Pannello "Computer nella rete" nella finestra: elenca i TrayDrop accesi nella stessa rete
  (si aggiorna da solo ogni 20 s, oppure "Aggiorna"). "Collega" apre la configurazione con
  quel computer gia' inserito. Se il destinatario non compare, i due computer non sono
  sulla stessa rete (o la rete blocca la ricerca: in quel caso l'IP si scrive a mano).
- "Cerca" usa un messaggio broadcast in LAN (senza token). Se una rete o Netskope lo
  blocca, basta scrivere l'IP a mano.
- Da terminale funziona ancora:  python traydrop.py init --peer <IP> [--token <TOKEN>]

Con piu' di due computer: il "peer" e' un solo destinatario; per ora l'app parla
con una coppia. (Estendibile a una lista di destinatari.)

## Aggiornamenti
- TrayDrop controlla da solo (all'avvio e ogni 12 ore) se su GitHub c'e' una Release piu' nuova.
  Se c'e': notifica, barra "E' disponibile TrayDrop X" nella finestra e voce "Aggiorna a…" nel menu ⇄.
- "Aggiorna e riavvia": scarica il file giusto per il tuo sistema e processore (Mac Apple
  Silicon/Intel, Windows, Linux x86_64/arm64), ne verifica lo SHA-256, sostituisce l'app e la
  riavvia. La finestra aperta si ricarica da sola sulla versione nuova.
- Si aggiornano da sole le versioni compilate (DMG, exe, binario Linux) se la loro cartella e'
  scrivibile. Con lo script (python traydrop.py) il pulsante apre la pagina della Release.
- Controllo manuale: finestra > Collegamento > Versione > "Controlla aggiornamenti",
  oppure menu ⇄ > "Controlla aggiornamenti…", oppure:  python traydrop.py check-update
- Per non controllare in automatico: togli la spunta "controlla ogni giorno".
  Il controllo e' una richiesta a api.github.com: non invia nulla di tuo.
- Versione installata:  TrayDrop version  (oppure riga "Versione" nella finestra).

## Pubblicare una nuova versione
    git tag v1.1.0 && git push origin v1.1.0      (con il token, come per main)
  GitHub Actions scrive 1.1.0 dentro l'app, compila Mac/Windows/Linux, li prova e crea la
  Release: da quel momento tutti i TrayDrop installati propongono l'aggiornamento.

## Lingua
- TrayDrop parla italiano, inglese, francese e spagnolo. Di default usa la lingua del sistema
  (se non e' tra queste: inglese). Per cambiarla: finestra > pannello Collegamento > "Lingua".
  Finestra, menu e notifiche cambiano subito.
- Per aggiungere o modificare un testo: scrivilo in italiano con tr("...") (Python) o T('...')
  (finestra) e aggiungi le traduzioni nel dizionario TRANSLATIONS in fondo a traydrop.py.
  python tools/check_i18n.py controlla che non manchi nulla (lo fa anche GitHub Actions).

## Uso
    python traydrop.py gui            # FINESTRA moderna: drag & drop, storico, stato collegamento (consigliata)
    python traydrop.py tk             # finestra semplice tkinter (alternativa)
    python3 traydrop.py menubar        # (alias: tray) avvia l'icona
    python3 traydrop.py ping           # test connessione
    python3 traydrop.py send FILE...   # invio da terminale
    python traydrop.py clip            # invia gli appunti (testo, immagine o file copiati)
    python3 traydrop.py install-login  # avvio automatico all'accesso
    python3 traydrop.py install-shortcut  # Windows: "Invia a > TrayDrop"; Linux: script Nautilus

- macOS: clic su ⇄ > "Invia selezione del Finder" (o "Scegli file/cartella").
- Windows/Linux: clic sull'icona = selettore file; menu per cartelle, test, ricevuti.
- Le cartelle viaggiano come .zip. I file ricevuti vanno in ~/Downloads/TrayDrop.

## Appunti (testo / immagine)
- Copia qualcosa (⌘C / Ctrl+C), poi menu ⇄ > "Invia appunti", oppure il pulsante "Invia appunti" nella finestra.
- Sull'altro computer finisce direttamente negli appunti: incolla con ⌘V / Ctrl+V. Arriva una notifica.
- Le immagini vengono salvate anche come PNG in ~/Downloads/TrayDrop ("Appunti <data ora>.png").
- File copiati nel Finder / Esplora file: partono come normali file.
- Priorità: file copiati > testo > immagine (da Excel/Word arriva il testo, non l'immagine delle celle).
- Nella finestra, "Testi ricevuti" mostra gli ultimi 10 testi arrivati con "Copia" per rimetterli negli appunti
  (solo in memoria: spariscono quando chiudi TrayDrop).
- Invio solo a mano, mai automatico: negli appunti finiscono spesso password e codici.
- Limite 50 MB. Il testo formattato arriva come testo semplice.
- Va aggiornato TrayDrop su ENTRAMBI i computer (la versione vecchia rifiuta gli appunti).
- Scorciatoia da tastiera (Mac): app Comandi Rapidi > nuovo comando "Esegui script shell" con
  `<percorso python> <percorso>/traydrop.py clip`, poi assegnagli una scorciatoia.
- Linux: serve wl-clipboard (Wayland) o xclip (X11). Windows/macOS: nessun pacchetto in più.

## Note
- Porta TCP 8787 in ingresso: consenti Python nel firewall (Windows/macOS lo chiedono da soli).
- Usa IP fissi (riserva l'indirizzo di ogni computer nel router).
- Firma HMAC col token + checksum SHA-256. Il contenuto viaggia in chiaro sulla LAN.
- Vuoi un .exe / .app da doppio clic senza installare Python? Vedi "Windows: creare TrayDrop.exe".

## Linux
- Versione compilata: TrayDrop-Linux-x86_64.tar.gz (PC) o TrayDrop-Linux-arm64.tar.gz
  (Raspberry Pi 64 bit, ARM), da Actions > Artifacts o dalle Releases.
    mkdir -p ~/.local/bin && tar -xzf TrayDrop-Linux-x86_64.tar.gz -C ~/.local/bin
    ~/.local/bin/TrayDrop install-app      # voce "TrayDrop" nel menu delle applicazioni
    ~/.local/bin/TrayDrop install-login    # facoltativo: avvio automatico
- Doppio clic / menu applicazioni: icona ⇄ nell'area di notifica E finestra TrayDrop.
  Sui desktop senza area di notifica (GNOME di serie) resta solo la finestra.
- Appunti: serve wl-clipboard (Wayland) o xclip (X11):  sudo apt install wl-clipboard xclip
- Compilato su Ubuntu 22.04: funziona sulle distribuzioni con glibc 2.35 o piu' recente.

## Windows
- Installa:  pip install pystray pillow   (e, se vuoi la finestra nativa, pywebview)
- Avvio:     python traydrop.py tray   (icona nell'area di notifica; clic = finestra)
- Avvio automatico / "Invia a":  python traydrop.py install-login  /  install-shortcut
  I .cmd creati impostano da soli il PATH dell'ambiente conda (non serve "conda activate").
- I file che arrivano dal Mac con caratteri non validi su Windows (: ? * " < > |) vengono
  rinominati con "_" (es. "Report: Q3?.pdf" -> "Report_ Q3_.pdf").
- Una seconda copia di TrayDrop non puo' occupare la stessa porta: se e' gia' attivo,
  "gui" riapre solo la finestra (come su Mac).
- Appunti: usa PowerShell, gia' presente in Windows. Su PC aziendali con PowerShell
  bloccato (modalita' "Constrained Language") l'invio/ricezione degli appunti non funziona.
- "Mostra con impronta" (token) c'e' solo su Mac. Su Windows, per collegare un nuovo
  computer usa "Modifica" > "Genera nuovo" (e incollalo sull'altro), oppure leggilo con
  type %USERPROFILE%\.traydrop\config.json

## Windows: creare TrayDrop.exe (da fare SU Windows: PyInstaller non crea .exe da Mac/Linux)
    pip install pyinstaller pystray pillow
    pyinstaller --onefile --noconsole --name TrayDrop --hidden-import pystray._win32 traydrop.py
  -> dist\TrayDrop.exe. Doppio clic = icona nell'area di notifica.
- Al primo doppio clic si apre la finestra "Collega i tuoi computer": configuri tutto li'.
  La configurazione e' in %USERPROFILE%\.traydrop (la stessa usata da python traydrop.py).
- Poi, dall'exe:  TrayDrop.exe install-login  e  TrayDrop.exe install-shortcut
- Defender/SmartScreen a volte segnalano gli exe "onefile" non firmati: e' normale,
  scegli "Ulteriori informazioni > Esegui comunque", oppure usa --onedir invece di --onefile.

## Se l'icona non compare (macOS)
- Con il notch la barra dei menu nasconde le icone se e' piena: chiudi qualche icona o usa `gui`.
- Impostazioni > Barra dei menu > "Consenti nella barra dei menu": abilita Python.
- Leggi i messaggi stampati nel Terminale all'avvio (errori, porta occupata, rumps mancante).
- Drag & drop nella finestra: pip3 install tkinterdnd2

## Finestra "gui"
- Si apre come app a se' (finestra Chrome/Edge/Brave se presenti, altrimenti il browser). Lanciare `gui` di nuovo
  riapre solo la finestra se TrayDrop e' gia' attivo.
- Finestra nativa senza browser (opzionale): pip install pywebview
- La finestra e' raggiungibile solo dal tuo computer (127.0.0.1) ed e' protetta da una chiave casuale.
- Cartelle: usa "Scegli cartella..." (viaggiano come .zip). I file si trascinano nella finestra.
- Dalla barra dei menu / area di notifica c'e' la voce "Apri finestra TrayDrop".
- Barra di progresso per ogni trasferimento (in invio e in ricezione) con percentuale, MB e velocita'.
- Pannello "Collegamento": IP di questo computer, destinatario e token (Mostra / Copia su Mac);
  "Modifica" per cambiare altro computer, token, porta o cartella. Clic sul pallino in alto = stessa cosa.
- Pulsante ⏻ in alto a destra = spegne TrayDrop (interrompe anche i trasferimenti in corso). Per riaccenderlo: python traydrop.py gui
