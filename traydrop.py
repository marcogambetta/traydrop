#!/usr/bin/env python3
"""TrayDrop - invia file tra i tuoi computer (macOS, Windows, Linux) sulla stessa LAN con un click.

Ogni computer esegue sia il ricevitore (server HTTP) sia il mittente (icona nella
barra dei menu / area di notifica). Autenticazione: firma HMAC-SHA256 con un segreto
condiviso (mai trasmesso). Il nucleo usa solo la libreria standard; per l'icona:
  macOS:          pip3 install rumps
  Windows/Linux:  pip install pystray pillow

Uso:
  python3 traydrop.py init --peer 192.168.1.156 [--token XXXX]
  python3 traydrop.py menubar        # icona nella barra/area di notifica (alias: tray)
  python3 traydrop.py gui           # FINESTRA moderna (drag & drop, storico) - consigliata
  python3 traydrop.py tk            # finestra semplice tkinter (alternativa)
  python3 traydrop.py serve          # solo ricevitore (senza interfaccia)
  python3 traydrop.py send FILE...   # invia da terminale
  python3 traydrop.py clip           # invia gli appunti (testo, immagine o file copiati)
  python3 traydrop.py ping           # test connessione
  python3 traydrop.py install-login  # avvio automatico al login
  python traydrop.py install-app     # macOS: crea TrayDrop.app in Applicazioni (Launchpad, Spotlight)
  python3 traydrop.py install-shortcut  # 'Invia a > TrayDrop' in Esplora file / Nautilus
"""
import argparse, hashlib, hmac, http.client, json, os, secrets, shutil
import shlex, socket, struct, subprocess, sys, tempfile, threading, time, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

HOME = Path(os.environ.get("TRAYDROP_HOME", Path.home() / ".traydrop"))
CONFIG = HOME / "config.json"
DEFAULT_PORT = 8787
CHUNK = 1024 * 1024
CLIP_MAX = 50 * 1024 * 1024  # limite per testo/immagine dagli appunti


def default_inbox():
    return os.environ.get("TRAYDROP_INBOX") or str(Path.home() / "Downloads" / "TrayDrop")


def load_cfg(allow_missing=False):
    """Legge ~/.traydrop/config.json. Con allow_missing=True (interfacce grafiche) una config
    mancante non e' un errore: si parte 'da configurare' e la finestra chiede i dati."""
    if not CONFIG.exists():
        if allow_missing:
            return {"peer": "", "port": DEFAULT_PORT, "token": secrets.token_urlsafe(24),
                    "inbox": default_inbox(), "_new": True}
        msg = ("TrayDrop non e' ancora configurato. Apri la finestra (python traydrop.py gui) "
               "oppure: python traydrop.py init --peer <IP-altro-computer>")
        if IS_WIN:  # con pythonw / .exe senza console il messaggio non si vedrebbe
            notify("TrayDrop - errore", msg)
        sys.exit(msg)
    cfg = json.loads(CONFIG.read_text())
    cfg.setdefault("port", DEFAULT_PORT)
    cfg["inbox"] = os.environ.get("TRAYDROP_INBOX") or cfg.get("inbox") or default_inbox()
    return cfg


def save_cfg(cfg):
    """Salva la config in modo atomico, leggibile solo dall'utente."""
    HOME.mkdir(parents=True, exist_ok=True)
    data = {k: cfg[k] for k in ("peer", "port", "peer_port", "token", "inbox", "ui_port")
            if cfg.get(k) not in (None, "")}
    tmp = CONFIG.with_name(CONFIG.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    os.replace(tmp, CONFIG)
    cfg.pop("_new", None)


def is_configured(cfg):
    return bool(cfg.get("peer")) and not cfg.get("_new")


def sign(token, msg):
    return hmac.new(token.encode(), msg.encode(), hashlib.sha256).hexdigest()


IS_MAC = sys.platform == "darwin"
IS_WIN = sys.platform.startswith("win")
_tray = None  # icona pystray (Windows/Linux), impostata da run_tray


FROZEN = getattr(sys, "frozen", False)  # True dentro un .exe / .app creato con PyInstaller


def self_cmd(*args, console=True):
    """Comando per rilanciare TrayDrop con altri argomenti: funziona sia come script
    Python sia come eseguibile impacchettato con PyInstaller."""
    if FROZEN:
        return [sys.executable, *args]
    return [py_exe(console), str(Path(__file__).resolve()), *args]


def win_cmd_file(args, background=False):
    """Contenuto di un file .cmd (Avvio automatico / Invia a) che lancia TrayDrop.
    UTF-8 + chcp 65001 per i percorsi con lettere accentate; con conda aggiunge le
    cartelle delle DLL al PATH (senza 'conda activate' pystray/Pillow possono non caricarsi)."""
    lines = ["@echo off", "chcp 65001 >nul"]
    pfx = Path(sys.prefix)
    if not FROZEN and (pfx / "conda-meta").exists():
        dirs = [pfx, pfx / "Library/mingw-w64/bin", pfx / "Library/usr/bin", pfx / "Library/bin", pfx / "Scripts"]
        lines.append('set "PATH=' + ";".join(str(d) for d in dirs) + ';%PATH%"')
    cmd = " ".join(f'"{c}"' for c in self_cmd(*args, console=False))
    lines.append(f'start "" {cmd}' if background else f"{cmd} %*")
    return "\r\n".join(lines) + "\r\n"


_WIN_BAD = set('<>:"/\\|?*') | {chr(i) for i in range(32)}
_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def safe_name(name):
    """Su Windows rende valido un nome di file arrivato da Mac/Linux (es. 'Report: Q3?.pdf')."""
    if not IS_WIN:
        return name
    n = "".join("_" if c in _WIN_BAD else c for c in name).rstrip(" .")
    if n.split(".")[0].upper() in _WIN_RESERVED:
        n = "_" + n
    return n or "file"


class Server(ThreadingHTTPServer):
    """Su Windows SO_REUSEADDR permette a DUE processi di ascoltare sulla stessa porta:
    una seconda istanza di TrayDrop partirebbe senza errori e si 'ruberebbe' i file.
    Li' serve invece l'uso esclusivo della porta."""
    if IS_WIN:
        allow_reuse_address = False

        def server_bind(self):
            excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
            if excl is not None:
                self.socket.setsockopt(socket.SOL_SOCKET, excl, 1)
            super().server_bind()


def py_exe(console=True):
    """Interprete Python; su Windows sceglie python.exe (console) o pythonw.exe (senza finestra)."""
    exe = Path(sys.executable)
    if IS_WIN:
        alt = exe.with_name("python.exe" if console else "pythonw.exe")
        if alt.exists():
            return str(alt)
    return str(exe)


def notify(title, msg):
    try:
        if IS_MAC:
            esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
            subprocess.run(["osascript", "-e",
                            f'display notification "{esc(msg)}" with title "{esc(title)}"'],
                           capture_output=True)
        elif IS_WIN:
            if _tray is not None:
                _tray.notify(msg, title)
            elif "errore" in title.lower():
                import ctypes
                ctypes.windll.user32.MessageBoxW(0, msg, title, 0x10)
            else:
                print(f"[{title}] {msg}")
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", title, msg], capture_output=True)
        elif _tray is not None:
            _tray.notify(msg, title)
        else:
            print(f"[{title}] {msg}")
    except Exception:
        print(f"[{title}] {msg}")


def open_folder(path):
    Path(path).mkdir(parents=True, exist_ok=True)
    if IS_MAC:
        subprocess.run(["open", str(path)])
    elif IS_WIN:
        os.startfile(str(path))  # noqa
    else:
        subprocess.run(["xdg-open", str(path)])


UI_STATE = {"events": [], "online": None, "info": "", "clips": [], "clip_n": 0,
            "lock": threading.Lock()}


TRANSFERS = {}
_tr_lock = threading.Lock()


def tr_start(direction, name, total=0, base=0.0, span=1.0, phase=""):
    tid = secrets.token_hex(4)
    now = time.time()
    with _tr_lock:
        TRANSFERS[tid] = {"id": tid, "dir": direction, "name": name, "total": total, "done": 0,
                          "frac": 0.0, "phase": phase, "t0": now, "tp": now, "d0": 0,
                          "speed": 0.0, "base": base, "span": span}
    return tid


def tr_set(tid, done=None, total=None, frac=None, phase=None):
    t = TRANSFERS.get(tid)
    if not t:
        return
    now = time.time()
    if phase is not None and phase != t["phase"]:
        t["phase"], t["tp"], t["d0"], t["speed"] = phase, now, done or 0, 0.0
    if total is not None:
        t["total"] = total
    if done is not None:
        t["done"] = done
        dt = now - t["tp"]
        if dt > 0.25:
            t["speed"] = (done - t["d0"]) / dt
    if frac is not None:
        t["frac"] = max(0.0, min(1.0, frac))


def tr_end(tid):
    with _tr_lock:
        TRANSFERS.pop(tid, None)


def tr_list():
    with _tr_lock:
        return sorted((dict(v) for v in TRANSFERS.values()), key=lambda v: v["t0"])


def local_ip():
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.connect(("10.255.255.255", 1))
        ip = sk.getsockname()[0]
        sk.close()
        return ip
    except Exception:
        return "?"


def ui_event(kind, name, size=0, status="ok", err=""):
    with UI_STATE["lock"]:
        UI_STATE["events"].insert(0, {"kind": kind, "name": name, "size": size,
                                      "status": status, "err": err, "t": time.time()})
        del UI_STATE["events"][40:]


# ----------------------------------------------------------------- appunti
# clip_read()  -> ("files", [percorsi]) | ("text", str) | ("image", png_bytes) | (None, None)
# clip_write_text(s) / clip_write_image(png_bytes)
# Priorita' in lettura: file copiati > testo > immagine (Excel/Word mettono negli
# appunti sia il testo sia un'immagine: di solito si vuole il testo).
PASTE_KEY = "⌘V" if IS_MAC else "Ctrl+V"


def png_size(b):
    if len(b) >= 24 and b[:8] == b"\x89PNG\r\n\x1a\n":
        return struct.unpack(">II", b[16:24])
    return None


def describe_clip(kind, data):
    if kind == "text":
        return f"Appunti · testo ({len(data.decode('utf-8', 'replace'))} caratteri)"
    wh = png_size(data)
    return f"Appunti · immagine {wh[0]}×{wh[1]}" if wh else "Appunti · immagine"


def _run(cmd, **kw):
    kw.setdefault("timeout", 20)
    return subprocess.run(cmd, **kw)


# --- macOS: NSPasteboard (PyObjC, gia' presente con rumps); ripiego su pbcopy/osascript
def _mac_read():
    try:
        from AppKit import NSPasteboard, NSURL, NSBitmapImageRep
        try:
            from AppKit import NSPasteboardURLReadingFileURLsOnlyKey as FILES_ONLY
        except ImportError:
            FILES_ONLY = "NSPasteboardURLReadingFileURLsOnlyKey"
    except ImportError:
        return _mac_read_cli()
    pb = NSPasteboard.generalPasteboard()
    urls = pb.readObjectsForClasses_options_([NSURL], {FILES_ONLY: True}) or []
    paths = [str(u.path()) for u in urls if u.isFileURL()]
    if paths:
        return "files", paths
    s = pb.stringForType_("public.utf8-plain-text")
    if s:
        return "text", str(s)
    types = [str(t) for t in (pb.types() or [])]
    if "public.png" in types:
        d = pb.dataForType_("public.png")
        if d:
            return "image", bytes(d)
    if "public.tiff" in types:
        d = pb.dataForType_("public.tiff")
        rep = NSBitmapImageRep.imageRepWithData_(d) if d else None
        png = rep.representationUsingType_properties_(4, {}) if rep else None  # 4 = PNG
        if png:
            return "image", bytes(png)
    return None, None


def _mac_read_cli():
    env = dict(os.environ, LC_CTYPE="UTF-8")
    r = _run(["osascript", "-e", "POSIX path of (the clipboard as «class furl»)"],
             capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return "files", [r.stdout.strip()]
    r = _run(["pbpaste"], capture_output=True, env=env)
    if r.stdout:
        return "text", r.stdout.decode("utf-8", "replace")
    d = Path(tempfile.mkdtemp())
    try:
        f = d / "clip.png"
        _run(["osascript", "-e", f'set f to open for access POSIX file "{f}" with write permission',
              "-e", "write (the clipboard as «class PNGf») to f", "-e", "close access f"],
             capture_output=True)
        if f.exists() and f.stat().st_size:
            return "image", f.read_bytes()
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return None, None


def _mac_write_text(s):
    try:
        from AppKit import NSPasteboard
    except ImportError:
        _run(["pbcopy"], input=s.encode("utf-8"), env=dict(os.environ, LC_CTYPE="UTF-8"), check=True)
        return
    pb = NSPasteboard.generalPasteboard()
    pb.clearContents()
    if not pb.setString_forType_(s, "public.utf8-plain-text"):
        raise RuntimeError("scrittura negli appunti rifiutata")


def _mac_write_image(png):
    try:
        from AppKit import NSPasteboard, NSBitmapImageRep
        from Foundation import NSData
    except ImportError:
        d = Path(tempfile.mkdtemp())
        try:
            f = d / "clip.png"
            f.write_bytes(png)
            _run(["osascript", "-e", f'set the clipboard to (read (POSIX file "{f}") as «class PNGf»)'],
                 capture_output=True, check=True)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        return
    data = NSData.dataWithBytes_length_(png, len(png))
    pb = NSPasteboard.generalPasteboard()
    pb.clearContents()
    pb.setData_forType_(data, "public.png")
    rep = NSBitmapImageRep.imageRepWithData_(data)
    if rep is not None:  # anche TIFF, per le app piu' vecchie
        pb.setData_forType_(rep.TIFFRepresentation(), "public.tiff")


# --- Windows: PowerShell + System.Windows.Forms.Clipboard (nessuna dipendenza)
def _psq(p):
    return "'" + str(p).replace("'", "''") + "'"


def _ps(script):
    import base64
    enc = base64.b64encode(("Add-Type -AssemblyName System.Windows.Forms,System.Drawing\n" + script)
                           .encode("utf-16-le")).decode()
    r = _run(["powershell", "-NoProfile", "-NonInteractive", "-STA", "-EncodedCommand", enc],
             capture_output=True, text=True, creationflags=0x08000000)
    if r.returncode:
        raise RuntimeError((r.stderr or "PowerShell: errore").strip()[-300:])


def _win_read():
    d = Path(tempfile.mkdtemp())
    try:
        o = d / "clip"
        _ps(f"$o={_psq(o)}\n$C=[Windows.Forms.Clipboard]\n"
            "if($C::ContainsFileDropList()){[IO.File]::WriteAllLines($o+'.files',[string[]]@($C::GetFileDropList()))}\n"
            "elseif($C::ContainsText()){[IO.File]::WriteAllText($o+'.txt',$C::GetText())}\n"
            "elseif($C::ContainsImage()){$C::GetImage().Save($o+'.png',[Drawing.Imaging.ImageFormat]::Png)}\n")
        f = d / "clip.files"
        if f.exists():
            paths = [l for l in f.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
            return ("files", paths) if paths else (None, None)
        f = d / "clip.txt"
        if f.exists():
            s = f.read_text(encoding="utf-8-sig")
            return ("text", s) if s else (None, None)
        f = d / "clip.png"
        if f.exists():
            return "image", f.read_bytes()
        return None, None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _win_write(kind, data):
    d = Path(tempfile.mkdtemp())
    try:
        if kind == "text":
            f = d / "clip.txt"
            f.write_text(data, encoding="utf-8")
            _ps(f"[Windows.Forms.Clipboard]::SetText([IO.File]::ReadAllText({_psq(f)}))")
        else:
            f = d / "clip.png"
            f.write_bytes(data)
            _ps(f"$i=[Drawing.Image]::FromFile({_psq(f)});[Windows.Forms.Clipboard]::SetImage($i);$i.Dispose()")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --- Linux: wl-clipboard (Wayland) o xclip (X11)
def _lx_tool():
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste") and shutil.which("wl-copy"):
        return "wl"
    if shutil.which("xclip"):
        return "x"
    raise RuntimeError("serve wl-clipboard (Wayland) o xclip (X11): sudo apt install wl-clipboard xclip")


def _lx_get(t, mime=None):
    if t == "wl":
        cmd = ["wl-paste", "--no-newline"] + (["--type", mime] if mime else [])
    else:
        cmd = ["xclip", "-selection", "clipboard", "-o"] + (["-t", mime] if mime else [])
    r = _run(cmd, capture_output=True)
    return r.stdout if r.returncode == 0 else b""


def _lx_read():
    t = _lx_tool()
    raw = (_run(["wl-paste", "--list-types"], capture_output=True) if t == "wl" else
           _run(["xclip", "-selection", "clipboard", "-t", "TARGETS", "-o"], capture_output=True)).stdout
    types = raw.decode("utf-8", "replace").split()
    if "text/uri-list" in types:
        from urllib.request import url2pathname
        uris = _lx_get(t, "text/uri-list").decode("utf-8", "replace").splitlines()
        paths = [url2pathname(urlparse(u.strip()).path) for u in uris if u.strip().startswith("file://")]
        if paths:
            return "files", paths
    if any(x in types for x in ("text/plain;charset=utf-8", "UTF8_STRING", "text/plain", "STRING")):
        s = _lx_get(t).decode("utf-8", "replace")
        if s:
            return "text", s
    if "image/png" in types:
        b = _lx_get(t, "image/png")
        if b:
            return "image", b
    return None, None


def _lx_write(kind, data):
    t = _lx_tool()
    mime = "text/plain;charset=utf-8" if kind == "text" else "image/png"
    payload = data.encode("utf-8") if kind == "text" else data
    cmd = ["wl-copy", "--type", mime] if t == "wl" else ["xclip", "-selection", "clipboard", "-t",
                                                           "UTF8_STRING" if kind == "text" else mime, "-i"]
    # xclip / wl-copy restano in background a "tenere" gli appunti: niente pipe su stdout
    _run(cmd, input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def clip_read():
    if IS_MAC:
        return _mac_read()
    if IS_WIN:
        return _win_read()
    return _lx_read()


def clip_write_text(s):
    if IS_MAC:
        return _mac_write_text(s)
    if IS_WIN:
        return _win_write("text", s)
    return _lx_write("text", s)


def clip_write_image(png):
    if IS_MAC:
        return _mac_write_image(png)
    if IS_WIN:
        return _win_write("image", png)
    return _lx_write("image", png)


def remember_clip(text):
    with UI_STATE["lock"]:
        UI_STATE["clip_n"] += 1
        UI_STATE["clips"].insert(0, {"id": UI_STATE["clip_n"], "text": text[:2_000_000], "t": time.time()})
        del UI_STATE["clips"][10:]


def on_clip_received(cfg, kind, data):
    """Mette negli appunti il testo/immagine ricevuto. Le immagini restano anche come PNG
    nella cartella ricevuti; il testo viene salvato in .txt solo se gli appunti falliscono."""
    label = describe_clip(kind, data)
    inbox = Path(cfg["inbox"])
    stamp = time.strftime("%Y-%m-%d %H.%M.%S")
    saved, err = None, ""
    if kind == "image":
        inbox.mkdir(parents=True, exist_ok=True)
        saved = unique_path(inbox, f"Appunti {stamp}.png")
        saved.write_bytes(data)
    try:
        if kind == "text":
            text = data.decode("utf-8", "replace")
            remember_clip(text)
            clip_write_text(text)
        else:
            clip_write_image(data)
    except Exception as e:
        err = str(e)
        if kind == "text":
            inbox.mkdir(parents=True, exist_ok=True)
            saved = unique_path(inbox, f"Appunti {stamp}.txt")
            saved.write_bytes(data)
    if err:
        ui_event("in", label, len(data), "error", f"appunti non aggiornati ({err}); salvato in {saved.name}")
        notify("TrayDrop - errore", f"{label}: appunti non aggiornati, salvato in {saved.name}")
    else:
        ui_event("in", label, len(data))
        notify("TrayDrop", f"Ricevuto {label[10:]} — è negli appunti, incolla con {PASTE_KEY}")


# ---------------------------------------------------------------- ricevitore
def unique_path(folder: Path, name: str) -> Path:
    p = folder / name
    stem, suf, i = p.stem, p.suffix, 1
    while p.exists():
        p = folder / f"{stem} ({i}){suf}"
        i += 1
    return p


class Handler(BaseHTTPRequestHandler):
    server_version = "TrayDrop/1"

    def log_message(self, *a):
        pass

    def _reply(self, code, text=""):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _auth(self, payload):
        ts, sig = self.headers.get("X-Ts", ""), self.headers.get("X-Sig", "")
        try:
            fresh = abs(time.time() - float(ts)) < 300
        except ValueError:
            return False
        exp = sign(self.server.cfg["token"], f"{payload}|{ts}")
        return fresh and hmac.compare_digest(exp, sig)

    def do_GET(self):
        if self.path == "/ping" and self._auth("ping"):
            return self._reply(200, "pong")
        self._reply(403, "forbidden")

    def _put_clip(self):
        try:
            kind = self.headers.get("X-Kind", "")
            size = int(self.headers.get("Content-Length", "-1"))
            sha = self.headers.get("X-Sha256", "")
        except ValueError:
            return self._reply(400, "bad request")
        if kind not in ("text", "image") or not 0 < size <= CLIP_MAX \
                or not self._auth(f"clip|{kind}|{size}|{sha}"):
            return self._reply(403, "forbidden")
        tid = tr_start("in", "Appunti", size, 0.0, 1.0, "Ricezione")
        try:
            buf, left = bytearray(), size
            while left > 0:
                b = self.rfile.read(min(CHUNK, left))
                if not b:
                    raise ConnectionError("trasferimento interrotto")
                buf += b; left -= len(b)
                tr_set(tid, done=size - left, frac=(size - left) / size)
            data = bytes(buf)
            if hashlib.sha256(data).hexdigest() != sha:
                raise ValueError("checksum errato")
        except Exception as e:
            return self._reply(400, str(e))
        finally:
            tr_end(tid)
        self._reply(201, "ok")
        try:
            on_clip_received(self.server.cfg, kind, data)
        except Exception as e:
            ui_event("in", "Appunti", size, "error", str(e))

    def do_PUT(self):
        if self.path == "/clip":
            return self._put_clip()
        try:
            name = os.path.basename(unquote(self.headers.get("X-Name", ""))).strip()
            size = int(self.headers.get("Content-Length", "-1"))
            sha = self.headers.get("X-Sha256", "")
        except ValueError:
            return self._reply(400, "bad request")
        if not name or name.startswith(".") or size < 0 or not self._auth(f"{name}|{size}|{sha}"):
            return self._reply(403, "forbidden")
        inbox = Path(self.server.cfg["inbox"])
        inbox.mkdir(parents=True, exist_ok=True)
        tmp = inbox / f".{secrets.token_hex(6)}.part"
        h, left = hashlib.sha256(), size
        tid = tr_start("in", name, size, 0.0, 1.0, "Ricezione")
        try:
            with open(tmp, "wb") as f:
                while left > 0:
                    buf = self.rfile.read(min(CHUNK, left))
                    if not buf:
                        raise ConnectionError("trasferimento interrotto")
                    f.write(buf); h.update(buf); left -= len(buf)
                    tr_set(tid, done=size - left, frac=(size - left) / size if size else 1.0)
            if h.hexdigest() != sha:
                raise ValueError("checksum errato")
            dest = unique_path(inbox, safe_name(name))
            os.replace(tmp, dest)
        except Exception as e:
            tmp.unlink(missing_ok=True)
            return self._reply(400, str(e))
        finally:
            tr_end(tid)
        self._reply(201, dest.name)
        self.server.on_receive(dest)


RECV = {"srv": None, "udp": None}  # ricevitore attivo (TCP) e risponditore per la ricerca (UDP)


def _default_recv(p):
    try:
        ui_event("in", p.name, p.stat().st_size)
    except OSError:
        ui_event("in", p.name)
    notify("TrayDrop", f"Ricevuto: {p.name}")


def _bind_receiver(cfg, port, on_receive):
    srv = Server(("0.0.0.0", int(port)), Handler)  # OSError se la porta e' occupata
    srv.cfg, srv.on_receive = cfg, on_receive
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def start_server(cfg, on_receive=None):
    try:
        srv = _bind_receiver(cfg, cfg["port"], on_receive or _default_recv)
    except OSError as e:
        sys.exit(f"Impossibile ascoltare sulla porta {cfg['port']}: {e}\n"
                 "Forse TrayDrop e' gia' in esecuzione (chiudilo) o la porta e' occupata.")
    RECV["srv"] = srv
    start_discovery_responder(cfg)
    return srv


def rebind_receiver(cfg, port):
    """Sposta il ricevitore su un'altra porta senza riavviare TrayDrop (OSError se occupata)."""
    old = RECV["srv"]
    new = _bind_receiver(cfg, port, old.on_receive if old else _default_recv)
    RECV["srv"] = new
    if old is not None:
        def stop():
            old.shutdown(); old.server_close()
        threading.Thread(target=stop, daemon=True).start()
    start_discovery_responder(cfg, port)


# ------------------------------------------------- ricerca nella rete locale
# Ogni TrayDrop acceso risponde (UDP, stessa porta) a un messaggio broadcast con il
# nome del computer. Non viene mai inviato il token: serve solo a trovare l'IP.
INSTANCE_ID = secrets.token_hex(6)
DISCO_Q = b"TRAYDROP?1"


def start_discovery_responder(cfg, port=None):
    port = int(port or cfg["port"])
    old, RECV["udp"] = RECV["udp"], None
    if old is not None:
        old.close()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", port))
        s.settimeout(1.0)
    except OSError:
        return  # la ricerca e' un aiuto: senza, si inserisce l'IP a mano
    RECV["udp"] = s

    def loop():
        while RECV["udp"] is s:
            try:
                data, addr = s.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            if data.startswith(DISCO_Q):
                reply = json.dumps({"app": "traydrop", "v": 1, "id": INSTANCE_ID,
                                    "name": socket.gethostname(), "port": int(cfg["port"])}).encode()
                try:
                    s.sendto(reply, addr)
                except OSError:
                    pass
    threading.Thread(target=loop, daemon=True).start()


PEERS = {}  # ip -> {ip, name, port, seen}: altri TrayDrop visti in rete
_peers_lock = threading.Lock()
PEER_TTL = 65  # secondi senza risposta prima di toglierlo dall'elenco


def scan_network(cfg):
    """Cerca gli altri TrayDrop e aggiorna l'elenco (chi non risponde da un po' sparisce)."""
    found = discover(int(cfg["port"]), wait=1.2)
    now = time.time()
    with _peers_lock:
        for f in found:
            PEERS[f["ip"]] = dict(f, seen=now)
        for ip in [ip for ip, p in PEERS.items() if now - p["seen"] > PEER_TTL]:
            del PEERS[ip]


def peers_list(cfg):
    """Elenco per la finestra; il destinatario attuale c'e' sempre, anche se non risponde."""
    dest = (cfg.get("peer") or "").lower() if is_configured(cfg) else ""
    with _peers_lock:
        items = [dict(p) for p in PEERS.values()]
    out, dest_seen = [], False
    for p in sorted(items, key=lambda x: (x["name"].lower(), x["ip"])):
        names = {p["ip"], p["name"].lower(), p["name"].lower() + ".local"}
        is_dest = bool(dest) and dest in names
        dest_seen = dest_seen or is_dest
        out.append({"ip": p["ip"], "name": p["name"], "port": p["port"], "dest": is_dest, "missing": False})
    if dest and not dest_seen:
        out.insert(0, {"ip": cfg["peer"], "name": "", "port": int(cfg.get("peer_port", cfg["port"])),
                       "dest": True, "missing": True})
    return out


def _scan_loop(cfg):
    while True:
        try:
            scan_network(cfg)
        except Exception:
            pass
        time.sleep(20)


def discover(port=DEFAULT_PORT, wait=1.6, targets=None):
    """Cerca altri TrayDrop accesi nella LAN. Ritorna [{ip, name, port}]."""
    if targets is None:
        targets = {"255.255.255.255"}
        ip = local_ip()
        if ip.count(".") == 3:
            targets.add(ip.rsplit(".", 1)[0] + ".255")  # broadcast della sottorete /24
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(0.2)
        for _ in range(2):  # due giri: l'UDP puo' perdere pacchetti
            for t in targets:
                try:
                    s.sendto(DISCO_Q, (t, int(port)))
                except OSError:
                    pass
            end = time.time() + wait / 2
            while time.time() < end:
                try:
                    data, addr = s.recvfrom(1024)
                    j = json.loads(data)
                except socket.timeout:
                    continue
                except (OSError, ValueError):
                    continue
                if j.get("app") != "traydrop" or j.get("id") == INSTANCE_ID:
                    continue
                found[addr[0]] = {"ip": addr[0], "name": str(j.get("name", ""))[:60],
                                  "port": int(j.get("port", port))}
    finally:
        s.close()
    return sorted(found.values(), key=lambda f: f["name"].lower())


# ------------------------------------------------------------------ mittente
NOT_CONFIGURED = "destinatario non configurato: apri la finestra TrayDrop > Collegamento"


def _conn(cfg, timeout=30):
    if not cfg.get("peer"):
        raise RuntimeError(NOT_CONFIGURED)
    return http.client.HTTPConnection(cfg["peer"], int(cfg.get("peer_port", cfg["port"])), timeout=timeout)


def ping(cfg, timeout=10):
    ts = str(time.time())
    try:
        c = _conn(cfg, timeout)
        c.request("GET", "/ping", headers={"X-Ts": ts, "X-Sig": sign(cfg["token"], f"ping|{ts}")})
        r = c.getresponse()
        return r.status == 200, f"HTTP {r.status}"
    except Exception as e:
        return False, str(e)


def explain_ping(ok, info):
    """Traduce l'esito del test di connessione in un consiglio comprensibile."""
    if ok:
        return "Collegato ✓"
    i = (info or "").lower()
    if NOT_CONFIGURED.lower() in i:
        return "Non configurato: inserisci l'altro computer."
    if "403" in i:
        return "L'altro computer risponde, ma il token è diverso: usa lo stesso token su entrambi."
    if "refused" in i or "10061" in i:
        return "A quell'indirizzo non c'è TrayDrop in ascolto: è acceso sull'altro computer? La porta è la stessa?"
    if "timed out" in i or "timeout" in i or "10060" in i:
        return "L'altro computer non risponde: controlla l'IP, il firewall o Netskope."
    if "getaddrinfo" in i or "name or service" in i or "nodename" in i or "11001" in i:
        return "Indirizzo non trovato: controlla l'IP o il nome."
    if "unreachable" in i or "no route" in i or "10065" in i or "10051" in i:
        return "Rete non raggiungibile: i due computer sono sulla stessa rete?"
    return f"Non raggiungibile ({info})"


def send_file(cfg, path, progress=None):
    """progress(stage, done, total) con stage in 'zip' | 'hash' | 'send'."""
    path = Path(path)
    tmpdir = None
    if path.is_dir():  # le cartelle vengono inviate come .zip
        if progress:
            progress("zip", 0, 0)
        tmpdir = Path(tempfile.mkdtemp())
        archive = shutil.make_archive(str(tmpdir / path.name), "zip", str(path.parent), path.name)
        path = Path(archive)
    try:
        size = path.stat().st_size
        h, n = hashlib.sha256(), 0
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(CHUNK), b""):
                h.update(blk)
                n += len(blk)
                if progress:
                    progress("hash", n, size)
        sha, name = h.hexdigest(), path.name
        ts = str(time.time())
        c = _conn(cfg)
        c.putrequest("PUT", "/upload")
        c.putheader("Content-Length", str(size))
        c.putheader("X-Name", quote(name))
        c.putheader("X-Sha256", sha)
        c.putheader("X-Ts", ts)
        c.putheader("X-Sig", sign(cfg["token"], f"{name}|{size}|{sha}|{ts}"))
        c.endheaders()
        sent = 0
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(CHUNK), b""):
                c.send(blk)
                sent += len(blk)
                if progress:
                    progress("send", sent, size)
        r = c.getresponse()
        body = r.read().decode()
        if r.status != 201:
            raise RuntimeError(f"{r.status} {body}")
        return body
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def send_many(cfg, paths, quiet=False, tid=None, base=0.0, span=1.0):
    ok, errs = 0, []
    for p in paths:
        name = Path(p).name
        own = tid is None
        t = tr_start("out", name, 0, base, span, "Preparazione") if own else tid

        def prog(stage, done, total, t=t):
            r = (done / total) if total else 1.0
            if stage == "zip":
                tr_set(t, done=0, total=0, frac=base, phase="Compressione")
            elif stage == "hash":
                tr_set(t, done=done, total=total, frac=base + span * 0.12 * r, phase="Preparazione")
            else:
                tr_set(t, done=done, total=total, frac=base + span * (0.12 + 0.88 * r), phase="Invio")
        try:
            size = Path(p).stat().st_size if Path(p).is_file() else 0
            send_file(cfg, p, prog)
            ok += 1
            ui_event("out", name, size)
        except Exception as e:
            errs.append(f"{name}: {e}")
            ui_event("out", name, 0, "error", str(e))
        finally:
            if own:
                tr_end(t)
    if not quiet:
        if errs:
            notify("TrayDrop - errore", "; ".join(errs)[:200])
        elif ok:
            notify("TrayDrop", f"Inviati {ok} elemento/i")
    return ok, errs


OLD_PEER_HINT = ("token diverso, oppure sull'altro computer c'è una versione di TrayDrop "
                 "senza gli appunti: aggiornala")


def send_clip(cfg, kind, data, progress=None):
    size, sha, ts = len(data), hashlib.sha256(data).hexdigest(), str(time.time())
    c = _conn(cfg)
    try:
        c.putrequest("PUT", "/clip")
        c.putheader("Content-Length", str(size))
        c.putheader("X-Kind", kind)
        c.putheader("X-Sha256", sha)
        c.putheader("X-Ts", ts)
        c.putheader("X-Sig", sign(cfg["token"], f"clip|{kind}|{size}|{sha}|{ts}"))
        c.endheaders()
        mv = memoryview(data)
        for i in range(0, size, CHUNK):
            c.send(mv[i:i + CHUNK])
            if progress:
                progress(min(i + CHUNK, size), size)
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
    except (BrokenPipeError, ConnectionResetError):
        raise RuntimeError(f"connessione chiusa dall'altro computer ({OLD_PEER_HINT})")
    if r.status == 403:
        raise RuntimeError(f"rifiutato ({OLD_PEER_HINT})")
    if r.status != 201:
        raise RuntimeError(f"{r.status} {body}")


def send_clipboard(cfg, quiet=False):
    """Invia il contenuto degli appunti. Ritorna (ok, messaggio)."""
    def fail(msg, label="Appunti"):
        ui_event("out", label, 0, "error", msg)
        if not quiet:
            notify("TrayDrop - errore", msg[:200])
        return False, msg
    try:
        kind, val = clip_read()
    except Exception as e:
        return fail(f"impossibile leggere gli appunti: {e}")
    if kind is None:
        msg = "gli appunti sono vuoti (o il formato non è supportato)"
        if not quiet:
            notify("TrayDrop", msg[0].upper() + msg[1:])
        return False, msg
    if kind == "files":
        ok, errs = send_many(cfg, val, quiet=quiet)
        return (not errs), (f"inviati {ok} file dagli appunti" if not errs else "; ".join(errs))
    data = val.encode("utf-8") if kind == "text" else val
    label = describe_clip(kind, data)
    if len(data) > CLIP_MAX:
        return fail(f"troppo grande ({len(data) // 2**20} MB): salvalo come file e invialo", label)
    tid = tr_start("out", label, len(data), 0.0, 1.0, "Invio")
    try:
        send_clip(cfg, kind, data,
                  progress=lambda d, t: tr_set(tid, done=d, total=t, frac=d / t if t else 1.0))
    except Exception as e:
        return fail(str(e), label)
    finally:
        tr_end(tid)
    ui_event("out", label, len(data))
    if not quiet:
        notify("TrayDrop", f"Inviato: {label}")
    return True, label


# ------------------------------------------------------------ selettori / UI
FINDER_SEL = """tell application "Finder"
  set sel to selection as alias list
  set out to ""
  repeat with f in sel
    set out to out & POSIX path of f & linefeed
  end repeat
  return out
end tell"""

MAC_CHOOSE = """tell application "System Events" to activate
set fs to choose file with multiple selections allowed
set out to ""
repeat with f in fs
  set out to out & POSIX path of f & linefeed
end repeat
return out"""

MAC_CHOOSE_DIR = """tell application "System Events" to activate
set f to choose folder
return POSIX path of f"""


def osa_paths(script):
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    return [l for l in r.stdout.splitlines() if l.strip()]


def pick_cmd(folder=False):
    """Mostra il selettore di file (tkinter) e stampa i percorsi scelti. Girato come
    sotto-processo per non interferire col ciclo eventi dell'icona."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
    except Exception as e:
        sys.exit(f"Selettore file non disponibile (serve tkinter e uno schermo): {e}")
    root.withdraw()
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    res = [filedialog.askdirectory()] if folder else list(filedialog.askopenfilenames())
    for p in res:
        if p:
            print(p)


def pick_paths(folder=False):
    if IS_MAC:
        return osa_paths(MAC_CHOOSE_DIR if folder else MAC_CHOOSE)
    cmd = self_cmd("pick", *(["--dir"] if folder else []))
    kw = {"creationflags": 0x08000000} if IS_WIN else {}  # CREATE_NO_WINDOW
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode and r.stderr.strip():
        notify("TrayDrop - errore", r.stderr.strip()[-200:])
    return [l for l in r.stdout.splitlines() if l.strip()]


def _ping_notify(cfg):
    ok, info = ping(cfg)
    notify("TrayDrop", "Connessione OK" if ok else explain_ping(ok, info))


def peer_label(cfg):
    if not is_configured(cfg):
        return "Destinatario: da configurare…"
    return f"Destinatario: {cfg['peer']}:{cfg.get('peer_port', cfg['port'])}"


def open_setup_if_needed(cfg, ui_url):
    """Al primo avvio (nessuna config) apre subito la finestra di configurazione."""
    if not is_configured(cfg):
        threading.Timer(1.0, open_window, args=(ui_url + "#setup",)).start()


def run_menubar(cfg):
    """macOS: icona nella barra dei menu con rumps."""
    try:
        import rumps
    except ImportError:
        sys.exit("Manca 'rumps'. Installa con:  pip3 install rumps\n"
                 "Oppure usa la finestra:        python3 traydrop.py gui")
    try:  # nessuna icona nel Dock
        from AppKit import NSApplication, NSApplicationActivationPolicyAccessory
        NSApplication.sharedApplication().setActivationPolicy_(NSApplicationActivationPolicyAccessory)
    except Exception:
        pass
    _ui_srv, ui_url = start_ui_server(cfg)
    if _ui_srv is None:  # TrayDrop e' gia' acceso: apri la sua finestra e basta
        print("TrayDrop e' gia' in esecuzione: apro la finestra.")
        return open_window(ui_url)
    start_server(cfg)
    open_setup_if_needed(cfg, ui_url)
    print(f"TrayDrop attivo: ascolto sulla porta {cfg['port']}, {peer_label(cfg).lower()}.\n"
          "Cerca l'icona ⇄ nella barra dei menu in alto a destra.\n"
          "Non la vedi? (notch / barra piena) -> Impostazioni > Barra dei menu > consenti 'Python',\n"
          "oppure chiudi e usa la finestra:  python traydrop.py gui")

    class App(rumps.App):
        def __init__(self):
            super().__init__("TrayDrop", title="⇄", quit_button="Esci")
            self.peer_item = rumps.MenuItem(peer_label(cfg))
            self.login_item = rumps.MenuItem("Avvia all'accesso", callback=self.toggle_login)
            self.login_item.state = MAC_AGENT.exists()
            self.menu = [
                rumps.MenuItem("Apri finestra TrayDrop", callback=lambda _: open_window(ui_url)),
                rumps.MenuItem("Invia appunti (testo / immagine)", callback=self.clip),
                rumps.MenuItem("Invia selezione del Finder", callback=self.finder),
                rumps.MenuItem("Scegli file da inviare…", callback=self.choose),
                rumps.MenuItem("Scegli cartella da inviare…", callback=self.choose_dir),
                None,
                rumps.MenuItem("Apri cartella ricevuti", callback=lambda _: open_folder(cfg["inbox"])),
                rumps.MenuItem("Test connessione", callback=lambda _: _ping_notify(cfg)),
                rumps.MenuItem("Collegamento…", callback=lambda _: open_window(ui_url + "#setup")),
                self.login_item,
                self.peer_item,
                None,
            ]
            self._timer = rumps.Timer(self.refresh, 2)  # la config puo' cambiare dalla finestra
            self._timer.start()

        def refresh(self, _):
            self.peer_item.title = peer_label(cfg)

        def toggle_login(self, item):
            try:
                if MAC_AGENT.exists():
                    uninstall_login_mac()
                    notify("TrayDrop", "Non partirà più all'accesso")
                else:
                    install_login(load_now=False)
                    notify("TrayDrop", "Partirà da solo a ogni accesso")
            except OSError as e:
                notify("TrayDrop - errore", f"Avvio automatico: {e}")
            item.state = MAC_AGENT.exists()

        def _send(self, paths):
            if not paths:
                notify("TrayDrop", "Nessun file selezionato")
                return
            def job():
                self.title = "⇡"
                send_many(cfg, paths)
                self.title = "⇄"
            threading.Thread(target=job, daemon=True).start()

        def clip(self, _):
            def job():
                self.title = "⇡"
                send_clipboard(cfg)
                self.title = "⇄"
            threading.Thread(target=job, daemon=True).start()

        def finder(self, _):
            self._send(osa_paths(FINDER_SEL))

        def choose(self, _):
            self._send(pick_paths())

        def choose_dir(self, _):
            self._send(pick_paths(folder=True))

    App().run()


def run_tray(cfg):
    """Windows / Linux: icona nell'area di notifica con pystray.
    Clic sull'icona = apre la finestra TrayDrop."""
    global _tray
    import pystray
    from PIL import Image, ImageDraw
    _ui_srv, ui_url = start_ui_server(cfg)
    if _ui_srv is None:  # TrayDrop e' gia' acceso: apri la sua finestra e basta
        print("TrayDrop e' gia' in esecuzione: apro la finestra.")
        return open_window(ui_url)
    start_server(cfg)
    open_setup_if_needed(cfg, ui_url)

    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((2, 2, 62, 62), fill=(30, 110, 220, 255))
    d.polygon([(14, 24), (40, 24), (40, 16), (54, 28), (40, 40), (40, 32), (14, 32)], fill="white")
    d.polygon([(50, 42), (24, 42), (24, 34), (10, 46), (24, 58), (24, 50), (50, 50)], fill="white")

    def send_async(folder=False):
        def job():
            paths = pick_paths(folder)
            if paths:
                send_many(cfg, paths)
        threading.Thread(target=job, daemon=True).start()

    menu = pystray.Menu(
        pystray.MenuItem("Apri finestra TrayDrop", lambda: open_window(ui_url), default=True),
        pystray.MenuItem("Invia appunti (testo / immagine)",
                         lambda: threading.Thread(target=send_clipboard, args=(cfg,), daemon=True).start()),
        pystray.MenuItem("Scegli file da inviare…", lambda: send_async(False)),
        pystray.MenuItem("Scegli cartella da inviare…", lambda: send_async(True)),
        pystray.MenuItem("Apri cartella ricevuti", lambda: open_folder(cfg["inbox"])),
        pystray.MenuItem("Test connessione", lambda: threading.Thread(target=_ping_notify, args=(cfg,), daemon=True).start()),
        pystray.MenuItem("Collegamento…", lambda: open_window(ui_url + "#setup")),
        pystray.MenuItem(lambda item: peer_label(cfg), None, enabled=False),
        pystray.MenuItem("Esci", lambda icon: icon.stop()),
    )
    _tray = pystray.Icon("traydrop", img, "TrayDrop", menu)
    _tray.run()


def run_tk(cfg):
    """Finestra normale (tkinter) con pulsanti e, se disponibile, drag & drop.
    Funziona su macOS, Windows e Linux, senza icona nella barra."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        sys.exit("tkinter non disponibile. macOS/Windows: reinstalla Python da python.org; "
                 "Linux: sudo apt install python3-tk")
    dnd = False
    try:
        from tkinterdnd2 import TkinterDnD, DND_FILES
        root = TkinterDnD.Tk(); dnd = True
    except Exception:
        root = tk.Tk()
    root.title("TrayDrop")
    root.geometry("360x330")
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    status = tk.StringVar(value=f"Pronto  ->  {cfg['peer']}:{cfg['port']}")

    def set_status(s):
        root.after(0, lambda: status.set(s))

    def do_send(paths):
        paths = [p for p in paths if p]
        if not paths:
            return
        def job():
            set_status(f"Invio di {len(paths)} elemento/i…")
            ok, errs = send_many(cfg, paths)
            set_status("Inviato ✓" if not errs else "Errore: " + errs[0][:80])
        threading.Thread(target=job, daemon=True).start()

    def on_receive(p):
        notify("TrayDrop", f"Ricevuto: {p.name}")
        set_status(f"Ricevuto: {p.name}")

    start_server(cfg, on_receive=on_receive)

    zone = tk.Label(root, relief="groove", borderwidth=2, height=5,
                    text="Trascina qui i file da inviare" if dnd else
                    "Per il drag & drop:  pip3 install tkinterdnd2")
    zone.pack(fill="x", padx=12, pady=(12, 6))
    if dnd:
        zone.drop_target_register(DND_FILES)
        zone.dnd_bind("<<Drop>>", lambda e: do_send(list(root.tk.splitlist(e.data))))

    def b(text, cmd):
        tk.Button(root, text=text, command=cmd).pack(fill="x", padx=12, pady=2)
    def clip():
        def job():
            set_status("Invio appunti…")
            ok, msg = send_clipboard(cfg, quiet=True)
            set_status(("Inviato ✓ " if ok else "Errore: ") + msg[:80])
        threading.Thread(target=job, daemon=True).start()
    b("Invia appunti (testo / immagine)", clip)
    b("Invia file…", lambda: do_send(list(filedialog.askopenfilenames(parent=root))))
    b("Invia cartella…", lambda: do_send([filedialog.askdirectory(parent=root)]))
    b("Apri cartella ricevuti", lambda: open_folder(cfg["inbox"]))
    def test():
        ok, info = ping(cfg)
        set_status("Connessione OK ✓" if ok else f"Non raggiungibile ({info})")
    b("Test connessione", lambda: threading.Thread(target=test, daemon=True).start())
    tk.Label(root, textvariable=status, wraplength=330, fg="#444").pack(pady=8)
    root.mainloop()


# ------------------------------------------------------------ interfaccia web
UI_HTML = r"""<!doctype html>
<html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TrayDrop</title>
<style>
:root{--bg:#f4f5f8;--card:#fff;--fg:#14171f;--mut:#6b7280;--line:#e4e7ec;--acc:#2563eb;--ok:#16a34a;--bad:#dc2626}
@media (prefers-color-scheme:dark){:root{--bg:#0e1014;--card:#171a21;--fg:#e8eaf0;--mut:#8b93a3;--line:#262b36;--acc:#4c8dff;--ok:#2fd16b;--bad:#ff6b6b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:520px;margin:0 auto;padding:22px 16px 40px}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
h1{font-size:21px;margin:0;letter-spacing:-.01em}
h1 span{color:var(--acc)}
.pill{display:inline-flex;gap:7px;align-items:center;padding:5px 11px;border-radius:99px;background:var(--card);border:1px solid var(--line);font-size:12.5px;color:var(--mut)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--mut)}
.on .dot{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 25%,transparent)}
.off .dot{background:var(--bad)}
.drop{border:2px dashed var(--line);border-radius:20px;background:var(--card);padding:38px 16px;text-align:center;transition:.15s;cursor:pointer;user-select:none}
.drop:hover{border-color:var(--acc)}
.drop.hot{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 9%,var(--card));transform:scale(1.015)}
.drop .big{font-size:40px;line-height:1}
.drop b{display:block;margin-top:10px;font-size:16px}
.drop p{margin:4px 0 0;color:var(--mut);font-size:13.5px}
.row{display:flex;gap:8px;margin:12px 0 24px}
button{flex:1;padding:10px 12px;border-radius:12px;border:1px solid var(--line);background:var(--card);color:var(--fg);font:inherit;cursor:pointer;transition:.12s}
button:hover{border-color:var(--acc);color:var(--acc)}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);margin:0 2px 8px}
.list{background:var(--card);border:1px solid var(--line);border-radius:16px;overflow:hidden}
.it{display:flex;gap:11px;align-items:center;padding:11px 13px;border-bottom:1px solid var(--line)}
.it:last-child{border:0}
.ic{width:30px;height:30px;flex:none;border-radius:9px;display:grid;place-items:center;font-weight:700;background:color-mix(in srgb,var(--acc) 15%,transparent);color:var(--acc)}
.in .ic{background:color-mix(in srgb,var(--ok) 17%,transparent);color:var(--ok)}
.err .ic{background:color-mix(in srgb,var(--bad) 17%,transparent);color:var(--bad)}
.nm{flex:1;min-width:0}
.nm b{display:block;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nm small{color:var(--mut)}
.bar{height:4px;background:var(--line);border-radius:4px;margin-top:7px;overflow:hidden}
.bar i{display:block;height:100%;width:0;background:var(--acc);transition:width .12s}
.empty{padding:22px;text-align:center;color:var(--mut)}
.hd{display:flex;gap:8px;align-items:center}
.off-btn{flex:none;width:34px;height:34px;padding:0;border-radius:50%;color:var(--bad);font-size:16px;line-height:1}
.off-btn:hover{border-color:var(--bad);color:var(--bad);background:color-mix(in srgb,var(--bad) 10%,var(--card))}
.pc{font-variant-numeric:tabular-nums;color:var(--mut);font-size:13px;width:40px;text-align:right;flex:none}
.bar.ind i{width:35%!important;animation:ind 1s ease-in-out infinite alternate}
@keyframes ind{from{margin-left:0}to{margin-left:65%}}
.kvr{display:flex;align-items:center;gap:10px;padding:11px 13px;border-bottom:1px solid var(--line)}
.kvr:last-child{border:0}
.kvr span{color:var(--mut);width:112px;flex:none;font-size:13.5px}
.kvr b{flex:1;min-width:0;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.kvr b.brk{white-space:normal;word-break:break-all}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.mini{flex:none;font-size:13px;color:var(--mut)}
.mini a{color:var(--acc);cursor:pointer}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;place-items:center;padding:20px;z-index:9}
#modal.show{display:grid}
#modal .box{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;max-width:360px;width:100%}
#modal h3{margin:0 0 6px;font-size:17px}
#modal p{margin:0 0 16px;color:var(--mut)}
#modal .row{margin:0}
button.danger{background:var(--bad);border-color:var(--bad);color:#fff}
button.danger:hover{color:#fff;opacity:.9}
.dead{padding:70px 10px;text-align:center;color:var(--mut)}
.dead .big{font-size:46px;color:var(--bad)}
#toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%) translateY(30px);background:var(--fg);color:var(--bg);padding:9px 16px;border-radius:99px;font-size:13.5px;opacity:0;transition:.2s;pointer-events:none;max-width:90vw}
#toast.show{opacity:1;transform:translateX(-50%)}
button.pri{background:var(--acc);border-color:var(--acc);color:#fff}
button.pri:hover{color:#fff;opacity:.92}
.pv{font-size:13.5px;white-space:pre-wrap;word-break:break-word;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.cl{align-items:flex-start}
.cl .mini{padding-top:2px}
.h2r{display:flex;align-items:baseline;justify-content:space-between;margin:24px 2px 8px}
.h2r h2{margin:0}
.lnk{color:var(--acc);cursor:pointer;font-size:13px}
.lnk:hover{text-decoration:underline}
#setup{position:fixed;inset:0;background:rgba(0,0,0,.45);display:none;place-items:center;padding:16px;z-index:8;overflow:auto}
#setup.show{display:grid}
.sbox{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;max-width:440px;width:100%}
.sbox h3{margin:0 0 6px;font-size:18px}
.hint{margin:0 0 14px;color:var(--mut);font-size:13.5px}
.fld{margin:0 0 14px}
.fld>span{display:block;font-size:12.5px;color:var(--mut);margin:0 0 5px;font-weight:600}
.fld>span small{font-weight:400}
.me2{font-size:13.5px}
input{width:100%;padding:9px 11px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--fg);font:inherit;font-size:14px}
input:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 20%,transparent)}
input.bad{border-color:var(--bad)}
.inrow{display:flex;gap:8px}
.inrow button{flex:none;padding:9px 14px}
.found{display:flex;flex-direction:column;gap:6px;margin-top:8px}
.found:empty{display:none}
.found button{text-align:left;display:flex;justify-content:space-between;gap:10px;padding:9px 11px}
.found button small{color:var(--mut)}
.found .none{color:var(--mut);font-size:13px}
.seg{display:flex;border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:8px}
.seg label{flex:1;cursor:pointer}
.seg input{display:none}
.seg i{display:block;text-align:center;font-style:normal;font-size:13px;padding:8px 4px;border-right:1px solid var(--line)}
.seg label:last-child i{border-right:0}
.seg input:checked+i{background:color-mix(in srgb,var(--acc) 14%,var(--card));color:var(--acc);font-weight:600}
.tkbox{border:1px dashed var(--line);border-radius:10px;padding:10px 11px;display:grid;grid-template-columns:1fr auto;gap:4px 10px;align-items:center}
.tkbox small{grid-column:1/-1;color:var(--mut);font-size:12.5px}
details{margin:2px 0 14px}
summary{cursor:pointer;color:var(--mut);font-size:13px;margin-bottom:10px}
.smsg{border-radius:10px;padding:10px 12px;margin:0 0 14px;font-size:13.5px}
.smsg.ok{background:color-mix(in srgb,var(--ok) 13%,var(--card));color:var(--ok)}
.smsg.err{background:color-mix(in srgb,var(--bad) 12%,var(--card));color:var(--bad)}
.smsg.wait{background:var(--bg);color:var(--mut)}
.pill{cursor:pointer}
.sbox .row{margin:0}
.badge{font-size:12px;padding:3px 9px;border-radius:99px;background:color-mix(in srgb,var(--ok) 15%,transparent);color:var(--ok);font-weight:600}
.badge.warn{background:color-mix(in srgb,var(--bad) 13%,transparent);color:var(--bad)}
.net-ic{font-size:15px}
#net .mini{flex:none}
</style></head>
<body><div class="wrap">
<header><h1>Tray<span>Drop</span></h1>
<div class="hd"><div id="peer" class="pill"><i class="dot"></i><span id="peerTxt">…</span></div>
<button id="bOff" class="off-btn" title="Spegni TrayDrop">⏻</button></div></header>

<div id="drop" class="drop"><div class="big">⇅</div>
<b>Trascina qui i file</b><p>oppure clicca per sceglierli</p></div>
<input id="file" type="file" multiple hidden>

<div class="row"><button id="bClip" class="pri" title="Invia il testo o l'immagine che hai copiato">Invia appunti</button><button id="bDir">Scegli cartella…</button><button id="bOpen">Apri ricevuti</button></div>

<h2>Attività</h2>
<div id="list" class="list"><div class="empty">Ancora nulla</div></div>

<div id="clipsBox" style="display:none"><h2 style="margin-top:24px">Testi ricevuti</h2>
<div id="clips" class="list"></div></div>

<div class="h2r"><h2>Computer nella rete</h2><a id="bScanNet" class="lnk">Aggiorna</a></div>
<div id="net" class="list"><div class="empty">Cerco…</div></div>

<div class="h2r"><h2>Collegamento</h2><a id="bEdit" class="lnk">Modifica</a></div>
<div class="list">
<div class="kvr"><span>Questo computer</span><b id="me" class="mono">…</b></div>
<div class="kvr"><span>Destinatario</span><b id="to" class="mono">…</b></div>
<div class="kvr"><span>Token</span><b id="tok" class="mono brk">••••••••••</b><div class="mini" id="tokMini"><a id="tokShow">Mostra con impronta</a> · <a id="tokCopy">Copia</a></div></div>
<div class="kvr"><span>Ricevuti in</span><b id="inboxp" class="mono"></b></div>
</div>
</div><div id="toast"></div>
<div id="setup"><div class="box sbox">
<h3 id="sTitle">Collega i tuoi computer</h3>
<p id="sIntro" class="hint"></p>
<div class="fld"><span>Questo computer</span><div class="mono me2" id="sMe">…</div></div>
<div class="fld"><span>Altro computer</span>
  <div class="inrow"><input id="fPeer" class="mono" placeholder="es. 192.168.1.156" autocomplete="off" spellcheck="false"><button id="bScan" type="button">Cerca</button></div>
  <div id="found" class="found"></div></div>
<div class="fld"><span>Token condiviso <small>· lo stesso su entrambi i computer</small></span>
  <div class="seg" id="tmode">
    <label id="tmKeep"><input type="radio" name="tm" value="keep"><i>Tieni l'attuale</i></label>
    <label><input type="radio" name="tm" value="new"><i>Genera nuovo</i></label>
    <label><input type="radio" name="tm" value="paste"><i>Incolla</i></label></div>
  <div id="tkNew" class="tkbox" hidden><b class="mono brk" id="tkVal"></b><a id="tkCopy" class="lnk">Copia</a>
    <small>Copialo e incollalo nell'altro computer (TrayDrop › Collegamento › Incolla).</small></div>
  <input id="fTok" class="mono" placeholder="Incolla qui il token dell'altro computer" autocomplete="off" spellcheck="false" hidden></div>
<details id="adv"><summary>Avanzate</summary>
  <div class="fld"><span>Porta <small>· la stessa su entrambi</small></span><input id="fPort" class="mono" type="number" min="1024" max="65535"></div>
  <div class="fld"><span>Cartella ricevuti</span><div class="inrow"><input id="fInbox" class="mono" spellcheck="false"><button id="bInbox" type="button">Scegli…</button></div></div>
</details>
<div id="sMsg" class="smsg" hidden></div>
<div class="row"><button id="sCancel" type="button">Annulla</button><button id="sSave" type="button" class="pri">Salva e prova</button></div>
</div></div>
<div id="modal"><div class="box"><h3>Spegnere TrayDrop?</h3><p id="mTxt"></p>
<div class="row"><button id="mNo">Annulla</button><button id="mYes" class="danger">Spegni</button></div></div></div>
<script>
const K=new URLSearchParams(location.search).get('k')||'';
const $=s=>document.querySelector(s);
const q=p=>p+'?k='+encodeURIComponent(K);
let last={events:[],active:[],peer:'',online:null},dead=false,tok='',tokV=false;
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function fmt(n){if(!n)return'';const u=['B','KB','MB','GB'];let i=0;while(n>=1024&&i<3){n/=1024;i++}return n.toFixed(i?1:0)+' '+u[i]}
function ago(t){const s=Math.max(0,Date.now()/1000-t);if(s<10)return'adesso';if(s<60)return Math.floor(s)+' s fa';if(s<3600)return Math.floor(s/60)+' min fa';if(s<86400)return Math.floor(s/3600)+' h fa';return new Date(t*1000).toLocaleDateString()}
function toast(m){const t=$('#toast');t.textContent=m;t.className='show';clearTimeout(toast.h);toast.h=setTimeout(()=>t.className='',2600)}
function render(){
  const s=last;
  if(!s.configured){$('#peer').className='pill off';$('#peerTxt').textContent='Da configurare';$('#peer').title='Clicca per collegare l’altro computer'}
  else{$('#peer').className='pill '+(s.online===null?'':(s.online?'on':'off'));
    $('#peerTxt').textContent=s.online===null?'Verifica…':(s.online?'Collegato a '+s.peer:'Non raggiungibile · '+s.peer);
    $('#peer').title=s.online?'':(s.hint||'')}
  $('#me').textContent=(s.host?s.host+' · ':'')+(s.ip||'?')+' · porta '+(s.port||'');
  $('#to').textContent=s.configured?s.peer:'— non configurato —';
  $('#tokMini').style.display=s.can_reveal?'':'none';
  renderNet(s);
  if(!s.configured&&!setupShown&&!dead)openSetup(true);
  $('#inboxp').textContent=s.inbox||'';
  let h='';
  for(const a of s.active||[]){
    const pct=Math.round((a.frac||0)*100), ind=(a.total===0&&a.phase!=='Preparazione');
    const det=[a.phase,(a.total&&a.done)?fmt(a.done)+' / '+fmt(a.total):'',a.speed>0?fmt(a.speed)+'/s':''].filter(Boolean).join(' · ');
    h+=`<div class="it ${a.dir==='in'?'in':''}"><div class="ic">${a.dir==='in'?'↓':'↑'}</div><div class="nm"><b>${esc(a.name)}</b><small>${esc(det)}</small><div class="bar ${ind?'ind':''}"><i style="width:${pct}%"></i></div></div><div class="pc">${ind?'…':pct+'%'}</div></div>`;
  }
  for(const e of s.events){
    const cls=e.status==='ok'?e.kind:'err', ic=e.status!=='ok'?'!':(e.kind==='in'?'↓':'↑');
    const sub=e.status!=='ok'?esc(e.err||'errore'):(e.kind==='in'?'Ricevuto':'Inviato')+(e.size?' · '+fmt(e.size):'')+' · '+ago(e.t);
    h+=`<div class="it ${cls}"><div class="ic">${ic}</div><div class="nm"><b>${esc(e.name)}</b><small>${sub}</small></div></div>`;
  }
  $('#list').innerHTML=h||'<div class="empty">Ancora nulla</div>';
  const cl=s.clips||[];
  $('#clipsBox').style.display=cl.length?'':'none';
  const ck=cl.map(c=>c.id+':'+c.t).join(',');
  if(ck!==render.ck){render.ck=ck;
    $('#clips').innerHTML=cl.map(c=>`<div class="kvr cl"><div class="nm"><div class="pv">${esc(c.preview)}</div><small style="color:var(--mut)">${c.n} caratteri · ${ago(c.t)}</small></div><div class="mini"><a data-c="${c.id}">Copia</a></div></div>`).join('')}
}
$('#clips').addEventListener('click',async e=>{const id=e.target.dataset&&e.target.dataset.c;if(!id)return;
  const r=await fetch(q('/api/clip_copy')+'&i='+id,{method:'POST'});toast(r.ok?'Copiato negli appunti':'Errore nella copia')});
$('#bClip').onclick=async()=>{const b=$('#bClip');b.disabled=true;
  try{const r=await fetch(q('/api/send_clip'),{method:'POST'});const j=await r.json();toast(j.ok?'Inviato: '+j.msg.replace(/^Appunti · /,''):'Errore: '+j.msg)}
  catch(e){toast('Errore di rete')}finally{b.disabled=false;load()}};
async function load(){if(dead)return;try{const r=await fetch(q('/api/state'));last=await r.json();render()}catch(e){}}
function sendFile(f){return new Promise(res=>{
  const x=new XMLHttpRequest();x.open('POST',q('/api/send'));
  x.setRequestHeader('X-Name',encodeURIComponent(f.name));
  x.onloadend=()=>{if(x.status!==200)toast('Errore: '+f.name);load();res()};
  x.send(f);load()})}
async function sendAll(files){for(const f of files)await sendFile(f)}
const drop=$('#drop');
drop.onclick=()=>$('#file').click();
$('#file').onchange=e=>{sendAll([...e.target.files]);e.target.value=''};
['dragenter','dragover'].forEach(t=>window.addEventListener(t,e=>{e.preventDefault();drop.classList.add('hot')}));
['dragleave','drop'].forEach(t=>window.addEventListener(t,e=>{e.preventDefault();if(t==='drop'||e.target===document.documentElement)drop.classList.remove('hot')}));
window.addEventListener('drop',e=>{
  const files=[];let dirs=0;
  for(const it of e.dataTransfer.items||[]){const en=it.webkitGetAsEntry&&it.webkitGetAsEntry();if(en&&en.isDirectory){dirs++;continue}const f=it.getAsFile();if(f)files.push(f)}
  if(dirs)toast('Per le cartelle usa “Scegli cartella…”');
  if(files.length)sendAll(files)
});
$('#bDir').onclick=async()=>{toast('Scegli la cartella…');await fetch(q('/api/pick_dir'),{method:'POST'});load()};
$('#bOpen').onclick=()=>fetch(q('/api/open_inbox'));
(function loop(){load().then(()=>{if(!dead)setTimeout(loop,(last.active&&last.active.length)?300:1500)})})();
let tokTimer=null,tokBusy=false;
function hideTok(){clearInterval(tokTimer);tokTimer=null;tok='';tokV=false;$('#tok').textContent='••••••••••';$('#tokShow').textContent='Mostra con impronta'}
$('#tokShow').onclick=async()=>{
  if(tokV){hideTok();return}
  if(tokBusy)return;tokBusy=true;toast('Appoggia il dito sul sensore Touch ID…');
  try{
    const r=await fetch(q('/api/reveal_token'),{method:'POST'});const j=await r.json();
    if(!r.ok){toast(j.error||'Autenticazione non riuscita');return}
    tok=j.token;tokV=true;$('#tok').textContent=tok;
    let left=j.seconds||20;const upd=()=>{$('#tokShow').textContent='Nascondi ('+left+')'};upd();
    tokTimer=setInterval(()=>{left--;if(left<=0)hideTok();else upd()},1000);
  }catch(e){toast('Errore di rete')}finally{tokBusy=false}
};
$('#tokCopy').onclick=async()=>{
  if(!tokV||!tok){toast('Prima mostra il token con l’impronta');return}
  try{await navigator.clipboard.writeText(tok)}catch(e){const i=document.createElement('textarea');i.value=tok;document.body.appendChild(i);i.select();document.execCommand('copy');i.remove()}
  toast('Token copiato')};
document.addEventListener('visibilitychange',()=>{if(document.hidden)hideTok()});
$('#bOff').onclick=()=>{const n=(last.active||[]).length;$('#mTxt').textContent=n?'Ci sono trasferimenti in corso: verranno interrotti.':'Non riceverai file finché non lo riavvii.';$('#modal').className='show'};
$('#mNo').onclick=()=>$('#modal').className='';
$('#mYes').onclick=async()=>{$('#modal').className='';dead=true;try{await fetch(q('/api/quit'),{method:'POST'})}catch(e){}
  document.querySelector('.wrap').innerHTML='<div class="dead"><div class="big">⏻</div><h2 style="font-size:18px;color:var(--fg);text-transform:none;letter-spacing:0;margin:10px 0">TrayDrop è spento</h2><p>Per riaccenderlo lancia <b>python traydrop.py gui</b></p></div>'};

/* ---------- computer nella rete ---------- */
function renderNet(s){
  const ps=s.peers||[],net=(s.ip||'').split('.').slice(0,3).join('.');
  let h='';
  for(const p of ps){
    const title=p.name||p.ip, sub=[p.name?p.ip:'',p.port!==s.port?'porta '+p.port:'',p.missing?'non trovato in questa rete':''].filter(Boolean).join(' · ');
    const right=p.dest?(p.missing?'<span class="badge warn">Destinatario</span>':'<span class="badge">Destinatario</span>')
      :`<a class="lnk" data-ip="${esc(p.ip)}" data-port="${p.port}">Collega</a>`;
    h+=`<div class="it ${p.missing?'err':'in'}"><div class="ic net-ic">${p.missing?'!':esc(title.charAt(0).toUpperCase())}</div><div class="nm"><b>${esc(title)}</b><small>${esc(sub||'TrayDrop acceso')}</small></div><div class="mini">${right}</div></div>`;
  }
  if(!ps.length)h=`<div class="empty">Nessun altro TrayDrop acceso nella rete ${esc(net)}.x</div>`;
  else if(ps.length===1&&ps[0].missing)h+=`<div class="empty" style="padding:12px">Nessun altro TrayDrop acceso nella rete ${esc(net)}.x</div>`;
  if(h!==renderNet.h){renderNet.h=h;$('#net').innerHTML=h}
}
$('#bScanNet').onclick=async()=>{const b=$('#bScanNet');b.textContent='Cerco…';
  try{const j=await (await post('/api/scan')).json();last.peers=j.peers;renderNet(last)}catch(e){toast('Ricerca non riuscita')}
  finally{b.textContent='Aggiorna'}};
$('#net').addEventListener('click',async e=>{const a=e.target.closest('a[data-ip]');if(!a)return;
  await openSetup(false);$('#fPeer').value=a.dataset.ip;$('#found').innerHTML='';
  if(a.dataset.port&&a.dataset.port!==$('#fPort').value){$('#fPort').value=a.dataset.port;$('#adv').open=true}
  sMsg('wait','Controlla il token e premi “Salva e prova”.')});

/* ---------- configurazione del collegamento ---------- */
let setupShown=false,firstRun=false,cfgNow={},newTok='';
const post=(p,body)=>fetch(q(p),{method:'POST',headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined});
function sMsg(cls,txt){const m=$('#sMsg');m.className='smsg '+cls;m.textContent=txt;m.hidden=!txt}
function tmode(){const r=document.querySelector('input[name=tm]:checked');return r?r.value:''}
async function setTMode(v){
  const r=document.querySelector('input[name=tm][value='+v+']');if(r)r.checked=true;
  $('#tkNew').hidden=v!=='new';$('#fTok').hidden=v!=='paste';
  if(v==='new'&&!newTok){const j=await (await post('/api/gen_token')).json();newTok=j.token;$('#tkVal').textContent=newTok}
  if(v==='paste')$('#fTok').focus()}
document.querySelectorAll('input[name=tm]').forEach(r=>r.onchange=()=>setTMode(r.value));
async function openSetup(first){
  setupShown=true;firstRun=!!first;newTok='';$('#tkVal').textContent='';$('#fTok').value='';$('#found').innerHTML='';sMsg('','');
  cfgNow=await (await fetch(q('/api/config'))).json();
  $('#sMe').textContent=cfgNow.host+' · '+cfgNow.ip;
  $('#fPeer').value=cfgNow.peer||'';$('#fPort').value=cfgNow.port;$('#fInbox').value=cfgNow.inbox;
  ['#fPeer','#fPort','#fTok','#fInbox'].forEach(s=>$(s).classList.remove('bad'));
  const conf=cfgNow.configured;
  $('#sTitle').textContent=conf?'Collegamento':'Collega i tuoi computer';
  $('#sIntro').textContent=conf?'Modifica l’altro computer o il token. I cambiamenti valgono subito.'
    :'Apri TrayDrop anche sull’altro computer. Su UNO dei due scegli “Genera nuovo” e copia il token; sull’altro scegli “Incolla”.';
  $('#tmKeep').style.display=conf?'':'none';
  $('#sCancel').style.display=conf?'':'none';$('#sCancel').textContent='Annulla';
  $('#adv').open=false;
  await setTMode(conf?'keep':'new');
  $('#setup').className='show';
  if(!conf)scan(true);else $('#fPeer').focus()}
function closeSetup(){$('#setup').className='';load()}
$('#bEdit').onclick=()=>openSetup(false);
$('#peer').onclick=()=>openSetup(false);
$('#sCancel').onclick=closeSetup;
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&$('#setup').className&&cfgNow.configured)closeSetup()});
async function scan(quiet){
  const f=$('#found'),b=$('#bScan');b.disabled=true;b.textContent='Cerco…';
  if(!quiet)f.innerHTML='';
  try{const j=await (await post('/api/discover?port='+encodeURIComponent($('#fPort').value||8787))).json();
    if(j.found.length){f.innerHTML=j.found.map(x=>`<button type="button" data-ip="${esc(x.ip)}" data-port="${x.port}"><span>${esc(x.name||'TrayDrop')}</span><small class="mono">${esc(x.ip)}</small></button>`).join('');
      if(j.found.length===1&&!$('#fPeer').value){$('#fPeer').value=j.found[0].ip}}
    else if(!quiet)f.innerHTML='<div class="none">Nessun TrayDrop trovato. Controlla che sia aperto sull’altro computer, oppure scrivi l’IP (sull’altro computer è indicato in “Questo computer”).</div>'}
  catch(e){if(!quiet)f.innerHTML='<div class="none">Ricerca non riuscita: scrivi l’IP a mano.</div>'}
  finally{b.disabled=false;b.textContent='Cerca'}}
$('#bScan').onclick=()=>scan(false);
$('#found').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;$('#fPeer').value=b.dataset.ip;
  if(b.dataset.port&&b.dataset.port!==$('#fPort').value){$('#fPort').value=b.dataset.port;$('#adv').open=true}
  $('#fPeer').classList.remove('bad')});
$('#bInbox').onclick=async()=>{const j=await (await post('/api/pick_inbox')).json();if(j.path)$('#fInbox').value=j.path};
async function copyText(t){try{await navigator.clipboard.writeText(t)}catch(e){const i=document.createElement('textarea');i.value=t;document.body.appendChild(i);i.select();document.execCommand('copy');i.remove()}}
$('#tkCopy').onclick=async()=>{await copyText(newTok);toast('Token copiato: incollalo nell’altro computer')};
$('#sSave').onclick=async()=>{
  ['#fPeer','#fPort','#fTok','#fInbox'].forEach(s=>$(s).classList.remove('bad'));
  const m=tmode(),body={peer:$('#fPeer').value.trim(),port:+$('#fPort').value,inbox:$('#fInbox').value.trim()};
  if(m==='new')body.token=newTok;
  if(m==='paste'){body.token=$('#fTok').value.trim();if(!body.token){$('#fTok').classList.add('bad');sMsg('err','Incolla il token copiato dall’altro computer.');return}}
  if(!body.peer){$('#fPeer').classList.add('bad');sMsg('err','Scrivi l’IP dell’altro computer o usa “Cerca”.');return}
  const b=$('#sSave');b.disabled=true;sMsg('wait','Salvo e provo il collegamento…');
  try{const r=await post('/api/config',body),j=await r.json();
    if(!r.ok){sMsg('err',j.error||'Errore');const fm={peer:'#fPeer',port:'#fPort',token:'#fTok',inbox:'#fInbox'}[j.field];
      if(fm){$(fm).classList.add('bad');if(fm==='#fPort'||fm==='#fInbox')$('#adv').open=true}return}
    load();
    if(j.ping_ok){sMsg('ok','Salvato. '+j.ping_msg);setTimeout(()=>{if($('#setup').className)closeSetup()},1300)}
    else{sMsg('err','Salvato, ma il test non è riuscito: '+j.ping_msg+(m==='new'?' Hai incollato il nuovo token anche sull’altro computer?':''));
      cfgNow.configured=true;$('#sCancel').style.display='';$('#sCancel').textContent='Chiudi';$('#tmKeep').style.display=''}}
  catch(e){sMsg('err','Errore di rete: TrayDrop è ancora acceso?')}
  finally{b.disabled=false}};
if(location.hash==='#setup')openSetup(false);
</script></body></html>"""


def _ping_loop(cfg):
    while True:
        if is_configured(cfg):
            ok, info = ping(cfg, timeout=4)
        else:
            ok, info = False, NOT_CONFIGURED
        UI_STATE["online"], UI_STATE["info"] = ok, info
        time.sleep(5)


def apply_config(cfg, new, ui_port=None):
    """Valida e applica la config inviata dalla finestra. Ritorna (ok, risposta)."""
    peer = str(new.get("peer", "")).strip()
    if not peer or len(peer) > 253 or any(c.isspace() or c in "/\\:@" for c in peer):
        return False, {"error": "Indirizzo dell'altro computer non valido (es. 192.168.1.156)", "field": "peer"}
    try:
        port = int(new.get("port") or cfg["port"])
        if not 1024 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        return False, {"error": "Porta non valida: usa un numero tra 1024 e 65535", "field": "port"}
    token = new.get("token")
    if token is not None:
        token = str(token).strip()
        if len(token) < 16 or any(c.isspace() for c in token):
            return False, {"error": "Token non valido: incolla quello completo dell'altro computer", "field": "token"}
    inbox = os.path.expanduser(str(new.get("inbox") or cfg["inbox"]).strip())
    try:
        Path(inbox).mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return False, {"error": f"Cartella ricevuti non utilizzabile: {e}", "field": "inbox"}
    if port != int(cfg["port"]):
        try:
            rebind_receiver(cfg, port)
        except OSError as e:
            return False, {"error": f"La porta {port} è già occupata: {e.strerror or e}", "field": "port"}
        if ui_port:
            cfg["ui_port"] = ui_port  # la finestra resta allo stesso indirizzo anche al prossimo avvio
    cfg.update(peer=peer, port=port, inbox=inbox)
    cfg.pop("peer_port", None)
    if token:
        cfg["token"] = token
    try:
        save_cfg(cfg)
    except OSError as e:
        return False, {"error": f"Impossibile salvare la configurazione: {e}"}
    ok, info = ping(cfg, timeout=4)
    UI_STATE["online"], UI_STATE["info"] = ok, info
    return True, {"ok": True, "ping_ok": ok, "ping_msg": explain_ping(ok, info)}


def ui_key():
    f = HOME / "ui.key"
    HOME.mkdir(parents=True, exist_ok=True)
    if f.exists() and f.read_text().strip():
        return f.read_text().strip()
    k = secrets.token_urlsafe(16)
    f.write_text(k)
    try:
        f.chmod(0o600)
    except OSError:
        pass
    return k


REVEAL_LOCK = threading.Lock()
REVEAL_SECONDS = 20


def biometric_auth(reason="Mostra il token di TrayDrop"):
    """Ritorna (True, '') SOLO se l'utente si autentica con l'impronta digitale.
    Nessun ripiego su password/PIN. In caso di dubbio o errore: (False, motivo)."""
    try:
        if IS_MAC:
            try:
                import LocalAuthentication as LA
            except ImportError:
                return False, ("Manca il modulo per Touch ID. Installa: "
                               "pip install pyobjc-framework-LocalAuthentication")
            policy = getattr(LA, "LAPolicyDeviceOwnerAuthenticationWithBiometrics", 1)  # solo biometria
            ctx = LA.LAContext.alloc().init()
            can, err = ctx.canEvaluatePolicy_error_(policy, None)
            if not can:
                return False, f"Touch ID non disponibile: {err.localizedDescription() if err else 'sconosciuto'}"
            done, res = threading.Event(), {}

            def reply(success, error):
                res["ok"] = bool(success)
                res["err"] = str(error.localizedDescription()) if error else ""
                done.set()
            ctx.evaluatePolicy_localizedReason_reply_(policy, reason, reply)
            if not done.wait(60):
                return False, "Tempo scaduto"
            return (True, "") if res.get("ok") else (False, res.get("err") or "Impronta non riconosciuta")
        if sys.platform.startswith("linux") and shutil.which("fprintd-verify"):
            r = subprocess.run(["fprintd-verify"], capture_output=True, text=True, timeout=45)
            return ("verify-match" in r.stdout), "Impronta non riconosciuta"
    except Exception as e:
        return False, f"Autenticazione non riuscita: {e}"
    return False, "Impronta digitale non supportata su questo sistema"


class UIHandler(BaseHTTPRequestHandler):
    server_version = "TrayDropUI/1"

    def log_message(self, *a):
        pass

    def _allowed(self):
        host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]")
        key = parse_qs(urlparse(self.path).query).get("k", [""])[0]
        return host in ("127.0.0.1", "localhost") and hmac.compare_digest(key, self.server.key)

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._allowed():
            return self._send(403, "forbidden", "text/plain")
        path = urlparse(self.path).path
        cfg = self.server.cfg
        if path == "/":
            return self._send(200, UI_HTML, "text/html")
        if path == "/api/state":
            with UI_STATE["lock"]:
                ev = list(UI_STATE["events"])
                clips = [{"id": c["id"], "t": c["t"], "n": len(c["text"]), "preview": c["text"][:300]}
                         for c in UI_STATE["clips"]]
            conf = is_configured(cfg)
            return self._send(200, json.dumps({"peer": f"{cfg['peer']}:{cfg.get('peer_port', cfg['port'])}" if conf else "",
                                               "configured": conf,
                                               "online": UI_STATE["online"], "info": UI_STATE["info"],
                                               "hint": explain_ping(bool(UI_STATE["online"]), UI_STATE["info"]),
                                               "inbox": cfg["inbox"], "events": ev, "clips": clips,
                                               "active": tr_list(), "ip": local_ip(),
                                               "host": socket.gethostname(), "port": cfg["port"],
                                               "can_reveal": IS_MAC, "peers": peers_list(cfg)}))
        if path == "/api/config":
            return self._send(200, json.dumps({"configured": is_configured(cfg), "peer": cfg.get("peer", ""),
                                               "port": int(cfg["port"]), "inbox": cfg["inbox"],
                                               "ip": local_ip(), "host": socket.gethostname(),
                                               "can_reveal": IS_MAC}))
        if path == "/api/open_inbox":
            open_folder(cfg["inbox"])
            return self._send(200, "{}")
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        if not self._allowed():
            return self._send(403, "forbidden", "text/plain")
        path = urlparse(self.path).path
        cfg = self.server.cfg
        if path == "/api/config":
            try:
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}") if 0 < n < 65536 else {}
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._send(400, json.dumps({"error": "richiesta non valida"}))
            ok, res = apply_config(cfg, body, ui_port=self.server.server_address[1])
            return self._send(200 if ok else 400, json.dumps(res))
        if path == "/api/scan":
            scan_network(cfg)
            return self._send(200, json.dumps({"peers": peers_list(cfg)}))
        if path == "/api/gen_token":
            return self._send(200, json.dumps({"token": secrets.token_urlsafe(24)}))
        if path == "/api/discover":
            try:
                port = int(parse_qs(urlparse(self.path).query).get("port", [DEFAULT_PORT])[0])
            except ValueError:
                port = DEFAULT_PORT
            return self._send(200, json.dumps({"found": discover(port), "me": local_ip()}))
        if path == "/api/pick_inbox":
            paths = pick_paths(folder=True)
            return self._send(200, json.dumps({"path": paths[0].rstrip("/") if paths else ""}))
        if path == "/api/reveal_token":
            if not REVEAL_LOCK.acquire(blocking=False):
                return self._send(409, json.dumps({"error": "Autenticazione già in corso"}))
            try:
                ok, msg = biometric_auth()
            finally:
                REVEAL_LOCK.release()
            if not ok:
                return self._send(403, json.dumps({"error": msg or "Autenticazione negata"}))
            return self._send(200, json.dumps({"token": cfg["token"], "seconds": REVEAL_SECONDS}))
        if path == "/api/quit":
            self._send(200, "{}")
            threading.Timer(0.4, lambda: os._exit(0)).start()
            return
        if path == "/api/send_clip":
            ok, msg = send_clipboard(cfg, quiet=True)
            return self._send(200, json.dumps({"ok": ok, "msg": msg}))
        if path == "/api/clip_copy":
            try:
                cid = int(parse_qs(urlparse(self.path).query).get("i", ["0"])[0])
            except ValueError:
                cid = 0
            with UI_STATE["lock"]:
                txt = next((c["text"] for c in UI_STATE["clips"] if c["id"] == cid), None)
            if txt is None:
                return self._send(404, json.dumps({"error": "non trovato"}))
            try:
                clip_write_text(txt)
            except Exception as e:
                return self._send(500, json.dumps({"error": str(e)}))
            return self._send(200, "{}")
        if path == "/api/pick_dir":
            paths = pick_paths(folder=True)
            ok, errs = send_many(cfg, paths, quiet=True) if paths else (0, [])
            return self._send(200, json.dumps({"ok": ok, "errors": errs}))
        if path == "/api/send":
            try:
                name = os.path.basename(unquote(self.headers.get("X-Name", ""))).strip()
                size = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                return self._send(400, "bad request", "text/plain")
            if not name or size < 0:
                return self._send(400, "bad request", "text/plain")
            tmpdir = Path(tempfile.mkdtemp())
            tid = tr_start("out", name, size, 0.0, 0.5, "Caricamento")
            try:
                tmp = tmpdir / name
                left = size
                with open(tmp, "wb") as f:
                    while left > 0:
                        buf = self.rfile.read(min(CHUNK, left))
                        if not buf:
                            raise ConnectionError("upload interrotto")
                        f.write(buf)
                        left -= len(buf)
                        tr_set(tid, done=size - left, frac=0.5 * (size - left) / size if size else 0.5)
                ok, errs = send_many(cfg, [tmp], quiet=True, tid=tid, base=0.5, span=0.5)
            except Exception as e:
                ui_event("out", name, 0, "error", str(e))
                return self._send(500, json.dumps({"error": str(e)}))
            finally:
                tr_end(tid)
                shutil.rmtree(tmpdir, ignore_errors=True)
            return self._send(200 if not errs else 502, json.dumps({"ok": ok, "errors": errs}))
        self._send(404, "not found", "text/plain")


def start_ui_server(cfg):
    """Avvia il server locale dell'interfaccia (solo 127.0.0.1). Ritorna (server|None, url)."""
    port = int(cfg.get("ui_port", int(cfg["port"]) + 1))
    key = ui_key()
    url = f"http://127.0.0.1:{port}/?k={key}"
    try:
        srv = Server(("127.0.0.1", port), UIHandler)
    except OSError:
        return None, url  # gia' in esecuzione
    srv.cfg, srv.key = cfg, key
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=_ping_loop, args=(cfg,), daemon=True).start()
    threading.Thread(target=_scan_loop, args=(cfg,), daemon=True).start()
    return srv, url


def open_window(url, block=False):
    """Apre l'interfaccia: finestra nativa (pywebview) se c'e', altrimenti finestra
    'app' di Chrome/Edge/Brave, altrimenti il browser predefinito."""
    if block:
        try:
            import webview
            webview.create_window("TrayDrop", url, width=480, height=720, min_size=(380, 520))
            webview.start()
            return
        except ImportError:
            pass
        except Exception as e:
            print("pywebview non utilizzabile:", e)
    launched = False
    try:
        if IS_MAC:
            for app in ("Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium"):
                if Path(f"/Applications/{app}.app").exists():
                    subprocess.Popen(["open", "-na", app, "--args", f"--app={url}", "--window-size=480,740"])
                    launched = True
                    break
        elif IS_WIN:
            bases = [os.environ.get(v, "") for v in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")]
            for rel in ("Google/Chrome/Application/chrome.exe", "Microsoft/Edge/Application/msedge.exe"):
                for b in bases:
                    exe = Path(b) / rel
                    if b and exe.exists():
                        subprocess.Popen([str(exe), f"--app={url}", "--window-size=480,740"])
                        launched = True
                        break
                if launched:
                    break
        else:
            for exe in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"):
                if shutil.which(exe):
                    subprocess.Popen([exe, f"--app={url}", "--window-size=480,740"])
                    launched = True
                    break
    except Exception:
        launched = False
    if not launched:
        webbrowser.open(url)
    if block:
        print(f"TrayDrop pronto: {url}\nCtrl+C per uscire.")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


def run_web(cfg):
    """Interfaccia web locale (consigliata): finestra bella, drag & drop, storico."""
    srv, url = start_ui_server(cfg)
    if srv is None:  # un'altra istanza e' gia' attiva: riapri solo la finestra
        print("TrayDrop e' gia' in esecuzione: riapro la finestra.")
        return open_window(url)
    start_server(cfg)
    print(f"In ascolto sulla porta {cfg['port']} -> inbox: {cfg['inbox']}")
    open_window(url, block=True)


def run_ui(cfg):
    if IS_MAC:
        run_menubar(cfg)
    else:
        run_tray(cfg)


MAC_AGENT = Path.home() / "Library/LaunchAgents/com.marco.traydrop.plist"


def install_login(load_now=True):
    if IS_MAC:
        from xml.sax.saxutils import escape
        plist = MAC_AGENT
        plist.parent.mkdir(parents=True, exist_ok=True)
        app_exe = APP_PATH / "Contents/MacOS/TrayDrop"
        cmd = [str(app_exe)] if app_exe.exists() else self_cmd("menubar")
        args = "".join(f"<string>{escape(c)}</string>" for c in cmd)
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.marco.traydrop</string>
<key>ProgramArguments</key><array>{args}</array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
</dict></plist>""", encoding="utf-8")
        if load_now:  # dal menu dell'app (gia' accesa) basta che valga dal prossimo accesso
            subprocess.run(["launchctl", "unload", str(plist)], capture_output=True)
            subprocess.run(["launchctl", "load", str(plist)])
        print("Avvio automatico installato:", plist)
    elif IS_WIN:
        startup = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup"
        f = startup / "TrayDrop.cmd"
        f.write_text(win_cmd_file(["tray"], background=True), encoding="utf-8", newline="")
        print("Avvio automatico installato:", f)
    else:
        f = Path.home() / ".config/autostart/traydrop.desktop"
        f.parent.mkdir(parents=True, exist_ok=True)
        exe = " ".join(f'"{c}"' for c in self_cmd("tray"))
        f.write_text(f"[Desktop Entry]\nType=Application\nName=TrayDrop\n"
                     f"Exec={exe}\nX-GNOME-Autostart-enabled=true\n")
        print("Avvio automatico installato:", f)


def uninstall_login_mac():
    """Toglie l'avvio automatico senza chiudere TrayDrop (vale dal prossimo accesso)."""
    MAC_AGENT.unlink(missing_ok=True)


APP_PATH = Path.home() / "Applications" / "TrayDrop.app"
LSREGISTER = ("/System/Library/Frameworks/CoreServices.framework/Frameworks/"
              "LaunchServices.framework/Support/lsregister")


def _make_icns(dst):
    """Crea l'icona .icns dal PNG incorporato, con gli strumenti di macOS (sips, iconutil)."""
    import base64
    tmp = Path(tempfile.mkdtemp())
    try:
        src = tmp / "icon.png"
        src.write_bytes(base64.b64decode(ICON_PNG_B64))
        iconset = tmp / "TrayDrop.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                px = size * scale
                if px > 512:
                    continue
                name = f"icon_{size}x{size}{'@2x' if scale == 2 else ''}.png"
                if _run(["sips", "-z", str(px), str(px), str(src), "--out", str(iconset / name)],
                        capture_output=True).returncode:
                    return False
        return _run(["iconutil", "-c", "icns", str(iconset), "-o", str(dst)],
                    capture_output=True).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def install_app():
    """macOS: crea ~/Applications/TrayDrop.app (doppio clic, Launchpad, Spotlight, Dock).
    L'app contiene una COPIA di traydrop.py: dopo un aggiornamento rilancia install-app."""
    if not IS_MAC:
        print("install-app serve solo su macOS. Su Windows: install-login / install-shortcut,\n"
              "oppure crea TrayDrop.exe con PyInstaller (vedi LEGGIMI.md).")
        return
    import plistlib
    contents = APP_PATH / "Contents"
    if APP_PATH.exists():
        shutil.rmtree(APP_PATH)
    (contents / "MacOS").mkdir(parents=True)
    (contents / "Resources").mkdir()
    if FROZEN:
        cmd = [sys.executable, "menubar"]
    else:
        script = contents / "Resources" / "traydrop.py"
        shutil.copy2(Path(__file__).resolve(), script)
        cmd = [sys.executable, str(script), "menubar"]
    launcher = contents / "MacOS" / "TrayDrop"
    launcher.write_text("#!/bin/bash\n# Creato da: traydrop.py install-app\n"
                        "exec " + " ".join(shlex.quote(c) for c in cmd) + "\n")
    launcher.chmod(0o755)
    icon = _make_icns(contents / "Resources" / "TrayDrop.icns")
    info = {"CFBundleName": "TrayDrop", "CFBundleDisplayName": "TrayDrop",
            "CFBundleIdentifier": "com.marco.traydrop.app", "CFBundleExecutable": "TrayDrop",
            "CFBundlePackageType": "APPL", "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1",
            "LSMinimumSystemVersion": "10.13", "LSUIElement": True, "NSHighResolutionCapable": True}
    if icon:
        info["CFBundleIconFile"] = "TrayDrop"
    with open(contents / "Info.plist", "wb") as f:
        plistlib.dump(info, f)
    if Path(LSREGISTER).exists():  # la fa comparire subito in Launchpad / Spotlight
        _run([LSREGISTER, "-f", str(APP_PATH)], capture_output=True)
    print(f"Creata {APP_PATH}" + ("" if icon else "  (icona non creata: manca sips/iconutil)"))
    print("Aprila da Launchpad, Spotlight (⌘ Spazio > TrayDrop) o Finder > Applicazioni.\n"
          "Puoi trascinarla nel Dock. Dopo aver aggiornato traydrop.py rilancia: python traydrop.py install-app")
    if MAC_AGENT.exists():
        print("Aggiorno l'avvio automatico perche' usi l'app (TrayDrop si riavvia)...")
        install_login()


def install_shortcut():
    """Voce 'Invia a > TrayDrop' (Windows) / script Nautilus (Linux)."""
    if IS_WIN:
        f = Path(os.environ["APPDATA"]) / "Microsoft/Windows/SendTo/TrayDrop.cmd"
        f.write_text(win_cmd_file(["send"]), encoding="utf-8", newline="")
        print("Aggiunto: tasto destro su file > Invia a > TrayDrop\n ", f)
    elif IS_MAC:
        print("Su macOS usa 'Invia selezione del Finder' dal menu ⇄.")
    else:
        d = Path.home() / ".local/share/nautilus/scripts"
        d.mkdir(parents=True, exist_ok=True)
        f = d / "Invia con TrayDrop"
        exe = " ".join(f'"{c}"' for c in self_cmd("send"))
        f.write_text(f'#!/bin/bash\nIFS=$\'\\n\'\nexec {exe} $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\n')
        f.chmod(0o755)
        print("Aggiunto: tasto destro > Script > Invia con TrayDrop (Nautilus)\n ", f)


# Icona dell'app (PNG 512x512, generata per TrayDrop)
ICON_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AABV7UlEQVR42u3dd7xcVbk+8GetXaaflpwkhBQSQgtIkarAFeyVIhcV"
    "bBSvFxHsP+wI4kXFei0gAiKKYkOxXmxIERQEREpACCEhhZwkp02f2Xuv9ftjz5xMJtNOcsrMnufrZz7n5CQEmbLfZ717FYCIiIiI"
    "iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    "iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    "OpjgU0B8DxF1LM2ngHjxJr4PiIgBgnjhJ77WRMRgQCwKfF35fiCi3SvuDAUsFNThr6Pg+4GIAWAKCj0DAQMAtfHrJnbxnxd87xAF"
    "cmS/K8WfgYABgDrgtRIt/ExM4u/m+4MouMFA1/i1qPPzqQ4axABAu/kaNSvmzYq/2M1/FxF1Xjeg2ShfT7L4T9UtBWIAoEkW4lYK"
    "fqv/TP0/N3/+zv+flOL7h2i2SblzgR2SGniulSLe6u/tTkBgEGAAoN14PSZbwCfxs/kC84E5fXtL7blCqx6hPEcYVk5hZARaKzE6"
    "Oq6AYZcvD1HnxIL+/uWmEH448BJ7SmlYWsikFoaph0fGNOSwxtCQrijOzYq8blL0GQYYAGiaRvtiksW/8qv//eCgHOhdJrXq8X89"
    "ugajo2scAApAoeqDKQEYpd+LHPD6L8xBPu8P/D2X7xuidqv4hul/dsNhbPzT9alkctV46XOsAbhV1wobgIGBFWZ/X69QXlwYVk6N"
    "jKcVtq5SNUKBbiEYNPsZgwADAO3iaL+62Dcr+AKDK0V/ImIoLy5kcr0eHV1TLBX68gfcXHrk2+fGlz8/1rf0pfsahohY0cHnS8sW"
    "gDxYGrJPa8MFVK80zOVaa833DFFb00IKoTxvSAqxSSnP1ICjirkHpCndYmp4lTTN4eH1Dz6bG3p89KnffmJbRfgvBYOBUP/yZQLo"
    "h5na5G3dOqyBId0kEOxuGGAQYABg4W9xZF/n+/liYGCp4SUicnzdIwoYKQLIl37f3uc1n120xyGn7xeKzXmeMLBMGJEDALG3lKJH"
    "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"
    "1GEFn8WeePEmvv5ExGLPAkDE9woRizoRERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERER"
    "EREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREdH0+v/6Iqjr8vBIggAAAABJRU5E"
    "rkJggg=="
)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    i = sub.add_parser("init"); i.add_argument("--peer", required=True)
    i.add_argument("--token"); i.add_argument("--port", type=int, default=DEFAULT_PORT)
    i.add_argument("--inbox")
    s = sub.add_parser("send"); s.add_argument("files", nargs="+")
    p = sub.add_parser("pick"); p.add_argument("--dir", action="store_true")
    for c in ("menubar", "tray", "gui", "tk", "serve", "ping", "clip", "install-login", "install-shortcut",
              "install-app"):
        sub.add_parser(c)
    a = ap.parse_args()
    if a.cmd is None:
        if not FROZEN:
            ap.print_help()
            sys.exit(2)
        a.cmd = "menubar" if IS_MAC else "tray"  # doppio clic sull'eseguibile = icona

    if a.cmd == "init":
        HOME.mkdir(parents=True, exist_ok=True)
        token = a.token or secrets.token_urlsafe(24)
        cfg = {"peer": a.peer, "port": a.port, "token": token}
        if a.inbox:
            cfg["inbox"] = a.inbox
        CONFIG.write_text(json.dumps(cfg, indent=2)); CONFIG.chmod(0o600)
        print(f"Config salvata in {CONFIG}\nToken (usa lo STESSO sull'altro Mac):\n  {token}")
        return
    if a.cmd == "install-login":
        return install_login()
    if a.cmd == "install-shortcut":
        return install_shortcut()
    if a.cmd == "install-app":
        return install_app()
    if a.cmd == "pick":
        return pick_cmd(a.dir)
    cfg = load_cfg(allow_missing=a.cmd in ("menubar", "tray", "gui"))
    if a.cmd in ("menubar", "tray"):
        run_ui(cfg)
    elif a.cmd == "gui":
        run_web(cfg)
    elif a.cmd == "tk":
        run_tk(cfg)
    elif a.cmd == "serve":
        start_server(cfg); print(f"In ascolto sulla porta {cfg['port']}, inbox: {cfg['inbox']}")
        threading.Event().wait()
    elif a.cmd == "ping":
        ok, info = ping(cfg); print("OK" if ok else f"KO ({info})"); sys.exit(0 if ok else 1)
    elif a.cmd == "clip":
        ok, msg = send_clipboard(cfg)
        print(("Inviato: " if ok else "Errore: ") + msg)
        sys.exit(0 if ok else 1)
    elif a.cmd == "send":
        ok, errs = send_many(cfg, a.files); sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
