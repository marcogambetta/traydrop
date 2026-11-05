# TrayDrop

Send files, folders and clipboard contents (text and images) between your own computers on the
same local network, with one click from the ⇄ icon in the menu bar (Mac) or system tray (Windows, Linux).
Available in English, Italiano, Français and Español.

## Download

- **Stable version**: [Releases](../../releases) → `TrayDrop-macOS-AppleSilicon.dmg`,
  `TrayDrop-macOS-Intel.dmg`, `TrayDrop-Windows.exe`, `TrayDrop-Linux-x86_64.tar.gz`
  or `TrayDrop-Linux-arm64.tar.gz`.
- **Latest build**: [Actions](../../actions/workflows/build.yml) → most recent run with a green
  check mark → **Artifacts** at the bottom.

**Mac**: open the DMG and drag TrayDrop to Applications. The app is not signed by Apple: the first
time, open it, then go to System Settings → Privacy & Security → “Open Anyway”
(or run `xattr -dr com.apple.quarantine /Applications/TrayDrop.app`).
**Windows**: run `TrayDrop-Windows.exe`; if SmartScreen warns you: “More info” → “Run anyway”.
**Linux**: extract it and add it to the applications menu:

    mkdir -p ~/.local/bin && tar -xzf TrayDrop-Linux-x86_64.tar.gz -C ~/.local/bin
    ~/.local/bin/TrayDrop install-app      # adds TrayDrop to the applications menu
    ~/.local/bin/TrayDrop install-login    # optional: start at login

For the clipboard install `wl-clipboard` (Wayland) or `xclip` (X11). Desktops without a system
tray (e.g. stock GNOME) show the TrayDrop window instead of the ⇄ icon.

On first launch the **Connect your computers** window opens: “Search” finds the other computer;
on one of the two choose “Generate new” token, on the other “Paste”.

## Features

- Drag & drop files and folders (folders travel as .zip), progress bar with speed
- Send the clipboard: text and images land directly in the other computer's clipboard
- Finds the other TrayDrop computers on the network automatically
- Updates itself: checks the latest GitHub Release and installs it with one click
- Requests signed with a shared token (HMAC-SHA256) and SHA-256 checksums.
  Content is **not encrypted** on the local network: use it on networks you trust.

## Release a new version

    git tag v1.1 && git push origin v1.1

GitHub Actions stamps the version, builds all packages, tests them and publishes the Release;
installed copies then offer the update automatically.

Full documentation (Italian): [LEGGIMI.md](LEGGIMI.md). License: see [LICENSE](LICENSE) when present.
