# BoltGate Companion Bridge (`/companion`)

The BoltGate web interface (`https://eeeeee3434343423.github.io/boltgate-downloader/`) is **100% static** and runs cleanly on GitHub Pages. Because web browsers block raw multi-connection HTTP range striping, cross-origin candidate racing, P2P torrents, and direct disk I/O, the local **Companion Bridge** handles all unrestricted networking, source resolution, adaptive multi-mirror swarming, `.part.meta` resume, MD5/SHA-256 verification, and disk writes on your machine (`http://127.0.0.1:3847`).

---

## Requirements

- **Node.js 20+** (Node 22 recommended)
- **Optional:** [`aria2c`](https://aria2.github.io/) for magnet/`.torrent` P2P downloads and selective single-file torrent extraction. If `aria2c` is not installed, BoltGate runs all HTTP/HTTPS, Fast API, multi-mirror swarming, and IPFS racing cleanly in **Pure Node.js**.

---

## Start Commands

### Windows (PowerShell or 1-Click)

Double-click **`Launch-BoltGate.bat`** in the repository root, or run in PowerShell:

```powershell
git clone https://github.com/eeeeee3434343423/boltgate-downloader.git
cd boltgate-downloader
npm install
npm run build
npm run companion
```

Optional `aria2c` install on Windows:

```powershell
winget install aria2.aria2
# Alternative: scoop install aria2  OR  choco install aria2
```

Restart the Companion (or click **Re-check aria2c** in Settings) after installing `aria2c`.

---

### macOS (Terminal)

```bash
git clone https://github.com/eeeeee3434343423/boltgate-downloader.git
cd boltgate-downloader
npm install
npm run build
chmod +x companion/start.sh
./companion/start.sh
```

Or run directly with npm:

```bash
npm run companion
```

Optional `aria2c` install on macOS:

```bash
brew install aria2
```

---

## Optional Configuration (Inside BoltGate Settings)

1. **Anna's Archive Fast Download API Key:** Stored locally in `data/state.json`, never logged, and sent **only** to your configured Anna's Archive `/dyn/api/fast_download.json` endpoint as Tier 1 priority before mirrors/IPFS.
2. **Custom External Mirror URL Templates:** Add mirror URLs (one per line) using `{md5}` as a placeholder (for example: `https://mirror.example.org/get/{md5}`) so mirrors never go stale if a domain changes.
3. **IPFS Gateways:** Includes local Kubo gateway `http://127.0.0.1:8080/ipfs/{cid}` (checked first with a fast 1.5s timeout) plus public gateways (`dweb.link`, `ipfs.io`, `cloudflare-ipfs.com`, `w3s.link`, `gateway.pinata.cloud`).
4. **Minimum Speed Floor (Default `350 KB/s`):** The Companion evaluates each active mirror over a rolling 5-second window; if a mirror falls below the floor (or hits HTTP `429`/`503`) while faster or untried candidates exist, it aborts that worker, reassigns its unfinished byte range, and logs the switch in the UI.
