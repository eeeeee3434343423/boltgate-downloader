# BoltGate — Safe-First Multi-Segment & Multi-Source Accelerated Downloader

BoltGate is a local-first accelerated download manager featuring a pre-download **Safety Gate**, a **4-tier fast-source resolver** for digital books (Tier 1 Fast API -> Tier 2 External Mirrors -> Tier 3 Concurrent IPFS Race -> Tier 4 `aria2c` P2P), **adaptive multi-mirror swarming with live 5-second speed-floor switching**, **digital book anti-corruption & MD5 verification**, and a **100% static GitHub Pages frontend**.

- **Live Web UI (GitHub Pages):** https://eeeeee3434343423.github.io/boltgate-downloader/
- **Repository:** https://github.com/eeeeee3434343423/boltgate-downloader

---

## Why a Local Companion Bridge (`/companion`) + Hosted Static UI?

Web browsers block multi-connection `Range` striping, cross-origin mirror racing, P2P torrents, TLS/header inspection, and direct large-file disk assembly due to **CORS** and sandbox rules. BoltGate keeps the frontend 100% static (`dist/`) on GitHub Pages while running all unrestricted networking, source resolution, candidate racing, and disk I/O inside the local **`/companion`** bridge:

1. Start the local Companion Bridge on your PC (see [`companion/README.md`](./companion/README.md) for Windows & macOS commands).
2. Open either the **Live GitHub Pages UI** above or `http://127.0.0.1:3847` directly — the UI connects automatically to your local Companion Bridge and writes verified files directly to disk.

---

## Quick Start

### Windows (1-Click or PowerShell)
Double-click `Launch-BoltGate.bat`, or run:

```powershell
git clone https://github.com/eeeeee3434343423/boltgate-downloader.git
cd boltgate-downloader
npm install
npm run build
npm run companion
```

### macOS (Terminal)
```bash
git clone https://github.com/eeeeee3434343423/boltgate-downloader.git
cd boltgate-downloader
npm install
npm run build
chmod +x companion/start.sh
./companion/start.sh
```

See [`companion/README.md`](./companion/README.md) for optional `aria2c` installation (`winget install aria2.aria2` / `brew install aria2`) and local IPFS gateway setup.

---

## Key Capabilities

- **Smart Input Parser:** Paste direct file URLs, Anna's Archive book URLs (`/md5/<hash>`), raw 32-character MD5 hashes, multi-line mirror URLs, `magnet:?` links, `.torrent` URLs, or `ipfs://` URIs.
- **4-Tier Fast-Source Resolver & Concurrent Benchmarking (`/companion`):**
  - **Tier 1 (Fast API):** Uses your optional local Anna's Archive Fast Download API key (`/dyn/api/fast_download.json`) first when configured.
  - **Tier 2 (External Mirrors & Metadata):** Resolves configurable external mirror URL templates (`{md5}`) and extracts mirrors/CIDs from clean metadata pages (strictly respecting anti-bot/CAPTCHA gates without bypassing them), deprioritizing Slow Partner links.
  - **Tier 3 (IPFS Gateway Race):** Races local `http://127.0.0.1:8080/ipfs/<cid>` and public IPFS gateways concurrently (`HEAD` + 64 KiB `Range` throughput benchmark).
  - **Tier 4 (`aria2c` P2P & 16-Connection Mode):** Detects host `aria2c` safely (`shell: false`) for magnets, selective single-file `.torrent` downloads, or 16-connection HTTP transfers; runs cleanly in Pure Node.js when `aria2c` is absent.
- **Adaptive Swarming & Rolling Speed-Floor Switching:**
  - Single fast (`> 2 MB/s`) ranged mirrors saturate with 8–16 parallel byte-range workers writing buffered `256 KiB` chunks into pre-allocated `.part` files.
  - Equal-size mirrors swarm simultaneously across hosts; a rolling 5-second speed-floor monitor (`350 KB/s` default) evicts capped/rate-limited mirrors mid-flight, reassigns unfinished byte ranges to faster/standby mirrors, and logs every switch live in the UI.
- **Crash-Safe Resume & Pre-Rename MD5 Verification:** Persists chunk progress atomically in `.part.meta`, computes MD5 before atomic rename when an expected MD5 is known (displaying **`MD5 Verified`** on completion), and validates binary ebook/archive headers & trailers (`server/verifier.ts`).

---

## Project Architecture

- [`companion/README.md`](./companion/README.md) — Windows/macOS Companion setup & `aria2c` instructions.
- `companion/` — Smart input parser, 4-tier source resolver (`resolver.ts`), 5-way concurrent candidate benchmarker (`benchmarker.ts`), bencode `.torrent` parser (`torrentParser.ts`), `.part.meta` manager (`partMeta.ts`), `aria2c` bridge (`aria2.ts`), and entrypoint (`index.ts`).
- `shared/` — Pure TypeScript shared types (`types.ts`) and browser-safe smart input parser (`inputParser.ts`).
- `server/` — Safety Gate inspector (`inspector.ts`), multi-mirror adaptive engine (`engine.ts`), binary integrity checker (`verifier.ts`), queue/trust/settings manager (`manager.ts`), atomic persistence (`store.ts`), and CORS/PNA REST+SSE router (`app.ts`).
- `src/` — 100% static WCAG 2.2 AA React 19 + TypeScript UI deployed to GitHub Pages (`dist/`).
