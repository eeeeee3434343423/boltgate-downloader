# BoltGate — Project Status & Handoff

**Last Updated:** 2026-11-25  
**Workspace:** `C:\Users\jmrol\.gemini\antigravity\scratch\boltgate-downloader`  
**GitHub Repo:** https://github.com/eeeeee3434343423/boltgate-downloader  
**Live GitHub Pages UI:** https://eeeeee3434343423.github.io/boltgate-downloader/  
**Local Companion Engine Address:** `http://127.0.0.1:3847` (`Launch-BoltGate.bat` / `npm run companion` / `./companion/start.sh`)

---

## What's Going On Right Now

BoltGate Phase 4 is built and verified: a **100% static GitHub Pages frontend (`dist/`)** paired with the **`/companion` local bridge** for smart multi-source resolution, concurrent candidate benchmarking, adaptive multi-mirror swarming, live 5-second speed-floor eviction, `.part.meta` crash resume, pre-rename MD5 verification, and optional `aria2c` P2P delegation.

---

## Timeline of Completed Updates

### Phase 1 — Core Downloader & Safety Gate
- Zero-payload Safety Gate (`server/inspector.ts`), multi-segment `FileHandle` positional writer + work-stealing (`server/engine.ts`), pause/resume persistence (`server/store.ts`), bandwidth limiter (`server/throttle.ts`), and WCAG 2.2 AA React UI (`src/`).

### Phase 2 — Digital Books Anti-Corruption & GitHub Pages Deployment
- Constant-memory binary integrity checker (`server/verifier.ts`) for `.pdf`, `.epub`, `.mobi`, `.azw3`, `.djvu`, `.cbz`, `.cbr`, `.fb2`, `.zip`, `.rar`, `.7z`, `.gz` + HTML-trap detection.
- **Digital Books (Anti-Corrupt)** preset (`1` concurrent/host, `3` global, `4` streams/file) + `429`/`503` `Retry-After` backoff + allowlisted CORS/PNA & GitHub Pages CI/CD.

### Phase 3 — Multi-Mirror Striped Speed & Range Probe Fix
- `HEAD 200` omitting `Accept-Ranges` falls back to `GET Range: bytes=0-0`; `128 KiB` minimum ebook segmenting; `POST /api/inspect-mirrors`.

### Phase 4 — Smart Input Parser, 4-Tier Book Resolver, Adaptive Swarming, Speed-Floor Switcher & `/companion` Bridge
- **Smart Input Parser (`shared/inputParser.ts`, `PasteBar.tsx`):** Auto-growing multi-line bar accepts direct URLs, Anna's Archive `/md5/<hash>` links, raw 32-char MD5 hashes, multi-line mirrors, `magnet:?`, `.torrent` URLs, and `ipfs://` URIs.
- **4-Tier Resolver & Candidate Benchmarking (`companion/resolver.ts`, `companion/benchmarker.ts`):**
  - Tier 1 Fast Download API (`/dyn/api/fast_download.json`, key stored locally and redacted from all logs).
  - Tier 2 configurable custom mirror templates (`{md5}`) + clean metadata/CID extraction (stops immediately on anti-bot/CAPTCHA challenges without bypassing).
  - Tier 3 concurrent IPFS gateway race (local `127.0.0.1:8080` + public gateways) via `HEAD` + `Range: bytes=0-65535` throughput & HTML-trap probing.
  - Tier 4 safe `aria2c` integration (`companion/aria2.ts`, `companion/torrentParser.ts`) with selective single-file torrent download (`--select-file`) and one-click OS install hint when `aria2c` is absent.
- **Live 5s Speed-Floor Eviction, `.part.meta` & Pre-Rename MD5 (`server/engine.ts`, `companion/partMeta.ts`):** Evicts throttled mirrors under the configurable floor (`350 KB/s` default), hot-swaps unfinished byte ranges onto faster/standby mirrors, buffers `256 KiB` writes into pre-allocated `.part` files, recovers crashed transfers from `.part.meta`, and verifies MD5 before atomic rename.
- **Transparent Live Telemetry (`DownloadsView.tsx`, `CompletedView.tsx`, `InspectDrawer.tsx`, `SettingsView.tsx`):** Shows active source badges, combined MB/s, active worker count, expandable per-source speed table + live routing log, and **`MD5 Verified`** badges.
