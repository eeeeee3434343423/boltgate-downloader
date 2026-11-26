# BoltGate — Safe-First Multi-Segment Accelerated Downloader

BoltGate is a local-first accelerated download manager featuring a pre-download **Safety Gate**, **multi-segment parallel HTTP/HTTPS downloads with dynamic work-stealing**, **digital book anti-corruption verification** (`.epub`, `.pdf`, `.mobi`, `.azw3`, `.djvu`, `.cbz`, `.cbr`, `.fb2`), and **polite mirror queueing** for bulk link pastes.

- **Live Web UI (GitHub Pages):** https://eeeeee3434343423.github.io/boltgate-downloader/
- **Repository:** https://github.com/eeeeee3434343423/boltgate-downloader

---

## Why a Local Engine + Hosted UI?

Web browsers block multi-connection `Range` acceleration, TLS/header inspection, and direct large-file assembly across external hosts due to **CORS** and sandbox rules. BoltGate solves this cleanly:

1. Start the lightweight local Node.js engine on your PC (zero runtime server dependencies).
2. Open either the **Live GitHub Pages UI** above or `http://127.0.0.1:3847` directly — the UI connects automatically to your local engine so files download fast and save straight to disk.

---

## Quick Start

### Windows (1-Click)
Double-click `Launch-BoltGate.bat`, or run in PowerShell:

```powershell
git clone https://github.com/eeeeee3434343423/boltgate-downloader.git
cd boltgate-downloader
npm install
npm run build
npm start
```

### Bulk Links & Digital Books (Anti-Corruption & Multi-Mirror Speed)
- **Bulk Paste** extracts multiple links from text or lists and inspects every link before downloading.
- **Same File — Combine Mirrors for Speed** lets you paste 2+ mirror URLs for the same file in **Bulk Paste**, verifies identical exact byte sizes + `Range` support, stripes parallel byte ranges across all verified mirrors simultaneously (`128 KiB` minimum segment threshold for ebooks), steals slow tails onto the fastest active mirror, and fails over automatically on `429`/`503`.
- **Digital Books (Anti-Corrupt) preset** limits concurrent connections per mirror host (avoiding `429` rate limits and HTML countdown traps) and automatically honors `Retry-After` pauses.
- **Automatic File Verification** checks SHA-256 checksums plus binary headers/trailers (`%PDF-` / `%%EOF`, EPUB/CBZ ZIP `PK` + EOCD, `BOOKMOBI`, `AT&TFORM`, `Rar!`, `FictionBook`, and HTML-trap detection) right when each file finishes.
- **Live Speed Diagnostics** flag when a remote server omits byte ranges or hard-caps transfer speed server-side.
- *Note:* BoltGate accelerates **direct file URLs**; it cannot bypass manual CAPTCHAs, waiting rooms, or server-side bandwidth caps.

---

## Project Context & Architecture

- [`PROJECT_STATUS.md`](./PROJECT_STATUS.md) — Current status snapshot, update timeline, and next enhancements.
- [`AGENTS.md`](./AGENTS.md) — Workspace rules, architecture map, safety boundaries, and verification commands (auto-loaded in Antigravity chats).
- `server/inspector.ts` — Zero-payload Safety Gate (redirect chains, TLS verification, MIME vs. extension checks, double-extension detection, `HEAD` + `GET Range: bytes=0-0` fallback).
- `server/engine.ts` — Multi-segment / multi-mirror `FileHandle` positional writer (`pwrite`), dynamic tail work-stealing, pause/resume persistence, `429`/`503` `Retry-After` & mirror failover, and streaming SHA-256.
- `server/verifier.ts` — Constant-memory binary header/EOF/HTML-trap integrity checker for ebooks and archives.
- `server/manager.ts` & `server/app.ts` — Queue scheduler (global + per-host limits), multi-mirror group verification (`POST /api/inspect-mirrors`), SSE telemetry, Trust List rules, and allowlisted CORS/PNA REST server.
- `src/` — Accessible WCAG 2.2 AA React 19 + TypeScript UI.
