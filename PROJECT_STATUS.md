# BoltGate — Project Status & Handoff

**Last Updated:** 2026-11-25  
**Workspace:** `C:\Users\jmrol\.gemini\antigravity\scratch\boltgate-downloader`  
**GitHub Repo:** https://github.com/eeeeee3434343423/boltgate-downloader  
**Live GitHub Pages UI:** https://eeeeee3434343423.github.io/boltgate-downloader/  
**Local Engine Address:** `http://127.0.0.1:3847` (launch via `Launch-BoltGate.bat` or `npm start`)

---

## What's Going On Right Now

BoltGate is built, tested (**13/13 automated tests passing**), pushed to GitHub (`main`), and deployed live on GitHub Pages.

### How the Hybrid Architecture Works
- **GitHub Pages (`https://eeeeee3434343423.github.io/boltgate-downloader/`)** hosts the static React UI (`dist/`).
- **Your PC (`Launch-BoltGate.bat` / `http://127.0.0.1:3847`)** runs the local Node.js acceleration & safety engine so downloads bypass browser CORS restrictions, inspect TLS/headers/redirects before downloading, split into parallel streams, verify book formats, and write directly to disk.
- **Important if you still had the earlier session open:** Stop any older running `Launch-BoltGate.bat` / `node` process on port `3847` and launch it again so your local backend picks up the Phase 3 updates (`POST /api/inspect-mirrors`, 128 KiB ebook segmenting, and Range-probe fix).

---

## Timeline of Completed Updates

### Phase 1 — Core Downloader & Safety Gate
- Built zero-payload Safety Gate (`server/inspector.ts`), multi-segment `FileHandle` positional writer + work-stealing (`server/engine.ts`), pause/resume persistence (`server/store.ts`), bandwidth limiter (`server/throttle.ts`), queue/trust/SHA-256 manager (`server/manager.ts`), and WCAG 2.2 AA React UI (`src/`).
- Verified across desktop (`1280x800`), compact laptop (`1280x680`), and mobile (`390x844`) viewports; replaced compact native Settings checkboxes with `48x28 px` accessible switches.

### Phase 2 — Digital Books Anti-Corruption & GitHub Pages Deployment
- Added constant-memory file integrity checker (`server/verifier.ts`) validating PDF, EPUB, MOBI, AZW/AZW3, KFX, DJVU, CBZ, CBR, FB2, ZIP, RAR, 7z, and GZ structures and flagging HTML countdown/rate-limit pages saved under book extensions (`html_trap`).
- Added **Digital Books (Anti-Corrupt)** preset (`1` concurrent download per mirror host, `3` global across hosts, `4` streams/file) and HTTP `429`/`503` `Retry-After` handling.
- Added strict origin-allowlisted CORS + Private Network Access + CSRF protection (`server/app.ts`), offline **Connect Your Local BoltGate Engine** screen (`src/App.tsx`), and `.github/workflows/deploy-pages.yml`.

### Phase 3 — Multi-Mirror Striped Speed & Diagnostics (Latest, commit `a2d743a`)
- **Range Probe Fix:** `HEAD 200` without `Accept-Ranges` now automatically probes `GET Range: bytes=0-0` while preserving `HEAD` headers (`Content-Disposition`, `ETag`, `Content-Type`).
- **128 KiB Ebook Segmenting:** Lowered `DEFAULT_MIN_SEGMENT_BYTES` from `1 MiB` -> `128 KiB` so 1–10 MB books split across up to 16 parallel streams when servers support ranges.
- **Multi-Mirror Striped Downloads (`POST /api/inspect-mirrors`):** In **Bulk Paste**, pasting 2+ mirrors for the same book lets you choose **`Same File — Combine Mirrors for Speed`**. BoltGate verifies matching exact byte sizes, stripes parallel byte ranges across all verified mirrors, steals slow tails onto the fastest active mirror, and immediately fails over if one mirror returns `429`/`503`.
- **Speed Diagnostics:** Added live `< 512 KB/s` diagnostic notices in `DownloadsView.tsx` distinguishing single-stream servers from server-side mirror caps (such as Anna's Archive free Slow Partner Servers, which enforce server-side bandwidth caps that cannot be bypassed by any client).

---

## Verification Snapshot

- `npm run typecheck` — 0 errors
- `npm run build` — `dist/` + `dist-server/` clean (`index.js` `309.41 kB` / `89.96 kB` gzip)
- `npm test` — **13/13 tests passing** (`inspector.test.mjs`, `engine.test.mjs`, `verifier.test.mjs`, `api.test.mjs`)
- GitHub Actions `Deploy BoltGate UI to GitHub Pages` (run `45740374109`) — succeeded
- Live browser checks — verified both GitHub Pages **Bulk Paste -> Combine 2 Mirrors** UI and full end-to-end striped multi-mirror download (`6.00 MB` at `Avg 70.6 MB/s`, `Active Mirrors (2)`, `Parallel Segments (8)`).

---

## Ideas for Parallel Chats / Next Improvements

1. Add an in-app **Engine URL Switcher** in Settings (currently only shown on the offline Connect screen when `loadError` occurs) plus a 1-click Reset to `http://127.0.0.1:3847`.
2. Add a **Live Speed Cap Quick-Toggle** in the sidebar telemetry card so users can throttle/unthrottle without leaving Downloads.
3. Add a **Low Disk Space Pause Guard** that auto-pauses active downloads if free space drops below a configurable threshold.
4. Add a **Download History Export** (JSON/CSV with SHA-256 and integrity audit results).
