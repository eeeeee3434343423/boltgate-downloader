# BoltGate Project Agent Guide (`AGENTS.md`)

This workspace contains **BoltGate**, a local-first, safe-first multi-segment accelerated download manager with digital book anti-corruption verification and a hybrid GitHub Pages frontend.

## Project Identity & Endpoints

- **Workspace Path:** `C:\Users\jmrol\.gemini\antigravity\scratch\boltgate-downloader`
- **Live Web UI (GitHub Pages):** `https://eeeeee3434343423.github.io/boltgate-downloader/`
- **GitHub Repository:** `https://github.com/eeeeee3434343423/boltgate-downloader` (`main` branch)
- **Local Engine Default Address:** `http://127.0.0.1:3847` (1-click launcher: `Launch-BoltGate.bat`)

## Current Project Status (Phases 1–3 Complete)

See `PROJECT_STATUS.md` for full chronological details and next ideas. Summary of what is already built and verified:

1. **Phase 1 — Safe-First Accelerated Engine & UI:**
   - Zero-payload **Safety Gate** (`server/inspector.ts`) inspects redirects, TLS certificates, MIME vs. extension spoofing, double-extension disguises, Punycode/embedded credentials, range support, free disk space, and Trust List rules before writing any file bytes.
   - Multi-segment parallel downloader (`server/engine.ts`) writes non-overlapping byte chunks via a single shared `FileHandle` (`pwrite`) with streaming backpressure, dynamic tail work-stealing, pause/resume persistence (`server/store.ts`), global `TokenBucketThrottle`, and streaming SHA-256 verification.
   - Accessible WCAG 2.2 AA React 19 + TypeScript UI (`src/`) with Light/Dark themes, live SSE telemetry, Trust List management, Settings presets, Technical Inspector drawer, and 10s Undo toasts.
2. **Phase 2 — Digital Book Anti-Corruption & GitHub Pages Hybrid Deployment:**
   - Added constant-memory binary integrity checker (`server/verifier.ts`) supporting HTML-trap detection and header/trailer verification for `.pdf`, `.epub`, `.mobi`, `.azw`, `.azw3`, `.kfx`, `.djvu`, `.cbz`, `.cbr`, `.fb2`, `.zip`, `.rar`, `.7z`, `.gz`.
   - Added **Digital Books (Anti-Corrupt)** preset (`maxConcurrentDownloads: 3`, `maxConcurrentPerHost: 1`, `segmentsPerDownload: 4`), polite per-host queue limiting (`server/manager.ts`), and `429`/`503` `Retry-After` backoff.
   - Added allowlisted CORS + Private Network Access (`Access-Control-Allow-Private-Network: true`) and `403` CSRF protection in `server/app.ts`, plus `.github/workflows/deploy-pages.yml` deploying `dist/` to GitHub Pages on push to `main`.
3. **Phase 3 (Latest — commit `a2d743a`) — Multi-Mirror Striping & Speed Bottleneck Fixes:**
   - Fixed Range-support detection in `server/inspector.ts` so `HEAD 200` responses omitting `Accept-Ranges` fall back to `GET Range: bytes=0-0` while preserving `Content-Disposition`, `Content-Type`, and `ETag`.
   - Lowered `DEFAULT_MIN_SEGMENT_BYTES` to `128 * 1024` (`128 KiB`) so 1–10 MB ebooks split across up to 16 parallel streams.
   - Added Aria2-style **Multi-Mirror Striped Acceleration** (`POST /api/inspect-mirrors`, Bulk Paste **Same File — Combine Mirrors for Speed** mode, strict byte-size lock across mirrors, fastest-mirror tail work-stealing, and instant failover when a mirror returns `429`/`503`).
   - Added live `< 512 KB/s` bottleneck diagnostics in `src/components/DownloadsView.tsx` and per-segment mirror tracking in `src/components/InspectDrawer.tsx`.
   - **Operational Note:** If an older local BoltGate instance is still running on port `3847`, restart `Launch-BoltGate.bat` / `npm start` after building so the local backend serves the latest `dist-server/`.

## Architecture Map

| Area | Key Files | Responsibility |
| :--- | :--- | :--- |
| Shared Types | `shared/types.ts` | `DownloadItem`, `SafetyReport`, `MirrorProbeSummary`, `FileIntegrityReport`, `AppSettings`, `SSEEvent` |
| Backend Core | `server/inspector.ts`, `server/engine.ts`, `server/verifier.ts`, `server/throttle.ts` | Safety probing, multi-segment/multi-mirror downloader, ebook integrity verification, rate limiter |
| Backend Service | `server/manager.ts`, `server/store.ts`, `server/app.ts`, `server/index.ts` | Queue & per-host scheduler, atomic `state.json` persistence + Undo trash, REST/SSE + CORS/PNA router |
| Frontend UI | `src/App.tsx`, `src/api.ts`, `src/styles.css`, `src/components/*` | React 19 UI (`PasteBar`, `SafetyGateView`, `DownloadsView`, `CompletedView`, `TrustListView`, `SettingsView`, `InspectDrawer`) |
| Tests | `tests/inspector.test.mjs`, `tests/engine.test.mjs`, `tests/verifier.test.mjs`, `tests/api.test.mjs` | Zero-external-network `node --test` integration & unit suite (13 tests) |
| CI/CD | `.github/workflows/deploy-pages.yml` | Builds `dist/` with Vite (`base: './'`) and deploys to GitHub Pages |

## Engineering & Safety Constraints

- **No Gate / Rate-Limit Bypassing:** Never attempt to bypass CAPTCHAs, waiting rooms, paywalls/membership gates, or server-side bandwidth caps (e.g., Anna's Archive Slow Partner Server caps). Improve legitimate throughput only via Range probing, segment tuning, and verified matching multi-mirror striping.
- **Strict Localhost Security:** Never loosen `getAllowedCorsOrigin()` in `server/app.ts` to `*`. Keep allowlisted origins (`https://eeeeee3434343423.github.io`, `localhost`/`127.0.0.1`, optional `BOLTGATE_ALLOWED_ORIGIN`) and `403` CSRF rejection for untrusted mutating requests.
- **No Direct Execution:** `openFile` in `server/manager.ts` must continue blocking executable files; use `openInFolder` (`explorer.exe /select,...` with `shell: false`) instead.
- **Engine Integrity Invariants:** Always drain `inFlightWrites` before closing `FileHandle`; clamp chunks to remaining segment bounds right before `pwrite`; serialize `state.json` atomic renames through `StateStore.writeChain`.
- **Accessibility Floor:** Preserve WCAG 2.2 AA contrast, `:focus-visible` outlines, `calc(100dvh - 2rem)` modal bounds, and `>= 24x24 CSS px` pointer hit targets.

## Common Commands

```powershell
npm run typecheck   # Typecheck frontend (tsconfig.json) and server (tsconfig.server.json)
npm run build       # Compile server -> dist-server/ and Vite UI -> dist/
npm test            # Build server and run all 13 tests in tests/*.test.mjs
npm start           # Start local BoltGate server on http://127.0.0.1:3847
```

Pushing commits to `origin/main` automatically rebuilds and redeploys the static UI to GitHub Pages.
