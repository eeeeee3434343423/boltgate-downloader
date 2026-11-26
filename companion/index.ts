import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { formatLoopbackOrigin } from '../shared/compat.js';
import { assertLoopbackBindHost, createAppServer } from '../server/app.js';
import { DownloadManager } from '../server/manager.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// dist-server/companion/index.js -> project root is two levels up
const projectRoot = path.resolve(__dirname, '..', '..');

const PORT = Number(process.env.PORT ?? '3847');
const RAW_HOST = process.env.HOST ?? '127.0.0.1';

function openLocalBrowser(url: string): void {
  try {
    if (process.platform === 'win32') {
      const child = spawn('rundll32.exe', ['url.dll,FileProtocolHandler', url], {
        detached: true,
        stdio: 'ignore',
        shell: false,
      });
      child.unref();
      return;
    }
    const cmd = process.platform === 'darwin' ? 'open' : 'xdg-open';
    const child = spawn(cmd, [url], {
      detached: true,
      stdio: 'ignore',
      shell: false,
    });
    child.unref();
  } catch {
    // Non-fatal if headless environment cannot launch browser
  }
}

async function main(): Promise<void> {
  const HOST = assertLoopbackBindHost(RAW_HOST);
  const manager = new DownloadManager({
    dataDir: process.env.BOLTGATE_DATA_DIR ?? path.join(projectRoot, 'data'),
  });
  await manager.init();

  const caps = manager.getSnapshot().capabilities;
  const server = createAppServer({
    manager,
    distDir: path.join(projectRoot, 'dist'),
  });

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error(
        `[BoltGate Companion] ERROR: Port ${PORT} on ${HOST} is already in use by another process (possibly a stale BoltGate listener). Stop the existing process or set PORT=<other> before launching.`
      );
    } else {
      console.error('[BoltGate Companion] Failed to bind listener:', err.message);
    }
    void manager.shutdown().finally(() => process.exit(1));
  });

  server.listen(PORT, HOST, () => {
    // Bracket IPv6 loopback literals: http://[::1]:3847
    const localUrl = formatLoopbackOrigin(HOST, PORT);
    const pairing = manager.issuePairingCode(5 * 60_000);
    console.log(
      `BoltGate Companion v${caps.companionVersion} (API v${caps.apiVersion ?? 4}) listening at ${localUrl}`
    );
    console.log(
      `One-Time Pairing Code (valid 5 min, for hosted GitHub Pages UI): ${pairing.code}`
    );
    console.log(
      caps.aria2Available
        ? `aria2c detected: v${caps.aria2Version} (P2P + multi-connection acceleration enabled)`
        : `aria2c not found — running in Pure Node.js acceleration mode (optional install: ${caps.installHint.command})`
    );
    if (process.env.BOLTGATE_OPEN_BROWSER === '1') {
      openLocalBrowser(localUrl);
    }
  });

  let shuttingDown = false;
  const handleSignal = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log('\nShutting down BoltGate Companion cleanly...');
    await manager.shutdown();
    server.close(() => {
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 2000).unref();
  };

  process.on('SIGINT', handleSignal);
  process.on('SIGTERM', handleSignal);
}

main().catch((err) => {
  console.error('Fatal BoltGate Companion error:', err);
  process.exit(1);
});
