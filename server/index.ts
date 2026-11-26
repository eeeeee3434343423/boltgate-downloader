import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAppServer } from './app.js';
import { DownloadManager } from './manager.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// dist-server/server/index.js -> project root is two levels up
const projectRoot = path.resolve(__dirname, '..', '..');

const PORT = Number(process.env.PORT ?? '3847');
const HOST = process.env.HOST ?? '127.0.0.1';

async function main(): Promise<void> {
  const manager = new DownloadManager({
    dataDir: process.env.BOLTGATE_DATA_DIR ?? path.join(projectRoot, 'data'),
  });
  await manager.init();

  const server = createAppServer({
    manager,
    distDir: path.join(projectRoot, 'dist'),
  });

  server.listen(PORT, HOST, () => {
    console.log(`BoltGate listening at http://${HOST}:${PORT}`);
  });

  let shuttingDown = false;
  const handleSignal = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log('\nShutting down BoltGate cleanly...');
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
  console.error('Fatal BoltGate error:', err);
  process.exit(1);
});
