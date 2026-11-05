/**
 * Start an Express app on an ephemeral loopback port for integration tests
 * that exercise it with the global `fetch`.
 *
 * Servers started with `listen` are closed automatically after each test
 * (see `src/test/setup.ts`).
 */

import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Application } from 'express';

const servers: Server[] = [];

/**
 * Start the app and return its base URL, e.g. `http://127.0.0.1:54321`.
 */
export async function listen(app: Application): Promise<string> {
  const server = await new Promise<Server>((resolve, reject) => {
    const s = app.listen(0, '127.0.0.1');
    s.once('listening', () => resolve(s));
    s.once('error', reject);
  });
  servers.push(server);
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

/**
 * Close every server started with `listen` since the last call.
 */
export async function closeServers(): Promise<void> {
  const open = servers.splice(0);
  await Promise.all(
    open.map(
      (server) =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        })
    )
  );
}
