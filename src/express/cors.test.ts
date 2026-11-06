import { describe, it, expect } from 'vitest';
import express from 'express';
import { listen } from '../test/helpers/index.js';
import { createMcpCorsMiddleware } from './cors.js';

const INSPECTOR = 'http://localhost:6274';

async function serve(options?: Parameters<typeof createMcpCorsMiddleware>[0]): Promise<string> {
  const app = express();
  app.use(createMcpCorsMiddleware(options));
  app.get('/mcp', (_req, res) => {
    res.json({ ok: true });
  });
  return listen(app);
}

describe('createMcpCorsMiddleware', () => {
  it('always sets the MCP CORS headers', async () => {
    const baseUrl = await serve();
    const response = await fetch(`${baseUrl}/mcp`);

    expect(response.status).toBe(200);
    expect(response.headers.get('access-control-allow-credentials')).toBe('true');
    expect(response.headers.get('access-control-allow-headers')).toContain('Authorization');
    expect(response.headers.get('access-control-allow-headers')).toContain('mcp-session-id');
    expect(response.headers.get('access-control-expose-headers')).toContain('Mcp-Session-Id');
    expect(response.headers.get('access-control-allow-methods')).toContain('DELETE');
    expect(response.headers.get('access-control-max-age')).toBe('86400');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('allows the MCP Inspector origin by default', async () => {
    const baseUrl = await serve();
    const response = await fetch(`${baseUrl}/mcp`, { headers: { Origin: INSPECTOR } });
    expect(response.headers.get('access-control-allow-origin')).toBe(INSPECTOR);
  });

  it('allows the base URL and additional origins only', async () => {
    const baseUrl = await serve({
      baseUrl: 'https://example.com',
      additionalOrigins: ['https://custom.com'],
    });
    const origins = async (origin: string) =>
      (await fetch(`${baseUrl}/mcp`, { headers: { Origin: origin } })).headers.get(
        'access-control-allow-origin'
      );

    expect(await origins('https://example.com')).toBe('https://example.com');
    expect(await origins('https://custom.com')).toBe('https://custom.com');
    expect(await origins(INSPECTOR)).toBe(INSPECTOR);
    expect(await origins('https://malicious.com')).toBeNull();
  });

  it('answers preflight requests with 204', async () => {
    const baseUrl = await serve();
    const response = await fetch(`${baseUrl}/mcp`, {
      method: 'OPTIONS',
      headers: { Origin: INSPECTOR, 'Access-Control-Request-Method': 'POST' },
    });

    expect(response.status).toBe(204);
    expect(response.headers.get('access-control-allow-origin')).toBe(INSPECTOR);
  });
});
