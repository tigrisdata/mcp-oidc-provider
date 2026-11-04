/**
 * Minimal HTTP test client for Express apps built on the global `fetch`.
 *
 * Drop-in replacement for the subset of supertest the test suite used:
 *
 * ```typescript
 * const response = await request(app).post('/mcp').set('Authorization', 'Bearer x').send({ a: 1 });
 * response.status; response.body; response.headers['content-type'];
 * ```
 *
 * Each request starts the app on an ephemeral loopback port, performs the
 * request, and closes the server again. Redirects are never followed.
 */

import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Application } from 'express';

export interface TestResponse {
  /** HTTP status code */
  status: number;
  /** Response headers, keys lower-cased */
  headers: Record<string, string>;
  /** Parsed JSON body when the response is JSON, otherwise `{}` */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body: any;
  /** Raw response body */
  text: string;
}

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS';

function listen(app: Application): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1');
    server.once('listening', () => resolve(server));
    server.once('error', reject);
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
}

class TestRequest implements PromiseLike<TestResponse> {
  private readonly requestHeaders: Record<string, string> = {};
  private payload: string | undefined;

  constructor(
    private readonly app: Application,
    private readonly method: HttpMethod,
    private readonly path: string
  ) {}

  /** Set a request header. */
  set(name: string, value: string): this {
    this.requestHeaders[name] = value;
    return this;
  }

  /** Send a body. Objects are JSON-encoded with a JSON content type. */
  send(body: unknown): this {
    if (typeof body === 'string') {
      this.payload = body;
    } else {
      this.payload = JSON.stringify(body);
      if (!Object.keys(this.requestHeaders).some((h) => h.toLowerCase() === 'content-type')) {
        this.requestHeaders['Content-Type'] = 'application/json';
      }
    }
    return this;
  }

  then<TResult1 = TestResponse, TResult2 = never>(
    onfulfilled?: ((value: TestResponse) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null
  ): Promise<TResult1 | TResult2> {
    return this.execute().then(onfulfilled, onrejected);
  }

  private async execute(): Promise<TestResponse> {
    const server = await listen(this.app);
    try {
      const { port } = server.address() as AddressInfo;
      const response = await fetch(`http://127.0.0.1:${port}${this.path}`, {
        method: this.method,
        headers: this.requestHeaders,
        body: this.payload,
        redirect: 'manual',
      });

      const text = await response.text();
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });

      let body: unknown = {};
      if (text && (headers['content-type'] ?? '').includes('json')) {
        try {
          body = JSON.parse(text);
        } catch {
          body = {};
        }
      }

      return { status: response.status, headers, body, text };
    } finally {
      await close(server);
    }
  }
}

/**
 * Create a test client for an Express app.
 */
export function request(app: Application) {
  return {
    get: (path: string) => new TestRequest(app, 'GET', path),
    post: (path: string) => new TestRequest(app, 'POST', path),
    put: (path: string) => new TestRequest(app, 'PUT', path),
    delete: (path: string) => new TestRequest(app, 'DELETE', path),
    options: (path: string) => new TestRequest(app, 'OPTIONS', path),
  };
}
