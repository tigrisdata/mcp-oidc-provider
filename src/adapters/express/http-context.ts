import type { Request, Response } from 'express';
import type { HttpContext, HttpRequest, HttpResponse, SessionData } from '../../types/http.js';

// Extend express-session types
declare module 'express-session' {
  interface SessionData {
    userSessionId?: string;
    interactionSessionId?: string;
    [key: string]: unknown;
  }
}

/**
 * Create an HttpContext from Express Request and Response objects.
 *
 * @param req - Express Request object
 * @param res - Express Response object
 * @returns HttpContext for use with the OIDC provider
 */
export function createExpressHttpContext(req: Request, res: Response): HttpContext {
  return {
    request: createExpressHttpRequest(req),
    response: createExpressHttpResponse(res),
    getFullUrl(): string {
      const protocol = req.protocol;
      const host = req.get('host') ?? 'localhost';
      return `${protocol}://${host}${req.originalUrl}`;
    },
    // Include raw objects for oidc-provider interoperability
    rawRequest: req,
    rawResponse: res,
  };
}

/**
 * Create an HttpRequest from an Express Request.
 */
function createExpressHttpRequest(req: Request): HttpRequest {
  return {
    method: req.method,
    path: req.path,
    originalUrl: req.originalUrl,
    protocol: req.protocol,
    host: req.get('host') ?? 'localhost',
    headers: req.headers as Record<string, string | string[] | undefined>,
    query: req.query as Record<string, string | string[] | undefined>,
    params: req.params,
    body: req.body,
    session: req.session ? createExpressSessionData(req) : undefined,
  };
}

/**
 * Create a SessionData wrapper for Express session.
 */
function createExpressSessionData(req: Request): SessionData {
  return {
    get userSessionId(): string | undefined {
      return req.session?.['userSessionId'] as string | undefined;
    },
    set userSessionId(value: string | undefined) {
      if (req.session) {
        req.session['userSessionId'] = value;
      }
    },
    get interactionSessionId(): string | undefined {
      return req.session?.['interactionSessionId'] as string | undefined;
    },
    set interactionSessionId(value: string | undefined) {
      if (req.session) {
        req.session['interactionSessionId'] = value;
      }
    },
    regenerate(): Promise<void> {
      return new Promise((resolve, reject) => {
        req.session?.regenerate((err) => {
          if (err) {
            reject(err instanceof Error ? err : new Error(String(err)));
          } else {
            resolve();
          }
        });
      });
    },
    save(): Promise<void> {
      return new Promise((resolve, reject) => {
        req.session?.save((err) => {
          if (err) {
            reject(err instanceof Error ? err : new Error(String(err)));
          } else {
            resolve();
          }
        });
      });
    },
    get<T>(key: string): T | undefined {
      return req.session?.[key] as T | undefined;
    },
    set<T>(key: string, value: T): void {
      if (req.session) {
        req.session[key] = value;
      }
    },
  };
}

/**
 * Create an HttpResponse from an Express Response.
 */
function createExpressHttpResponse(res: Response): HttpResponse {
  const response: HttpResponse = {
    status(code: number): HttpResponse {
      res.status(code);
      return response;
    },
    json(data: unknown): void {
      res.json(data);
    },
    send(data: string): void {
      res.send(data);
    },
    redirect(url: string): void {
      res.redirect(url);
    },
    setHeader(name: string, value: string): HttpResponse {
      res.setHeader(name, value);
      return response;
    },
    get headersSent(): boolean {
      return res.headersSent;
    },
  };
  return response;
}
