/**
 * OAuth 2.1 error responses (RFC 6749 section 5.2, RFC 7591 section 3.2.2).
 * @internal
 */

import type { Response } from 'express';

/** An OAuth error with the HTTP status it should be reported with. */
export class OAuthRequestError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, description: string, status = 400) {
    super(description);
    this.name = 'OAuthRequestError';
    this.code = code;
    this.status = status;
  }
}

/** Turn any error into an `OAuthRequestError`, hiding internal messages. */
export function toOAuthError(error: unknown): OAuthRequestError {
  if (error instanceof OAuthRequestError) return error;
  return new OAuthRequestError('server_error', 'An unexpected error occurred', 500);
}

/** Send an OAuth JSON error body (`{ error, error_description }`). */
export function sendOAuthError(res: Response, error: OAuthRequestError): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  if (error.status === 401) {
    res.setHeader('WWW-Authenticate', 'Basic realm="token"');
  }
  res.status(error.status).json({ error: error.code, error_description: error.message });
}

/**
 * Append OAuth error parameters to a redirect URI (RFC 6749 section 4.1.2.1).
 */
export function errorRedirectUrl(
  redirectUri: string,
  error: OAuthRequestError,
  state: string | undefined,
  issuer: string
): string {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error.code);
  url.searchParams.set('error_description', error.message);
  if (state !== undefined) url.searchParams.set('state', state);
  url.searchParams.set('iss', issuer);
  return url.toString();
}
