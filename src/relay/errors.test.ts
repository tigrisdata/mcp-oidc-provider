import { describe, it, expect, vi } from 'vitest';
import type { Response } from 'express';
import { OAuthRequestError, errorRedirectUrl, sendOAuthError, toOAuthError } from './errors.js';

function mockResponse() {
  const headers: Record<string, string> = {};
  const res = {
    setHeader: vi.fn((name: string, value: string) => {
      headers[name] = value;
    }),
    status: vi.fn().mockReturnThis(),
    json: vi.fn(),
  };
  return { res: res as unknown as Response, headers, mock: res };
}

describe('errors', () => {
  it('carries an OAuth error code and status', () => {
    const error = new OAuthRequestError('invalid_grant', 'nope');
    expect(error.code).toBe('invalid_grant');
    expect(error.status).toBe(400);
    expect(error.message).toBe('nope');
    expect(error.name).toBe('OAuthRequestError');
    expect(new OAuthRequestError('invalid_client', 'x', 401).status).toBe(401);
  });

  it('hides unknown errors behind server_error', () => {
    const oauth = new OAuthRequestError('access_denied', 'no');
    expect(toOAuthError(oauth)).toBe(oauth);
    const wrapped = toOAuthError(new Error('database exploded'));
    expect(wrapped.code).toBe('server_error');
    expect(wrapped.status).toBe(500);
    expect(wrapped.message).not.toContain('database');
  });

  it('sends a JSON error body with no-store headers', () => {
    const { res, headers, mock } = mockResponse();
    sendOAuthError(res, new OAuthRequestError('invalid_request', 'bad'));

    expect(headers).toEqual({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
    expect(mock.status).toHaveBeenCalledWith(400);
    expect(mock.json).toHaveBeenCalledWith({ error: 'invalid_request', error_description: 'bad' });
  });

  it('challenges with Basic auth on 401', () => {
    const { res, headers } = mockResponse();
    sendOAuthError(res, new OAuthRequestError('invalid_client', 'bad', 401));
    expect(headers['WWW-Authenticate']).toBe('Basic realm="token"');
  });

  it('builds an error redirect with state and iss', () => {
    const url = new URL(
      errorRedirectUrl(
        'http://localhost:3000/cb?keep=1',
        new OAuthRequestError('access_denied', 'The user said no'),
        'abc',
        'https://relay.example'
      )
    );
    expect(url.searchParams.get('keep')).toBe('1');
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('error_description')).toBe('The user said no');
    expect(url.searchParams.get('state')).toBe('abc');
    expect(url.searchParams.get('iss')).toBe('https://relay.example');
  });

  it('omits state when the client sent none', () => {
    const url = new URL(
      errorRedirectUrl('cursor://callback', new OAuthRequestError('x', 'y'), undefined, 'i')
    );
    expect(url.searchParams.has('state')).toBe(false);
    expect(url.protocol).toBe('cursor:');
  });
});
