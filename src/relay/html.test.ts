import { describe, it, expect } from 'vitest';
import {
  escapeHtml,
  htmlDocument,
  renderConsentPage,
  renderErrorPage,
  type ConsentView,
} from './html.js';

const view: ConsentView = {
  clientName: 'Example <Client>',
  clientId: 'https://client.example/metadata.json',
  redirectUri: 'http://localhost:3000/callback?x="1"',
  redirectHost: 'localhost:3000',
  redirectIsLocal: true,
  scopes: ['openid', 'email'],
  upstreamName: 'auth.example.com',
  resourceName: 'Example MCP',
  action: 'http://localhost:3000/authorize/consent',
  fields: { id: 'abc', csrf: 'x"y' },
};

describe('html', () => {
  it('escapes HTML special characters', () => {
    expect(escapeHtml(`<a href="x">&'</a>`)).toBe(
      '&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;'
    );
    expect(escapeHtml(undefined)).toBe('');
    expect(escapeHtml(42)).toBe('42');
  });

  it('wraps content in a document with an escaped title', () => {
    const html = htmlDocument('A <title>', '<p>body</p>');
    expect(html).toContain('<title>A &lt;title&gt;</title>');
    expect(html).toContain('<p>body</p>');
    expect(html).toContain('name="robots" content="noindex"');
  });

  describe('renderConsentPage', () => {
    it('shows the client, redirect target and scopes, escaped', () => {
      const html = renderConsentPage(view);
      expect(html).toContain('Example &lt;Client&gt;');
      expect(html).not.toContain('Example <Client>');
      expect(html).toContain('<strong>localhost:3000</strong>');
      expect(html).toContain('http://localhost:3000/callback?x=&quot;1&quot;');
      expect(html).toContain('<code>openid</code>');
      expect(html).toContain('<code>email</code>');
      expect(html).toContain('auth.example.com');
      expect(html).toContain('<strong>Example MCP</strong>');
    });

    it('posts the hidden fields and decision to the action URL', () => {
      const html = renderConsentPage(view);
      expect(html).toContain('action="http://localhost:3000/authorize/consent"');
      expect(html).toContain('<input type="hidden" name="id" value="abc">');
      expect(html).toContain('<input type="hidden" name="csrf" value="x&quot;y">');
      expect(html).toContain('name="decision" value="approve"');
      expect(html).toContain('name="decision" value="deny"');
    });

    it('warns about local redirect targets', () => {
      expect(renderConsentPage(view)).toContain('runs on your computer');
      expect(renderConsentPage({ ...view, redirectIsLocal: false })).not.toContain(
        'runs on your computer'
      );
    });

    it('omits optional sections', () => {
      const html = renderConsentPage({ ...view, scopes: [], resourceName: undefined });
      expect(html).not.toContain('Requested access');
      expect(html).not.toContain('<strong>Example MCP</strong>');
    });
  });

  it('renders an error page', () => {
    const html = renderErrorPage('Oops <1>', 'Something & other');
    expect(html).toContain('<h1>Oops &lt;1&gt;</h1>');
    expect(html).toContain('Something &amp; other');
  });
});
