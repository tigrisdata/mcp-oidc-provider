/**
 * Minimal HTML rendering for the consent and error pages.
 * @internal
 */

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** Escape a value for safe interpolation into HTML text or attributes. */
export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, (char) => HTML_ESCAPES[char] ?? char);
}

const STYLES = `
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0; padding: 2rem 1rem;
         background: Canvas; color: CanvasText; display: flex; justify-content: center; }
  main { max-width: 28rem; width: 100%; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  p { line-height: 1.5; }
  dl { margin: 1rem 0; padding: 1rem; border: 1px solid color-mix(in srgb, CanvasText 20%, transparent);
       border-radius: 0.5rem; }
  dt { font-size: 0.8rem; opacity: 0.7; margin-top: 0.75rem; }
  dt:first-child { margin-top: 0; }
  dd { margin: 0.1rem 0 0; word-break: break-all; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }
  ul { margin: 0.25rem 0 0; padding-left: 1.25rem; }
  .warning { padding: 0.75rem 1rem; border-radius: 0.5rem; border: 1px solid #c58b00;
             background: color-mix(in srgb, #ffbf00 15%, transparent); }
  .actions { display: flex; gap: 0.75rem; margin-top: 1.5rem; }
  button { font: inherit; padding: 0.6rem 1.2rem; border-radius: 0.5rem; cursor: pointer;
           border: 1px solid color-mix(in srgb, CanvasText 30%, transparent); background: Canvas; color: CanvasText; }
  button.primary { background: #2563eb; border-color: #2563eb; color: white; }
`;

/** Wrap body markup in a complete HTML document. */
export function htmlDocument(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<style>${STYLES}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>
`;
}

/** Data available to the consent page template. */
export interface ConsentView {
  /** Name the client registered (or its host for a metadata document client). */
  clientName: string;
  /** The `client_id`; for Client ID Metadata Documents this is an `https` URL. */
  clientId: string;
  /** Where the authorization code will be sent. */
  redirectUri: string;
  /** Hostname of the redirect URI (shown prominently, per the MCP spec). */
  redirectHost: string;
  /** Whether the redirect URI points at the local machine. */
  redirectIsLocal: boolean;
  /** Scopes the client asked for. */
  scopes: string[];
  /** Human-readable name of the identity provider the user will sign in with. */
  upstreamName: string;
  /** Name of the resource being accessed (`resourceName`), if configured. */
  resourceName: string | undefined;
  /** Form action URL. */
  action: string;
  /** Hidden form fields that must be submitted with the decision. */
  fields: Record<string, string>;
}

/** Default consent page. */
export function renderConsentPage(view: ConsentView): string {
  const hidden = Object.entries(view.fields)
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`
    )
    .join('\n');
  const scopes =
    view.scopes.length > 0
      ? `<dt>Requested access</dt><dd><ul>${view.scopes
          .map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`)
          .join('')}</ul></dd>`
      : '';
  const warning = view.redirectIsLocal
    ? `<p class="warning">This application runs on your computer. Only continue if you started this request yourself.</p>`
    : '';
  const target = view.resourceName ? ` to <strong>${escapeHtml(view.resourceName)}</strong>` : '';

  return htmlDocument(
    'Authorize application',
    `<h1>Authorize <strong>${escapeHtml(view.clientName)}</strong>?</h1>
<p>${escapeHtml(view.clientName)} is asking for access${target} on your behalf.
If you continue, you will sign in with ${escapeHtml(view.upstreamName)} and the application will receive tokens for your account.</p>
<dl>
<dt>Application</dt><dd>${escapeHtml(view.clientName)}</dd>
<dt>Client identifier</dt><dd><code>${escapeHtml(view.clientId)}</code></dd>
<dt>Will be sent to</dt><dd><strong>${escapeHtml(view.redirectHost)}</strong><br><code>${escapeHtml(view.redirectUri)}</code></dd>
${scopes}
</dl>
${warning}
<form method="post" action="${escapeHtml(view.action)}">
${hidden}
<div class="actions">
<button type="submit" name="decision" value="approve" class="primary">Continue</button>
<button type="submit" name="decision" value="deny">Cancel</button>
</div>
</form>`
  );
}

/** Error page used when a request cannot be redirected back to the client. */
export function renderErrorPage(title: string, description: string): string {
  return htmlDocument(
    title,
    `<h1>${escapeHtml(title)}</h1>
<p>${escapeHtml(description)}</p>
<p>Close this window and try again from the application you were using.</p>`
  );
}
