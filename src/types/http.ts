/**
 * Session data interface for HTTP sessions.
 * Implementations should adapt their framework's session to this interface.
 */
export interface SessionData {
  /** User session ID linking to the user session store */
  userSessionId?: string;
  /** Interaction session ID for OAuth flow state */
  interactionSessionId?: string;

  /**
   * Regenerate the session (for security after authentication).
   * This should create a new session ID while preserving session data.
   */
  regenerate(): Promise<void>;

  /**
   * Save the session.
   * Call this after modifying session data.
   */
  save(): Promise<void>;

  /**
   * Get a value from the session.
   */
  get<T>(key: string): T | undefined;

  /**
   * Set a value in the session.
   */
  set<T>(key: string, value: T): void;
}

/**
 * Framework-agnostic HTTP request interface.
 * Adapt your framework's request object to this interface.
 */
export interface HttpRequest {
  /** HTTP method (GET, POST, etc.) */
  method: string;
  /** Request path without query string */
  path: string;
  /** Original URL including query string */
  originalUrl: string;
  /** Request protocol (http or https) */
  protocol: string;
  /** Host header value */
  host: string;
  /** Request headers (keys should be lowercase) */
  headers: Record<string, string | string[] | undefined>;
  /** Query parameters */
  query: Record<string, string | string[] | undefined>;
  /** URL parameters from route matching */
  params: Record<string, string>;
  /** Parsed request body (if applicable) */
  body?: unknown;
  /** Session data (optional, for frameworks with session support) */
  session?: SessionData;
}

/**
 * Framework-agnostic HTTP response interface.
 * Adapt your framework's response object to this interface.
 */
export interface HttpResponse {
  /**
   * Set the HTTP status code.
   * @returns this for chaining
   */
  status(code: number): HttpResponse;

  /**
   * Send a JSON response.
   * Should set Content-Type to application/json.
   */
  json(data: unknown): void;

  /**
   * Send a text or HTML response.
   */
  send(data: string): void;

  /**
   * Redirect to a URL.
   * @param url - The URL to redirect to
   */
  redirect(url: string): void;

  /**
   * Set a response header.
   * @returns this for chaining
   */
  setHeader(name: string, value: string): HttpResponse;

  /** Whether headers have already been sent */
  headersSent: boolean;
}

/**
 * Combined HTTP context passed to handlers.
 */
export interface HttpContext {
  /** The HTTP request */
  request: HttpRequest;
  /** The HTTP response */
  response: HttpResponse;

  /**
   * Get the full URL for the current request.
   * Should include protocol, host, and path with query string.
   */
  getFullUrl(): string;

  /**
   * Raw framework-specific request object.
   * Used for interoperability with libraries that need the original request.
   */
  rawRequest?: unknown;

  /**
   * Raw framework-specific response object.
   * Used for interoperability with libraries that need the original response.
   */
  rawResponse?: unknown;
}

/**
 * Next function for middleware chains.
 */
export type NextFunction = () => void | Promise<void>;

/**
 * Generic middleware function signature.
 */
export type Middleware = (ctx: HttpContext, next: NextFunction) => void | Promise<void>;
