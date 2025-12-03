import type { JWTPayload } from 'jose';

/**
 * User session stored after successful authentication.
 * This contains the user's identity and tokens from the upstream IdP.
 */
export interface UserSession {
  /** Unique user identifier from the IdP (sub claim) */
  userId: string;
  /** JWT claims from the ID token */
  claims: JWTPayload;
  /** Token set from the IdP */
  tokenSet: {
    /** Access token for calling IdP APIs */
    accessToken: string;
    /** ID token containing user identity */
    idToken: string;
    /** Refresh token for obtaining new access tokens */
    refreshToken: string;
  };
  /** Custom data extracted from IdP claims (e.g., organizations, roles) */
  customData?: Record<string, unknown>;
}

/**
 * Session store interface for managing user sessions.
 * Implement this to use a custom storage backend.
 */
export interface SessionStore {
  /**
   * Store a user session.
   * @param sessionId - Unique session identifier
   * @param session - The user session data
   * @param ttl - Optional TTL in milliseconds
   */
  set(sessionId: string, session: UserSession, ttl?: number): Promise<void>;

  /**
   * Retrieve a user session.
   * @param sessionId - The session identifier
   * @returns The session data, or undefined if not found
   */
  get(sessionId: string): Promise<UserSession | undefined>;

  /**
   * Delete a user session.
   * @param sessionId - The session identifier
   * @returns true if the session was deleted, false if it didn't exist
   */
  delete(sessionId: string): Promise<boolean>;

  /**
   * Clear all user sessions.
   */
  clear(): Promise<void>;
}

/**
 * Interaction session for storing OAuth flow state.
 * Used temporarily during the authorization flow.
 */
export interface InteractionSession {
  /** The OIDC provider interaction UID */
  interactionUid: string;
  /** OAuth state parameter for CSRF protection */
  idpState: string;
  /** OAuth nonce for replay protection */
  idpNonce: string;
  /** PKCE code verifier */
  codeVerifier: string;
}
