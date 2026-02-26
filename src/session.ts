/**
 * @xferops/auth-middleware
 *
 * Session cookie management for XferOps apps.
 */

import { createJWT, JWTPayload, validateJWT } from './index.js';

export interface SessionConfig {
  cookieName: string;
  secret: string;
  domain?: string;
  path?: string;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  httpOnly?: boolean;
  maxAge?: number;          // seconds
  refreshThreshold?: number; // seconds before expiry to trigger refresh
}

export interface SessionData {
  userId: string;
  email: string;
}

export interface SessionResult {
  valid: boolean;
  session?: SessionData;
  error?: string;
  shouldRefresh?: boolean;
}

// ─── Session create / validate ───────────────────────────────────────────────

/**
 * Create a session token (JWT) for the given identity.
 */
export async function createSession(
  session: SessionData,
  config: SessionConfig,
): Promise<string> {
  const payload: JWTPayload = {
    userId: session.userId,
    email:  session.email,
  };

  return createJWT(payload, config.secret, {
    expiresIn: config.maxAge ? `${config.maxAge}s` : undefined,
  });
}

/**
 * Validate a session cookie value and return the session data.
 */
export async function validateSession(
  cookieValue: string | undefined,
  config: SessionConfig,
): Promise<SessionResult> {
  if (!cookieValue) {
    return { valid: false, error: 'No session cookie' };
  }

  const result = await validateJWT(cookieValue, config.secret);

  if (!result.valid || !result.payload) {
    return { valid: false, error: result.error };
  }

  let shouldRefresh = false;
  if (config.refreshThreshold && result.payload.exp) {
    const now = Math.floor(Date.now() / 1000);
    shouldRefresh = result.payload.exp - now < config.refreshThreshold;
  }

  return {
    valid: true,
    session: {
      userId: result.payload.userId,
      email:  result.payload.email,
    },
    shouldRefresh,
  };
}

// ─── Cookie helpers ──────────────────────────────────────────────────────────

/**
 * Build the attributes portion of a Set-Cookie header.
 *
 * HttpOnly and Secure use bare-flag format (RFC 6265 §5.2) — NOT `HttpOnly=true`.
 * Using `HttpOnly=true` is incorrect per spec; many parsers treat it as an unknown
 * attribute name and silently drop the security flag.
 */
export function getCookieOptions(config: SessionConfig): string {
  const parts: string[] = [`Path=${config.path ?? '/'}`];

  if (config.secure !== false) parts.push('Secure');
  if (config.httpOnly !== false) parts.push('HttpOnly');

  parts.push(`SameSite=${config.sameSite ?? 'lax'}`);

  if (config.domain)  parts.push(`Domain=${config.domain}`);
  if (config.maxAge)  parts.push(`Max-Age=${config.maxAge}`);

  return parts.join('; ');
}

/**
 * Create a full Set-Cookie header string (async — uses real token).
 */
export async function createSessionCookieString(
  session: SessionData,
  config: SessionConfig,
): Promise<string> {
  const token = await createSession(session, config);
  return `${config.cookieName}=${token}; ${getCookieOptions(config)}`;
}

/**
 * Create a Set-Cookie header that clears the session.
 */
export function createLogoutCookie(config: SessionConfig): string {
  return `${config.cookieName}=; ${getCookieOptions(config)}; Max-Age=0`;
}

// ─── Removed: createSessionCookie (sync stub) ───────────────────────────────
// The old sync createSessionCookie() returned a literal "<token>" placeholder —
// callers who used it got a broken cookie that silently failed auth.
// Use createSessionCookieString() (async) instead.

// ─── Cookie parsing ──────────────────────────────────────────────────────────

/**
 * Parse a Cookie request header into a key-value map.
 */
export function parseCookieHeader(cookieHeader: string | undefined): Record<string, string> {
  if (!cookieHeader) return {};

  const cookies: Record<string, string> = {};
  cookieHeader.split(';').forEach((pair) => {
    const [name, ...rest] = pair.split('=');
    if (name) cookies[name.trim()] = rest.join('=').trim();
  });
  return cookies;
}

/**
 * Extract and validate a session from a Cookie request header.
 */
export function getSessionFromHeader(
  cookieHeader: string | undefined,
  config: SessionConfig,
): Promise<SessionResult> {
  const cookies = parseCookieHeader(cookieHeader);
  return validateSession(cookies[config.cookieName], config);
}

// ─── Default config ──────────────────────────────────────────────────────────

/**
 * Default session config for XferOps apps.
 * Cookie name matches the access token issued by xferops-auth.
 */
export const defaultSessionConfig: SessionConfig = {
  cookieName:       '__Secure-xferops.access-token',
  secret:           process.env.AUTH_SECRET ?? '',
  path:             '/',
  secure:           true,
  sameSite:         'lax',
  httpOnly:         true,
  maxAge:           60 * 15,       // 15 minutes (access token TTL)
  refreshThreshold: 60 * 5,        // refresh when <5 min remaining
};

export default {
  createSession,
  validateSession,
  getCookieOptions,
  createSessionCookieString,
  createLogoutCookie,
  parseCookieHeader,
  getSessionFromHeader,
  defaultSessionConfig,
};
