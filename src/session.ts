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
  maxAge?: number; // seconds
  refreshThreshold?: number; // seconds before expiry to refresh
}

export interface SessionData {
  userId: string;
  email: string;
  role?: string;
  name?: string;
}

export interface SessionResult {
  valid: boolean;
  session?: SessionData;
  error?: string;
  shouldRefresh?: boolean;
}

/**
 * Create a session cookie value
 */
export async function createSession(
  session: SessionData,
  config: SessionConfig
): Promise<string> {
  const payload: JWTPayload = {
    userId: session.userId,
    email: session.email,
    role: session.role,
    name: session.name,
  };

  return createJWT(payload, config.secret, { 
    expiresIn: config.maxAge ? `${config.maxAge}s` : '24h' 
  });
}

/**
 * Validate and parse a session cookie
 */
export async function validateSession(
  cookieValue: string | undefined,
  config: SessionConfig
): Promise<SessionResult> {
  if (!cookieValue) {
    return { valid: false, error: 'No session cookie' };
  }

  const result = await validateJWT(cookieValue, config.secret);

  if (!result.valid || !result.payload) {
    return { valid: false, error: result.error };
  }

  // Check if token needs refresh (expiring soon)
  let shouldRefresh = false;
  if (config.refreshThreshold && result.payload.exp) {
    const now = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = result.payload.exp - now;
    shouldRefresh = timeUntilExpiry < config.refreshThreshold;
  }

  return {
    valid: true,
    session: {
      userId: result.payload.userId,
      email: result.payload.email,
      role: result.payload.role,
      name: result.payload.name,
    },
    shouldRefresh,
  };
}

/**
 * Get cookie options for Set-Cookie header
 */
export function getCookieOptions(config: SessionConfig): string {
  const options: string[] = [
    `Path=${config.path || '/'}`,
    `HttpOnly=${config.httpOnly !== false ? 'true' : 'false'}`,
    `Secure=${config.secure !== false ? 'true' : 'false'}`,
    `SameSite=${config.sameSite || 'lax'}`,
  ];

  if (config.domain) {
    options.push(`Domain=${config.domain}`);
  }

  if (config.maxAge) {
    options.push(`Max-Age=${config.maxAge}`);
  }

  return options.join('; ');
}

/**
 * Create a Set-Cookie header value for session
 * Note: This is a sync version that returns a placeholder - use createSessionCookieString for actual use
 */
export function createSessionCookie(
  session: SessionData,
  config: SessionConfig
): string {
  // Note: Use createSessionCookieString for actual token generation
  // This sync version is a placeholder for API compatibility
  return `${config.cookieName}=<token>; ${getCookieOptions(config)}`;
}

/**
 * Create a session cookie (async version)
 */
export async function createSessionCookieString(
  session: SessionData,
  config: SessionConfig
): Promise<string> {
  const token = await createSession(session, config);
  return `${config.cookieName}=${token}; ${getCookieOptions(config)}`;
}

/**
 * Create a cleared session cookie (for logout)
 */
export function createLogoutCookie(config: SessionConfig): string {
  return `${config.cookieName}=; ${getCookieOptions(config)}; Max-Age=0`;
}

/**
 * Parse cookie header into key-value map
 */
export function parseCookieHeader(cookieHeader: string | undefined): Record<string, string> {
  if (!cookieHeader) {
    return {};
  }

  const cookies: Record<string, string> = {};
  
  cookieHeader.split(';').forEach((cookie) => {
    const [name, ...rest] = cookie.split('=');
    if (name && rest.length > 0) {
      cookies[name.trim()] = rest.join('=').trim();
    }
  });

  return cookies;
}

/**
 * Extract session from cookie header
 */
export function getSessionFromHeader(
  cookieHeader: string | undefined,
  config: SessionConfig
): Promise<SessionResult> {
  const cookies = parseCookieHeader(cookieHeader);
  const sessionCookie = cookies[config.cookieName];
  return validateSession(sessionCookie, config);
}

/**
 * Default config for XferOps apps
 */
export const defaultSessionConfig: SessionConfig = {
  cookieName: '__Secure-authjs.session-token',
  secret: process.env.AUTH_SECRET || '',
  path: '/',
  secure: true,
  sameSite: 'lax',
  httpOnly: true,
  maxAge: 60 * 60 * 24, // 24 hours
  refreshThreshold: 60 * 15, // 15 minutes
};

export default {
  createSession,
  validateSession,
  getCookieOptions,
  createSessionCookie,
  createSessionCookieString,
  createLogoutCookie,
  parseCookieHeader,
  getSessionFromHeader,
  defaultSessionConfig,
};