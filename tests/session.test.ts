import { describe, it, expect } from 'vitest';
import {
  createSession,
  validateSession,
  createSessionCookieString,
  createLogoutCookie,
  parseCookieHeader,
  getCookieOptions,
  defaultSessionConfig,
  type SessionConfig,
} from '../src/session';

const TEST_CONFIG: SessionConfig = {
  cookieName:       'test-session',
  secret:           'test-secret-key-for-testing',
  path:             '/',
  secure:           true,
  sameSite:         'lax',
  httpOnly:         true,
  maxAge:           3600,
  refreshThreshold: 300,
};

describe('session management', () => {
  // ── createSession ──────────────────────────────────────────────────────────

  describe('createSession', () => {
    it('creates a valid 3-part JWT', async () => {
      const token = await createSession(
        { userId: 'user123', email: 'test@example.com' },
        TEST_CONFIG,
      );
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });
  });

  // ── validateSession ────────────────────────────────────────────────────────

  describe('validateSession', () => {
    it('validates a valid session', async () => {
      const token = await createSession(
        { userId: 'user123', email: 'test@example.com' },
        TEST_CONFIG,
      );
      const result = await validateSession(token, TEST_CONFIG);
      expect(result.valid).toBe(true);
      expect(result.session?.userId).toBe('user123');
      expect(result.session?.email).toBe('test@example.com');
    });

    it('rejects an invalid token', async () => {
      const result = await validateSession('invalid-token', TEST_CONFIG);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('returns error for missing cookie', async () => {
      const result = await validateSession(undefined, TEST_CONFIG);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('No session cookie');
    });

    it('does not include role or name in session result', async () => {
      const token = await createSession(
        { userId: 'user123', email: 'test@example.com' },
        TEST_CONFIG,
      );
      const result = await validateSession(token, TEST_CONFIG);
      expect(result.valid).toBe(true);
      expect((result.session as any)?.role).toBeUndefined();
      expect((result.session as any)?.name).toBeUndefined();
    });
  });

  // ── getCookieOptions ───────────────────────────────────────────────────────

  describe('getCookieOptions', () => {
    it('uses bare HttpOnly and Secure flags (RFC 6265)', () => {
      const options = getCookieOptions(TEST_CONFIG);
      // Bare flags — NOT "HttpOnly=true"
      expect(options).toContain('HttpOnly');
      expect(options).not.toContain('HttpOnly=true');
      expect(options).toContain('Secure');
      expect(options).not.toContain('Secure=true');
    });

    it('includes Path and SameSite', () => {
      const options = getCookieOptions(TEST_CONFIG);
      expect(options).toContain('Path=/');
      expect(options).toContain('SameSite=lax');
    });

    it('includes Domain when provided', () => {
      const options = getCookieOptions({ ...TEST_CONFIG, domain: '.xferops.dev' });
      expect(options).toContain('Domain=.xferops.dev');
    });

    it('omits HttpOnly and Secure when disabled', () => {
      const options = getCookieOptions({ ...TEST_CONFIG, secure: false, httpOnly: false });
      expect(options).not.toContain('Secure');
      expect(options).not.toContain('HttpOnly');
    });

    it('includes Max-Age when configured', () => {
      const options = getCookieOptions(TEST_CONFIG);
      expect(options).toContain('Max-Age=3600');
    });
  });

  // ── createSessionCookieString ──────────────────────────────────────────────

  describe('createSessionCookieString', () => {
    it('creates a valid Set-Cookie string', async () => {
      const cookie = await createSessionCookieString(
        { userId: 'user123', email: 'test@example.com' },
        TEST_CONFIG,
      );
      expect(cookie).toContain('test-session=');
      expect(cookie).toContain('HttpOnly');
      expect(cookie).toContain('Secure');
      expect(cookie).toContain('SameSite=lax');
      expect(cookie).toContain('Path=/');
      // Value should be a real JWT, not a placeholder
      const tokenPart = cookie.split(';')[0].replace('test-session=', '');
      expect(tokenPart.split('.')).toHaveLength(3);
    });
  });

  // ── createLogoutCookie ─────────────────────────────────────────────────────

  describe('createLogoutCookie', () => {
    it('creates a cookie that clears the session', () => {
      const cookie = createLogoutCookie(TEST_CONFIG);
      expect(cookie).toContain('test-session=;');
      expect(cookie).toContain('Max-Age=0');
    });
  });

  // ── parseCookieHeader ──────────────────────────────────────────────────────

  describe('parseCookieHeader', () => {
    it('parses a multi-value cookie header', () => {
      const cookies = parseCookieHeader('a=1; b=2; c=3');
      expect(cookies['a']).toBe('1');
      expect(cookies['b']).toBe('2');
      expect(cookies['c']).toBe('3');
    });

    it('handles cookies with = in the value (e.g. base64)', () => {
      const cookies = parseCookieHeader('token=abc.def==');
      expect(cookies['token']).toBe('abc.def==');
    });

    it('returns empty object for undefined header', () => {
      expect(parseCookieHeader(undefined)).toEqual({});
    });
  });

  // ── defaultSessionConfig ───────────────────────────────────────────────────

  describe('defaultSessionConfig', () => {
    it('uses the xferops access token cookie name', () => {
      expect(defaultSessionConfig.cookieName).toBe('__Secure-xferops.access-token');
    });

    it('has 15m maxAge (matches access token TTL)', () => {
      expect(defaultSessionConfig.maxAge).toBe(900);
    });
  });
});
