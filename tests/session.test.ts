import { describe, it, expect } from 'vitest';
import { 
  createSession, 
  validateSession, 
  createSessionCookieString, 
  createLogoutCookie,
  parseCookieHeader,
  getCookieOptions,
  defaultSessionConfig,
  type SessionConfig 
} from '../src/session';

const TEST_CONFIG: SessionConfig = {
  cookieName: 'test-session',
  secret: 'test-secret-key-for-testing',
  path: '/',
  secure: true,
  sameSite: 'lax',
  httpOnly: true,
  maxAge: 3600,
  refreshThreshold: 300,
};

describe('session management', () => {
  describe('createSession', () => {
    it('should create a valid session token', async () => {
      const session = {
        userId: 'user123',
        email: 'test@example.com',
        role: 'admin',
      };

      const token = await createSession(session, TEST_CONFIG);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });
  });

  describe('validateSession', () => {
    it('should validate a valid session', async () => {
      const session = {
        userId: 'user123',
        email: 'test@example.com',
        role: 'admin',
      };

      const token = await createSession(session, TEST_CONFIG);
      const result = await validateSession(token, TEST_CONFIG);

      expect(result.valid).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.session?.userId).toBe('user123');
      expect(result.session?.email).toBe('test@example.com');
      expect(result.session?.role).toBe('admin');
    });

    it('should reject an invalid session', async () => {
      const result = await validateSession('invalid-token', TEST_CONFIG);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should return error for missing cookie', async () => {
      const result = await validateSession(undefined, TEST_CONFIG);

      expect(result.valid).toBe(false);
      expect(result.error).toBe('No session cookie');
    });
  });

  describe('createSessionCookieString', () => {
    it('should create a valid cookie string', async () => {
      const session = {
        userId: 'user123',
        email: 'test@example.com',
      };

      const cookieString = await createSessionCookieString(session, TEST_CONFIG);

      expect(cookieString).toContain('test-session=');
      expect(cookieString).toContain('HttpOnly=true');
      expect(cookieString).toContain('Secure=true');
      expect(cookieString).toContain('SameSite=lax');
      expect(cookieString).toContain('Path=/');
    });
  });

  describe('createLogoutCookie', () => {
    it('should create a cookie that clears the session', () => {
      const cookie = createLogoutCookie(TEST_CONFIG);

      expect(cookie).toContain('test-session=');
      expect(cookie).toContain('Max-Age=0');
    });
  });

  describe('parseCookieHeader', () => {
    it('should parse a cookie header', () => {
      const header = 'cookie1=value1; cookie2=value2; cookie3=value3';
      const cookies = parseCookieHeader(header);

      expect(cookies['cookie1']).toBe('value1');
      expect(cookies['cookie2']).toBe('value2');
      expect(cookies['cookie3']).toBe('value3');
    });

    it('should handle empty header', () => {
      const cookies = parseCookieHeader(undefined);
      expect(Object.keys(cookies)).toHaveLength(0);
    });
  });

  describe('getCookieOptions', () => {
    it('should generate correct cookie options', () => {
      const options = getCookieOptions(TEST_CONFIG);

      expect(options).toContain('Path=/');
      expect(options).toContain('HttpOnly=true');
      expect(options).toContain('Secure=true');
      expect(options).toContain('SameSite=lax');
    });

    it('should include domain when provided', () => {
      const configWithDomain: SessionConfig = {
        ...TEST_CONFIG,
        domain: '.xferops.dev',
      };

      const options = getCookieOptions(configWithDomain);
      expect(options).toContain('Domain=.xferops.dev');
    });
  });
});