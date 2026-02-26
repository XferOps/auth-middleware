import { describe, it, expect } from 'vitest';
import {
  validateJWT,
  createJWT,
  createRefreshToken,
  extractToken,
  authMiddleware,
  JWT_ISSUER,
  JWT_AUDIENCE,
} from '../src/index';

const TEST_SECRET = 'test-secret-key-for-testing-purposes-only';

describe('auth-middleware', () => {
  // ── createJWT ──────────────────────────────────────────────────────────────

  describe('createJWT', () => {
    it('creates a valid 3-part JWT', async () => {
      const token = await createJWT({ userId: 'user123', email: 'test@example.com' }, TEST_SECRET);
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);
    });

    it('sets iss and aud claims', async () => {
      const token = await createJWT({ userId: 'user123', email: 'test@example.com' }, TEST_SECRET);
      // Decode the payload (middle part) without verifying — just inspect claims
      const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      expect(decoded.iss).toBe(JWT_ISSUER);
      expect(decoded.aud).toBe(JWT_AUDIENCE);
    });

    it('defaults to 15m expiry', async () => {
      const before = Math.floor(Date.now() / 1000);
      const token = await createJWT({ userId: 'user123', email: 'test@example.com' }, TEST_SECRET);
      const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      const ttl = decoded.exp - before;
      // Should be ~15 minutes (900s) — allow ±10s for test timing
      expect(ttl).toBeGreaterThan(890);
      expect(ttl).toBeLessThan(910);
    });

    it('respects custom expiresIn', async () => {
      const before = Math.floor(Date.now() / 1000);
      const token = await createJWT(
        { userId: 'user123', email: 'test@example.com' },
        TEST_SECRET,
        { expiresIn: '1h' },
      );
      const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      const ttl = decoded.exp - before;
      expect(ttl).toBeGreaterThan(3590);
      expect(ttl).toBeLessThan(3610);
    });

    it('does not include role or name claims', async () => {
      const token = await createJWT({ userId: 'user123', email: 'test@example.com' }, TEST_SECRET);
      const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      expect(decoded.role).toBeUndefined();
      expect(decoded.name).toBeUndefined();
    });
  });

  // ── validateJWT ────────────────────────────────────────────────────────────

  describe('validateJWT', () => {
    it('validates a well-formed token', async () => {
      const token = await createJWT({ userId: 'user123', email: 'test@example.com' }, TEST_SECRET);
      const result = await validateJWT(token, TEST_SECRET);
      expect(result.valid).toBe(true);
      expect(result.payload?.userId).toBe('user123');
      expect(result.payload?.email).toBe('test@example.com');
    });

    it('rejects a malformed token', async () => {
      const result = await validateJWT('invalid.token.here', TEST_SECRET);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('rejects a token signed with the wrong secret', async () => {
      const token = await createJWT({ userId: 'user123', email: 'test@example.com' }, TEST_SECRET);
      const result = await validateJWT(token, 'wrong-secret');
      expect(result.valid).toBe(false);
    });

    it('rejects a token with wrong issuer', async () => {
      // Create a token with a different issuer by signing manually
      const { SignJWT } = await import('jose');
      const secretKey = new TextEncoder().encode(TEST_SECRET);
      const token = await new SignJWT({ email: 'test@example.com' })
        .setProtectedHeader({ alg: 'HS256' })
        .setSubject('user123')
        .setIssuer('https://evil.example.com')
        .setAudience(JWT_AUDIENCE)
        .setExpirationTime('15m')
        .sign(secretKey);

      const result = await validateJWT(token, TEST_SECRET);
      expect(result.valid).toBe(false);
    });

    it('rejects a token with wrong audience', async () => {
      const { SignJWT } = await import('jose');
      const secretKey = new TextEncoder().encode(TEST_SECRET);
      const token = await new SignJWT({ email: 'test@example.com' })
        .setProtectedHeader({ alg: 'HS256' })
        .setSubject('user123')
        .setIssuer(JWT_ISSUER)
        .setAudience('wrong-audience')
        .setExpirationTime('15m')
        .sign(secretKey);

      const result = await validateJWT(token, TEST_SECRET);
      expect(result.valid).toBe(false);
    });
  });

  // ── createRefreshToken ─────────────────────────────────────────────────────

  describe('createRefreshToken', () => {
    it('creates a valid token with ~30d expiry', async () => {
      const before = Math.floor(Date.now() / 1000);
      const token = await createRefreshToken(
        { userId: 'user123', email: 'test@example.com' },
        TEST_SECRET,
      );
      const result = await validateJWT(token, TEST_SECRET);
      expect(result.valid).toBe(true);

      const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      const ttlDays = (decoded.exp - before) / 86400;
      expect(ttlDays).toBeGreaterThan(29.9);
      expect(ttlDays).toBeLessThan(30.1);
    });
  });

  // ── extractToken ───────────────────────────────────────────────────────────

  describe('extractToken', () => {
    it('extracts token from Bearer header', () => {
      expect(extractToken('Bearer my-token-123')).toBe('my-token-123');
    });

    it('returns null for missing header', () => {
      expect(extractToken(undefined)).toBeNull();
    });

    it('returns null for non-Bearer scheme', () => {
      expect(extractToken('Basic auth-token')).toBeNull();
    });
  });

  // ── authMiddleware ─────────────────────────────────────────────────────────

  describe('authMiddleware', () => {
    it('validates a token from Authorization header', async () => {
      const token = await createJWT({ userId: 'user123', email: 'test@example.com' }, TEST_SECRET);
      const middleware = authMiddleware(TEST_SECRET);
      const result = await middleware(`Bearer ${token}`);
      expect(result.valid).toBe(true);
      expect(result.payload?.userId).toBe('user123');
    });

    it('rejects a missing token', async () => {
      const middleware = authMiddleware(TEST_SECRET);
      const result = await middleware(undefined);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('No token provided');
    });
  });
});
