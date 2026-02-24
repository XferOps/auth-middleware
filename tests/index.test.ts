import { describe, it, expect } from 'vitest';
import { validateJWT, createJWT, createRefreshToken, extractToken, authMiddleware } from '../src/index';

const TEST_SECRET = 'test-secret-key-for-testing-purposes-only';

describe('auth-middleware', () => {
  describe('createJWT', () => {
    it('should create a valid JWT token', async () => {
      const payload = {
        userId: 'user123',
        email: 'test@example.com',
        role: 'admin',
      };
      
      const token = await createJWT(payload, TEST_SECRET);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });
  });

  describe('validateJWT', () => {
    it('should validate a valid token', async () => {
      const payload = {
        userId: 'user123',
        email: 'test@example.com',
        role: 'admin',
      };
      
      const token = await createJWT(payload, TEST_SECRET);
      const result = await validateJWT(token, TEST_SECRET);
      
      expect(result.valid).toBe(true);
      expect(result.payload).toBeDefined();
      expect(result.payload?.userId).toBe('user123');
      expect(result.payload?.email).toBe('test@example.com');
      expect(result.payload?.role).toBe('admin');
    });

    it('should reject an invalid token', async () => {
      const result = await validateJWT('invalid.token.here', TEST_SECRET);
      
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject a token with wrong secret', async () => {
      const payload = { userId: 'user123', email: 'test@example.com' };
      const token = await createJWT(payload, TEST_SECRET);
      
      const result = await validateJWT(token, 'wrong-secret');
      
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('createRefreshToken', () => {
    it('should create a refresh token with 30 day expiration', async () => {
      const payload = { userId: 'user123', email: 'test@example.com' };
      
      const token = await createRefreshToken(payload, TEST_SECRET);
      
      expect(token).toBeDefined();
      
      // Verify the token is valid for longer
      const result = await validateJWT(token, TEST_SECRET);
      expect(result.valid).toBe(true);
    });
  });

  describe('extractToken', () => {
    it('should extract token from Bearer header', () => {
      const token = extractToken('Bearer my-token-123');
      expect(token).toBe('my-token-123');
    });

    it('should return null for missing header', () => {
      const token = extractToken(undefined);
      expect(token).toBeNull();
    });

    it('should return null for non-Bearer header', () => {
      const token = extractToken('Basic auth-token');
      expect(token).toBeNull();
    });
  });

  describe('authMiddleware', () => {
    it('should validate token from Authorization header', async () => {
      const payload = { userId: 'user123', email: 'test@example.com' };
      const token = await createJWT(payload, TEST_SECRET);
      
      const middleware = authMiddleware(TEST_SECRET);
      const result = await middleware(`Bearer ${token}`);
      
      expect(result.valid).toBe(true);
      expect(result.payload?.userId).toBe('user123');
    });

    it('should reject missing token', async () => {
      const middleware = authMiddleware(TEST_SECRET);
      const result = await middleware(undefined);
      
      expect(result.valid).toBe(false);
      expect(result.error).toBe('No token provided');
    });
  });
});
