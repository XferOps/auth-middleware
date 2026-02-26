/**
 * @xferops/auth-middleware
 *
 * Shared JWT validation middleware for XferOps apps.
 * Validates tokens against the shared AUTH_SECRET.
 *
 * v0.1 architecture contract:
 *   - All tokens are issued by auth.xferops.dev (JWT_ISSUER)
 *   - All tokens carry audience "xferops" (JWT_AUDIENCE)
 *   - JWTs carry identity only (sub, email) — never role or name claims
 *   - Apps resolve permissions from their own databases using AppRole
 */

import { jwtVerify, SignJWT, JWTPayload as JoseJWTPayload } from 'jose';

// ─── Constants ──────────────────────────────────────────────────────────────

/**
 * Issuer and audience for all XferOps JWTs.
 * Must match the values set by xferops-auth (src/lib/tokens.ts).
 */
export const JWT_ISSUER  = 'auth.xferops.dev';
export const JWT_AUDIENCE = 'xferops';

/**
 * Default access token TTL — 15 minutes.
 * Short window limits damage from a stolen token.
 */
const DEFAULT_ACCESS_TTL = '15m';

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * Shared role levels for all XferOps apps.
 *
 * This is a type contract only — no runtime permission logic lives here.
 * Each app maintains its own role assignments in its own database and
 * resolves the role for a given userId after validating the JWT.
 *
 * The auth service (xferops-auth) does NOT store or issue roles in JWTs.
 */
export enum AppRole {
  ADMIN   = 'ADMIN',
  MANAGER = 'MANAGER',
  MEMBER  = 'MEMBER',
  VIEWER  = 'VIEWER',
}

export interface JWTPayload {
  userId: string;
  email: string;
  exp?: number;
  iat?: number;
}

export interface ValidationResult {
  valid: boolean;
  payload?: JWTPayload;
  error?: string;
}

export interface CreateTokenOptions {
  expiresIn?: string; // e.g., "15m", "7d", "30d"
}

// ─── Internal helpers ────────────────────────────────────────────────────────

function toJosePayload(payload: JWTPayload): JoseJWTPayload {
  // v0.1: JWTs carry identity only — sub + email.
  // role and name are intentionally excluded; apps resolve them locally.
  return {
    sub: payload.userId,
    email: payload.email,
  };
}

function fromJosePayload(payload: JoseJWTPayload): JWTPayload {
  return {
    userId: payload.sub as string,
    email: payload.email as string,
    exp: payload.exp,
    iat: payload.iat,
  };
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Validate a JWT token.
 *
 * Enforces iss=auth.xferops.dev and aud=xferops so tokens from other sources
 * or with different audience claims are rejected even if the secret matches.
 *
 * @param token  - The JWT string (without "Bearer " prefix)
 * @param secret - The shared AUTH_SECRET
 */
export async function validateJWT(token: string, secret: string): Promise<ValidationResult> {
  try {
    const secretKey = new TextEncoder().encode(secret);

    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ['HS256'],
      issuer:     JWT_ISSUER,
      audience:   JWT_AUDIENCE,
    });

    return {
      valid: true,
      payload: fromJosePayload(payload),
    };
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('JWT expired')) {
        return { valid: false, error: 'Token has expired' };
      }
      return { valid: false, error: 'Invalid token' };
    }
    return { valid: false, error: 'Unknown validation error' };
  }
}

/**
 * Create a signed JWT token.
 *
 * Sets iss=auth.xferops.dev and aud=xferops on every token.
 * Default TTL is 15 minutes (access token standard).
 *
 * @param payload  - Identity payload (userId + email only — no roles)
 * @param secret   - The shared AUTH_SECRET
 * @param options  - Optional override for expiresIn
 */
export async function createJWT(
  payload: JWTPayload,
  secret: string,
  options: CreateTokenOptions = {},
): Promise<string> {
  const secretKey = new TextEncoder().encode(secret);

  return new SignJWT(toJosePayload(payload))
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setSubject(payload.userId)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setExpirationTime(options.expiresIn ?? DEFAULT_ACCESS_TTL)
    .sign(secretKey);
}

/**
 * Create a refresh token (30-day expiration).
 */
export async function createRefreshToken(
  payload: JWTPayload,
  secret: string,
): Promise<string> {
  return createJWT(payload, secret, { expiresIn: '30d' });
}

/**
 * Extract token from an Authorization header.
 *
 * @param authHeader - "Bearer <token>" string
 * @returns The token string, or null if missing/malformed
 */
export function extractToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null;
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null;
  return parts[1];
}

/**
 * Middleware factory for validating JWTs from Authorization headers.
 */
export function authMiddleware(secret: string) {
  return async (authHeader: string | undefined): Promise<ValidationResult> => {
    const token = extractToken(authHeader);
    if (!token) return { valid: false, error: 'No token provided' };
    return validateJWT(token, secret);
  };
}

// Re-export session utilities
export * from './session.js';

export default {
  validateJWT,
  createJWT,
  createRefreshToken,
  extractToken,
  authMiddleware,
};
