/**
 * @xferops/auth-middleware
 * 
 * Shared JWT validation middleware for XferOps apps.
 * Validates tokens against the shared AUTH_SECRET.
 */

import { jwtVerify, SignJWT, JWTPayload as JoseJWTPayload } from 'jose';

/**
 * Shared role levels for all XferOps apps.
 *
 * This is a type contract only — no runtime permission logic lives here.
 * Each app maintains its own role assignments in its own database and
 * resolves the role for a given userId after validating the JWT.
 *
 * The auth service (xferops-auth) does NOT store or issue roles.
 * JWTs carry identity only (sub, email) — never role claims.
 */
export enum AppRole {
  ADMIN = 'ADMIN',
  MANAGER = 'MANAGER',
  MEMBER = 'MEMBER',
  VIEWER = 'VIEWER',
}

export interface JWTPayload {
  userId: string;
  email: string;
  /**
   * @deprecated Roles are not included in XferOps JWTs as of v0.1.
   * Each app resolves permissions from its own database using AppRole.
   */
  role?: string;
  /**
   * @deprecated Name is not included in XferOps JWTs as of v0.1.
   */
  name?: string;
  exp?: number;
  iat?: number;
}

export interface ValidationResult {
  valid: boolean;
  payload?: JWTPayload;
  error?: string;
}

export interface CreateTokenOptions {
  expiresIn?: string; // e.g., "1h", "7d", "30d"
}

/**
 * Convert our payload to jose's format
 */
function toJosePayload(payload: JWTPayload): JoseJWTPayload {
  return {
    sub: payload.userId,
    email: payload.email,
    role: payload.role,
    name: payload.name,
  };
}

/**
 * Convert jose payload to our format
 */
function fromJosePayload(payload: JoseJWTPayload): JWTPayload {
  return {
    userId: payload.sub as string,
    email: payload.email as string,
    role: payload.role as string | undefined,
    name: payload.name as string | undefined,
    exp: payload.exp,
    iat: payload.iat,
  };
}

/**
 * Validate a JWT token
 * @param token - The JWT token string (without "Bearer " prefix)
 * @param secret - The shared AUTH_SECRET (base64 encoded)
 * @returns ValidationResult with payload if valid
 */
export async function validateJWT(token: string, secret: string): Promise<ValidationResult> {
  try {
    // Convert secret to Uint8Array
    const secretKey = new TextEncoder().encode(secret);

    // Verify the token
    const { payload } = await jwtVerify(token, secretKey, {
      algorithms: ['HS256'],
    });

    // Convert jose payload to our format
    const jwtPayload = fromJosePayload(payload);

    return {
      valid: true,
      payload: jwtPayload,
    };
  } catch (error) {
    // Determine the error type
    if (error instanceof Error) {
      if (error.message.includes('JWT expired')) {
        return { valid: false, error: 'Token has expired' };
      }
      if (error.message.includes('invalid')) {
        return { valid: false, error: 'Invalid token' };
      }
      return { valid: false, error: error.message };
    }
    return { valid: false, error: 'Unknown validation error' };
  }
}

/**
 * Create a JWT token
 * @param payload - The payload to encode
 * @param secret - The shared AUTH_SECRET
 * @param options - Options including expiration
 * @returns The JWT token string
 */
export async function createJWT(
  payload: JWTPayload, 
  secret: string, 
  options: CreateTokenOptions = {}
): Promise<string> {
  const secretKey = new TextEncoder().encode(secret);
  
  const jwt = new SignJWT(toJosePayload(payload))
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setSubject(payload.userId);

  // Set expiration if provided
  if (options.expiresIn) {
    jwt.setExpirationTime(options.expiresIn);
  } else {
    // Default: 24 hours
    jwt.setExpirationTime('24h');
  }

  return jwt.sign(secretKey);
}

/**
 * Create a refresh token (longer expiration)
 * @param payload - The payload to encode
 * @param secret - The shared AUTH_SECRET
 * @returns The refresh token string (30 day expiration)
 */
export async function createRefreshToken(
  payload: JWTPayload, 
  secret: string
): Promise<string> {
  return createJWT(payload, secret, { expiresIn: '30d' });
}

/**
 * Extract token from Authorization header
 * @param authHeader - The Authorization header value (e.g., "Bearer <token>")
 * @returns The token string, or null if not found
 */
export function extractToken(authHeader: string | undefined): string | null {
  if (!authHeader) {
    return null;
  }
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }
  
  return parts[1];
}

/**
 * Middleware factory for validating JWT in HTTP requests
 * @param secret - The shared AUTH_SECRET
 * @returns Middleware function
 */
export function authMiddleware(secret: string) {
  return async (authHeader: string | undefined): Promise<ValidationResult> => {
    const token = extractToken(authHeader);
    
    if (!token) {
      return { valid: false, error: 'No token provided' };
    }
    
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
