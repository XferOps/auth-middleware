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
/**
 * Issuer and audience for all XferOps JWTs.
 * Must match the values set by xferops-auth (src/lib/tokens.ts).
 */
export declare const JWT_ISSUER = "auth.xferops.dev";
export declare const JWT_AUDIENCE = "xferops";
/**
 * Shared role levels for all XferOps apps.
 *
 * This is a type contract only — no runtime permission logic lives here.
 * Each app maintains its own role assignments in its own database and
 * resolves the role for a given userId after validating the JWT.
 *
 * The auth service (xferops-auth) does NOT store or issue roles in JWTs.
 */
export declare enum AppRole {
    ADMIN = "ADMIN",
    MANAGER = "MANAGER",
    MEMBER = "MEMBER",
    VIEWER = "VIEWER"
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
    expiresIn?: string;
}
/**
 * Validate a JWT token.
 *
 * Enforces iss=auth.xferops.dev and aud=xferops so tokens from other sources
 * or with different audience claims are rejected even if the secret matches.
 *
 * @param token  - The JWT string (without "Bearer " prefix)
 * @param secret - The shared AUTH_SECRET
 */
export declare function validateJWT(token: string, secret: string): Promise<ValidationResult>;
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
export declare function createJWT(payload: JWTPayload, secret: string, options?: CreateTokenOptions): Promise<string>;
/**
 * Create a refresh token (30-day expiration).
 */
export declare function createRefreshToken(payload: JWTPayload, secret: string): Promise<string>;
/**
 * Extract token from an Authorization header.
 *
 * @param authHeader - "Bearer <token>" string
 * @returns The token string, or null if missing/malformed
 */
export declare function extractToken(authHeader: string | undefined): string | null;
/**
 * Middleware factory for validating JWTs from Authorization headers.
 */
export declare function authMiddleware(secret: string): (authHeader: string | undefined) => Promise<ValidationResult>;
export * from './session.js';
declare const _default: {
    validateJWT: typeof validateJWT;
    createJWT: typeof createJWT;
    createRefreshToken: typeof createRefreshToken;
    extractToken: typeof extractToken;
    authMiddleware: typeof authMiddleware;
};
export default _default;
//# sourceMappingURL=index.d.ts.map