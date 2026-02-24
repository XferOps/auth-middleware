/**
 * @xferops/auth-middleware
 *
 * Shared JWT validation middleware for XferOps apps.
 * Validates tokens against the shared AUTH_SECRET.
 */
export interface JWTPayload {
    userId: string;
    email: string;
    role?: string;
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
    expiresIn?: string;
}
/**
 * Validate a JWT token
 * @param token - The JWT token string (without "Bearer " prefix)
 * @param secret - The shared AUTH_SECRET (base64 encoded)
 * @returns ValidationResult with payload if valid
 */
export declare function validateJWT(token: string, secret: string): Promise<ValidationResult>;
/**
 * Create a JWT token
 * @param payload - The payload to encode
 * @param secret - The shared AUTH_SECRET
 * @param options - Options including expiration
 * @returns The JWT token string
 */
export declare function createJWT(payload: JWTPayload, secret: string, options?: CreateTokenOptions): Promise<string>;
/**
 * Create a refresh token (longer expiration)
 * @param payload - The payload to encode
 * @param secret - The shared AUTH_SECRET
 * @returns The refresh token string (30 day expiration)
 */
export declare function createRefreshToken(payload: JWTPayload, secret: string): Promise<string>;
/**
 * Extract token from Authorization header
 * @param authHeader - The Authorization header value (e.g., "Bearer <token>")
 * @returns The token string, or null if not found
 */
export declare function extractToken(authHeader: string | undefined): string | null;
/**
 * Middleware factory for validating JWT in HTTP requests
 * @param secret - The shared AUTH_SECRET
 * @returns Middleware function
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