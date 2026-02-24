"use strict";
/**
 * @xferops/auth-middleware
 *
 * Shared JWT validation middleware for XferOps apps.
 * Validates tokens against the shared AUTH_SECRET.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateJWT = validateJWT;
exports.createJWT = createJWT;
exports.createRefreshToken = createRefreshToken;
exports.extractToken = extractToken;
exports.authMiddleware = authMiddleware;
const jose_1 = require("jose");
/**
 * Convert our payload to jose's format
 */
function toJosePayload(payload) {
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
function fromJosePayload(payload) {
    return {
        userId: payload.sub,
        email: payload.email,
        role: payload.role,
        name: payload.name,
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
async function validateJWT(token, secret) {
    try {
        // Convert secret to Uint8Array
        const secretKey = new TextEncoder().encode(secret);
        // Verify the token
        const { payload } = await (0, jose_1.jwtVerify)(token, secretKey, {
            algorithms: ['HS256'],
        });
        // Convert jose payload to our format
        const jwtPayload = fromJosePayload(payload);
        return {
            valid: true,
            payload: jwtPayload,
        };
    }
    catch (error) {
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
async function createJWT(payload, secret, options = {}) {
    const secretKey = new TextEncoder().encode(secret);
    const jwt = new jose_1.SignJWT(toJosePayload(payload))
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setSubject(payload.userId);
    // Set expiration if provided
    if (options.expiresIn) {
        jwt.setExpirationTime(options.expiresIn);
    }
    else {
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
async function createRefreshToken(payload, secret) {
    return createJWT(payload, secret, { expiresIn: '30d' });
}
/**
 * Extract token from Authorization header
 * @param authHeader - The Authorization header value (e.g., "Bearer <token>")
 * @returns The token string, or null if not found
 */
function extractToken(authHeader) {
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
function authMiddleware(secret) {
    return async (authHeader) => {
        const token = extractToken(authHeader);
        if (!token) {
            return { valid: false, error: 'No token provided' };
        }
        return validateJWT(token, secret);
    };
}
exports.default = {
    validateJWT,
    createJWT,
    createRefreshToken,
    extractToken,
    authMiddleware
};
//# sourceMappingURL=index.js.map