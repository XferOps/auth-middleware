"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppRole = exports.JWT_AUDIENCE = exports.JWT_ISSUER = void 0;
exports.validateJWT = validateJWT;
exports.createJWT = createJWT;
exports.createRefreshToken = createRefreshToken;
exports.extractToken = extractToken;
exports.authMiddleware = authMiddleware;
const jose_1 = require("jose");
// ─── Constants ──────────────────────────────────────────────────────────────
/**
 * Issuer and audience for all XferOps JWTs.
 * Must match the values set by xferops-auth (src/lib/tokens.ts).
 */
exports.JWT_ISSUER = 'auth.xferops.dev';
exports.JWT_AUDIENCE = 'xferops';
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
var AppRole;
(function (AppRole) {
    AppRole["ADMIN"] = "ADMIN";
    AppRole["MANAGER"] = "MANAGER";
    AppRole["MEMBER"] = "MEMBER";
    AppRole["VIEWER"] = "VIEWER";
})(AppRole || (exports.AppRole = AppRole = {}));
// ─── Internal helpers ────────────────────────────────────────────────────────
function toJosePayload(payload) {
    // v0.1: JWTs carry identity only — sub + email.
    // role and name are intentionally excluded; apps resolve them locally.
    return {
        sub: payload.userId,
        email: payload.email,
    };
}
function fromJosePayload(payload) {
    return {
        userId: payload.sub,
        email: payload.email,
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
async function validateJWT(token, secret) {
    try {
        const secretKey = new TextEncoder().encode(secret);
        const { payload } = await (0, jose_1.jwtVerify)(token, secretKey, {
            algorithms: ['HS256'],
            issuer: exports.JWT_ISSUER,
            audience: exports.JWT_AUDIENCE,
        });
        return {
            valid: true,
            payload: fromJosePayload(payload),
        };
    }
    catch (error) {
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
async function createJWT(payload, secret, options = {}) {
    const secretKey = new TextEncoder().encode(secret);
    return new jose_1.SignJWT(toJosePayload(payload))
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setSubject(payload.userId)
        .setIssuer(exports.JWT_ISSUER)
        .setAudience(exports.JWT_AUDIENCE)
        .setExpirationTime(options.expiresIn ?? DEFAULT_ACCESS_TTL)
        .sign(secretKey);
}
/**
 * Create a refresh token (30-day expiration).
 */
async function createRefreshToken(payload, secret) {
    return createJWT(payload, secret, { expiresIn: '30d' });
}
/**
 * Extract token from an Authorization header.
 *
 * @param authHeader - "Bearer <token>" string
 * @returns The token string, or null if missing/malformed
 */
function extractToken(authHeader) {
    if (!authHeader)
        return null;
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer')
        return null;
    return parts[1];
}
/**
 * Middleware factory for validating JWTs from Authorization headers.
 */
function authMiddleware(secret) {
    return async (authHeader) => {
        const token = extractToken(authHeader);
        if (!token)
            return { valid: false, error: 'No token provided' };
        return validateJWT(token, secret);
    };
}
// Re-export session utilities
__exportStar(require("./session.js"), exports);
exports.default = {
    validateJWT,
    createJWT,
    createRefreshToken,
    extractToken,
    authMiddleware,
};
//# sourceMappingURL=index.js.map