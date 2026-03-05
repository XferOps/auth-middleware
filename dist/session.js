"use strict";
/**
 * @xferops/auth-middleware
 *
 * Session cookie management for XferOps apps.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.defaultSessionConfig = void 0;
exports.createSession = createSession;
exports.validateSession = validateSession;
exports.getCookieOptions = getCookieOptions;
exports.createSessionCookieString = createSessionCookieString;
exports.createLogoutCookie = createLogoutCookie;
exports.parseCookieHeader = parseCookieHeader;
exports.getSessionFromHeader = getSessionFromHeader;
const index_js_1 = require("./index.js");
// ─── Session create / validate ───────────────────────────────────────────────
/**
 * Create a session token (JWT) for the given identity.
 */
async function createSession(session, config) {
    const payload = {
        userId: session.userId,
        email: session.email,
    };
    return (0, index_js_1.createJWT)(payload, config.secret, {
        expiresIn: config.maxAge ? `${config.maxAge}s` : undefined,
    });
}
/**
 * Validate a session cookie value and return the session data.
 */
async function validateSession(cookieValue, config) {
    if (!cookieValue) {
        return { valid: false, error: 'No session cookie' };
    }
    const result = await (0, index_js_1.validateJWT)(cookieValue, config.secret);
    if (!result.valid || !result.payload) {
        return { valid: false, error: result.error };
    }
    let shouldRefresh = false;
    if (config.refreshThreshold && result.payload.exp) {
        const now = Math.floor(Date.now() / 1000);
        shouldRefresh = result.payload.exp - now < config.refreshThreshold;
    }
    return {
        valid: true,
        session: {
            userId: result.payload.userId,
            email: result.payload.email,
        },
        shouldRefresh,
    };
}
// ─── Cookie helpers ──────────────────────────────────────────────────────────
/**
 * Build the attributes portion of a Set-Cookie header.
 *
 * HttpOnly and Secure use bare-flag format (RFC 6265 §5.2) — NOT `HttpOnly=true`.
 * Using `HttpOnly=true` is incorrect per spec; many parsers treat it as an unknown
 * attribute name and silently drop the security flag.
 */
function getCookieOptions(config) {
    const parts = [`Path=${config.path ?? '/'}`];
    if (config.secure !== false)
        parts.push('Secure');
    if (config.httpOnly !== false)
        parts.push('HttpOnly');
    parts.push(`SameSite=${config.sameSite ?? 'lax'}`);
    if (config.domain)
        parts.push(`Domain=${config.domain}`);
    if (config.maxAge)
        parts.push(`Max-Age=${config.maxAge}`);
    return parts.join('; ');
}
/**
 * Create a full Set-Cookie header string (async — uses real token).
 */
async function createSessionCookieString(session, config) {
    const token = await createSession(session, config);
    return `${config.cookieName}=${token}; ${getCookieOptions(config)}`;
}
/**
 * Create a Set-Cookie header that clears the session.
 */
function createLogoutCookie(config) {
    return `${config.cookieName}=; ${getCookieOptions(config)}; Max-Age=0`;
}
// ─── Removed: createSessionCookie (sync stub) ───────────────────────────────
// The old sync createSessionCookie() returned a literal "<token>" placeholder —
// callers who used it got a broken cookie that silently failed auth.
// Use createSessionCookieString() (async) instead.
// ─── Cookie parsing ──────────────────────────────────────────────────────────
/**
 * Parse a Cookie request header into a key-value map.
 */
function parseCookieHeader(cookieHeader) {
    if (!cookieHeader)
        return {};
    const cookies = {};
    cookieHeader.split(';').forEach((pair) => {
        const [name, ...rest] = pair.split('=');
        if (name)
            cookies[name.trim()] = rest.join('=').trim();
    });
    return cookies;
}
/**
 * Extract and validate a session from a Cookie request header.
 */
function getSessionFromHeader(cookieHeader, config) {
    const cookies = parseCookieHeader(cookieHeader);
    return validateSession(cookies[config.cookieName], config);
}
// ─── Default config ──────────────────────────────────────────────────────────
/**
 * Default session config for XferOps apps.
 * Cookie name matches the access token issued by xferops-auth.
 */
exports.defaultSessionConfig = {
    cookieName: '__Secure-xferops.access-token',
    secret: process.env.AUTH_SECRET ?? '',
    path: '/',
    secure: true,
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 60 * 15, // 15 minutes (access token TTL)
    refreshThreshold: 60 * 5, // refresh when <5 min remaining
};
exports.default = {
    createSession,
    validateSession,
    getCookieOptions,
    createSessionCookieString,
    createLogoutCookie,
    parseCookieHeader,
    getSessionFromHeader,
    defaultSessionConfig: exports.defaultSessionConfig,
};
//# sourceMappingURL=session.js.map