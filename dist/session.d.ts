/**
 * @xferops/auth-middleware
 *
 * Session cookie management for XferOps apps.
 */
export interface SessionConfig {
    cookieName: string;
    secret: string;
    domain?: string;
    path?: string;
    secure?: boolean;
    sameSite?: 'lax' | 'strict' | 'none';
    httpOnly?: boolean;
    maxAge?: number;
    refreshThreshold?: number;
}
export interface SessionData {
    userId: string;
    email: string;
}
export interface SessionResult {
    valid: boolean;
    session?: SessionData;
    error?: string;
    shouldRefresh?: boolean;
}
/**
 * Create a session token (JWT) for the given identity.
 */
export declare function createSession(session: SessionData, config: SessionConfig): Promise<string>;
/**
 * Validate a session cookie value and return the session data.
 */
export declare function validateSession(cookieValue: string | undefined, config: SessionConfig): Promise<SessionResult>;
/**
 * Build the attributes portion of a Set-Cookie header.
 *
 * HttpOnly and Secure use bare-flag format (RFC 6265 §5.2) — NOT `HttpOnly=true`.
 * Using `HttpOnly=true` is incorrect per spec; many parsers treat it as an unknown
 * attribute name and silently drop the security flag.
 */
export declare function getCookieOptions(config: SessionConfig): string;
/**
 * Create a full Set-Cookie header string (async — uses real token).
 */
export declare function createSessionCookieString(session: SessionData, config: SessionConfig): Promise<string>;
/**
 * Create a Set-Cookie header that clears the session.
 */
export declare function createLogoutCookie(config: SessionConfig): string;
/**
 * Parse a Cookie request header into a key-value map.
 */
export declare function parseCookieHeader(cookieHeader: string | undefined): Record<string, string>;
/**
 * Extract and validate a session from a Cookie request header.
 */
export declare function getSessionFromHeader(cookieHeader: string | undefined, config: SessionConfig): Promise<SessionResult>;
/**
 * Default session config for XferOps apps.
 * Cookie name matches the access token issued by xferops-auth.
 */
export declare const defaultSessionConfig: SessionConfig;
declare const _default: {
    createSession: typeof createSession;
    validateSession: typeof validateSession;
    getCookieOptions: typeof getCookieOptions;
    createSessionCookieString: typeof createSessionCookieString;
    createLogoutCookie: typeof createLogoutCookie;
    parseCookieHeader: typeof parseCookieHeader;
    getSessionFromHeader: typeof getSessionFromHeader;
    defaultSessionConfig: SessionConfig;
};
export default _default;
//# sourceMappingURL=session.d.ts.map