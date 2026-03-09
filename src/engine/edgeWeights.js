/**
 * EDGE WEIGHTS — Phase 2
 *
 * Numerical strength scores for authentication and encryption options.
 * Rules check against thresholds rather than binary === 'None'.
 *
 * Auth scale  : 0 = no auth → 6 = strongest mutual-certificate auth
 * Enc  scale  : 0 = plaintext → 4 = TLS 1.3 (best current standard)
 */

// ── Authentication Strength ───────────────────────────────────────────────────
export const AUTH_STRENGTH = {
    'None': 0,   // No auth — always flag CRITICAL
    'Basic Auth': 1,   // Base64 credential in header — easily decoded, flag HIGH
    'API Key': 2,   // Shared secret — static, no user identity, flag MEDIUM on sensitive data
    'JWT': 3,   // Signed token — stateless, good
    'OAuth2': 4,   // Delegated auth — good for user-facing flows
    'IAM Role': 5,   // Cloud-native identity — strong
    'mTLS': 6,   // Mutual certificate — strongest, service-mesh grade
};

// Threshold helpers
export const AUTH_THRESHOLD_CRITICAL = 0;  // authStr === 0 → CRITICAL (no auth)
export const AUTH_THRESHOLD_WEAK = 1;  // authStr === 1 → HIGH (Basic Auth)
export const AUTH_THRESHOLD_ADEQUATE = 3;  // authStr >= 3 → acceptable for most flows

/** Returns true if the auth value means "no authentication at all" */
export function hasNoAuth(authValue) {
    return (AUTH_STRENGTH[authValue] ?? 0) === AUTH_THRESHOLD_CRITICAL;
}

/** Returns true if auth is present but weak (Basic Auth only) */
export function hasWeakAuth(authValue) {
    return (AUTH_STRENGTH[authValue] ?? 0) === AUTH_THRESHOLD_WEAK;
}

/** Returns true if auth is acceptable (JWT / OAuth2 / IAM / mTLS) */
export function hasAdequateAuth(authValue) {
    return (AUTH_STRENGTH[authValue] ?? 0) >= AUTH_THRESHOLD_ADEQUATE;
}

// ── Encryption Strength ───────────────────────────────────────────────────────
export const ENCRYPTION_STRENGTH = {
    'None': 0,   // Plaintext — always flag CRITICAL
    'TLS 1.0/1.1': 1,   // Deprecated — POODLE/BEAST — flag HIGH
    'TLS 1.2 (weak ciphers)': 2, // Acceptable minimum but non-FS ciphers — flag MEDIUM
    'TLS 1.2 (strong)': 3,   // Good — flag nothing
    'TLS 1.3': 4,   // Best — modern AEAD cipher suites
};

export const ENC_THRESHOLD_NONE = 0;  // encStr === 0 → CRITICAL
export const ENC_THRESHOLD_DEPRECATED = 1;  // encStr === 1 → HIGH (deprecated TLS)
export const ENC_THRESHOLD_ADEQUATE = 3;  // encStr >= 3 → acceptable

/** Returns true if the encryption value means "no encryption" */
export function hasNoEncryption(encValue) {
    return (ENCRYPTION_STRENGTH[encValue] ?? 0) === ENC_THRESHOLD_NONE;
}

/** Returns true if encryption is deprecated (TLS 1.0/1.1) */
export function hasDeprecatedTLS(encValue) {
    return (ENCRYPTION_STRENGTH[encValue] ?? 0) === ENC_THRESHOLD_DEPRECATED;
}

/** Returns true if encryption meets the minimum acceptable bar */
export function hasAdequateEncryption(encValue) {
    return (ENCRYPTION_STRENGTH[encValue] ?? 0) >= ENC_THRESHOLD_ADEQUATE;
}

/**
 * Returns a human-readable label for an auth value with its strength score.
 * Used in the edge editor UI to show strength visually.
 */
export function authStrengthLabel(authValue) {
    const str = AUTH_STRENGTH[authValue] ?? 0;
    const labels = ['⛔ None', '⚠️ Weak', '⚠️ Low', '✓ Acceptable', '✓ Good', '✓ Strong', '✓ Strongest'];
    return `${authValue} — ${labels[str] ?? '?'}`;
}

/**
 * Returns a human-readable label for an encryption value.
 */
export function encStrengthLabel(encValue) {
    const str = ENCRYPTION_STRENGTH[encValue] ?? 0;
    const labels = ['⛔ None', '⚠️ Deprecated', '⚠️ Weak ciphers', '✓ Good', '✓ Best'];
    return `${encValue} — ${labels[str] ?? '?'}`;
}
