/**
 * PROTOCOL POLICY — Phase 3
 *
 * Defines security constraints for each protocol based on where it is used.
 * Rules evaluate context (source/destination trust zone, encryption, auth)
 * rather than just the binary presence of security controls.
 *
 * Trust zone ordering (higher = more trusted / more isolated):
 *   internet (0) → dmz (1) → internal (2) → restricted (3)
 */

export const TRUST_ZONE_RANK = {
    internet: 0,
    dmz: 1,
    internal: 2,
    restricted: 3,
};

/**
 * Protocol policy map.
 *
 * Each entry defines:
 *   allowedZones   {string[]}  - Trust zones where this protocol is safe.
 *                               If either endpoint is OUTSIDE this set, flag.
 *   requiresAuth   {boolean}   - true = auth must be present (strength >= 1).
 *   requiresEncryption {boolean} - true = encryption must be present (strength >= 1).
 *   externalSeverity {string}  - severity to use when the protocol appears on
 *                               an edge that exits its allowed zones.
 *   reason         {string}    - Short human explanation of why the protocol
 *                               is restricted to certain zones.
 *
 * Protocols NOT in this map are treated as unrestricted (no zone policy applied).
 */
export const PROTOCOL_POLICY = {
    // ── Database protocols — must NEVER appear on internet/dmz-facing edges ──
    'SQL': {
        allowedZones: ['internal', 'restricted'],
        requiresAuth: true,
        requiresEncryption: true,
        externalSeverity: 'critical',
        reason: 'SQL protocol is designed for trusted internal use only. Direct SQL exposure enables injection attacks, bulk data dumps, and schema enumeration.',
    },
    'Redis': {
        allowedZones: ['internal', 'restricted'],
        requiresAuth: false,   // Redis AUTH is optional inside restricted nets
        requiresEncryption: false,
        externalSeverity: 'critical',
        reason: 'Redis has no authentication by default and is designed for trusted internal networks. Exposure beyond the internal zone is a critical misconfiguration (cf. Equifax 2017 pattern).',
    },

    // ── Messaging protocols — internal/DMZ only ──────────────────────────────
    'AMQP': {
        allowedZones: ['internal', 'dmz'],
        requiresAuth: true,
        requiresEncryption: true,
        externalSeverity: 'high',
        reason: 'AMQP (RabbitMQ/ActiveMQ) carries internal event streams and should not be directly reachable from the internet.',
    },

    // ── gRPC — internal preferred, but DMZ acceptable with encryption ─────────
    'gRPC': {
        allowedZones: ['internal', 'dmz', 'restricted'],
        requiresAuth: false,
        requiresEncryption: true,   // gRPC without TLS is a common footgun
        externalSeverity: 'high',
        reason: 'gRPC without TLS transmits protobuf as plaintext. When used across trust zones always require TLS.',
    },

    // ── S3/Object storage API — internal/restricted only ─────────────────────
    'S3': {
        allowedZones: ['internal', 'restricted'],
        requiresAuth: true,
        requiresEncryption: true,
        externalSeverity: 'high',
        reason: 'Object storage APIs should be accessed via signed URLs or internal IAM roles, not exposed directly to internet-facing services without a proxy.',
    },

    // ── HTTP — warn for external-facing, only flag clearly external ones ──────
    'HTTP': {
        allowedZones: ['internal'],   // internal east-west is acceptable (LOW)
        requiresAuth: false,
        requiresEncryption: false,
        externalSeverity: 'high',         // used by T-011 override below
        reason: 'HTTP transmits data in plaintext. For internet-facing connections this enables MITM attacks, credential theft, and session hijacking.',
    },
};

/**
 * Returns the effective trust zone of a node, checking multiple possible fields.
 * Handles both the trustZone field (set by componentDefs) and the zone field.
 */
export function getNodeTrustZone(node) {
    if (!node) return 'internal';
    return node.trustZone || node.zone || 'internal';
}

/**
 * Returns true if a trust zone is "outside" the allowed set for a protocol,
 * meaning the connection crosses into a zone where the protocol is unsafe.
 */
export function isZoneViolation(zone, allowedZones) {
    return !allowedZones.includes(zone);
}

/**
 * Returns the severity for a protocol/zone mismatch based on which zone is involved.
 * External zones (internet) are always more severe than DMZ violations.
 */
export function getViolationSeverity(zone, policy) {
    if (zone === 'internet') return 'critical';
    if (zone === 'dmz') return policy.externalSeverity === 'critical' ? 'high' : policy.externalSeverity;
    return 'medium';
}
