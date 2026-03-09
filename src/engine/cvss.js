/**
 * CVSS v3.1 BASE SCORE ENGINE — Phase 4
 *
 * Implements the full CVSSv3.1 base score formula per FIRST specification:
 * https://www.first.org/cvss/v3.1/specification-document
 *
 * Scores are computed per-finding and attached to the threat object as:
 *   threat.cvss = { score: 8.1, rating: 'High', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' }
 */

// ── CVSSv3.1 Metric Values ─────────────────────────────────────────────────────

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 }; // Attack Vector
const AC = { L: 0.77, H: 0.44 };                     // Attack Complexity
const PR = {                                          // Privileges Required
    N: { U: 0.85, C: 0.85 },
    L: { U: 0.62, C: 0.68 },
    H: { U: 0.27, C: 0.50 },
};
const UI = { N: 0.85, R: 0.62 };                    // User Interaction
const C = { N: 0.00, L: 0.22, H: 0.56 };           // Confidentiality Impact
const I = { N: 0.00, L: 0.22, H: 0.56 };           // Integrity Impact
const A = { N: 0.00, L: 0.22, H: 0.56 };           // Availability Impact

/**
 * Compute CVSSv3.1 base score from vector components.
 *
 * @param {Object} v - Vector object with keys: AV, AC, PR, UI, S, C, I, A
 *   Each should be the standard letter code (e.g. AV:'N', AC:'L', S:'U', etc.)
 * @returns {{ score: number, rating: string, vector: string }}
 */
export function computeCVSS(v) {
    const scope = v.S || 'U';

    // Exploitability sub-score
    const prVal = PR[v.PR]?.[scope] ?? 0.85;
    const exploitability = 8.22 * (AV[v.AV] ?? 0.85) * (AC[v.AC] ?? 0.77) * prVal * (UI[v.UI] ?? 0.85);

    // Impact sub-score
    const ISCBase = 1 - (1 - (C[v.C] ?? 0)) * (1 - (I[v.I] ?? 0)) * (1 - (A[v.A] ?? 0));
    let impactSubScore;
    if (scope === 'U') {
        impactSubScore = 6.42 * ISCBase;
    } else {
        impactSubScore = 7.52 * (ISCBase - 0.029) - 3.25 * Math.pow(ISCBase - 0.02, 15);
    }

    // If impact is 0, score is 0
    if (impactSubScore <= 0) return { score: 0.0, rating: 'None', vector: buildVector(v) };

    // Base score
    let rawScore;
    if (scope === 'U') {
        rawScore = Math.min(impactSubScore + exploitability, 10);
    } else {
        rawScore = Math.min(1.08 * (impactSubScore + exploitability), 10);
    }

    const score = roundup(rawScore);
    return { score, rating: getRating(score), vector: buildVector(v) };
}

/** CVSSv3.1 Roundup: rounds up to nearest 0.1 */
function roundup(x) {
    const rounded = Math.round(x * 100000);
    if (rounded % 10000 === 0) return rounded / 100000;
    return (Math.floor(rounded / 10000) + 1) / 10;
}

/** Map score to qualitative rating */
export function getRating(score) {
    if (score === 0.0) return 'None';
    if (score <= 3.9) return 'Low';
    if (score <= 6.9) return 'Medium';
    if (score <= 8.9) return 'High';
    return 'Critical';
}

/** Build the canonical CVSS:3.1/AV:.../... vector string */
function buildVector(v) {
    return `CVSS:3.1/AV:${v.AV}/AC:${v.AC}/PR:${v.PR}/UI:${v.UI}/S:${v.S}/C:${v.C}/I:${v.I}/A:${v.A}`;
}

/**
 * CVSSv3.1 vector profiles per rule ID.
 *
 * Vectors are derived from the threat characteristics:
 *   AV = Attack Vector   (N=Network, A=Adjacent, L=Local, P=Physical)
 *   AC = Attack Complexity (L=Low, H=High)
 *   PR = Privileges Required (N=None, L=Low, H=High)
 *   UI = User Interaction (N=None, R=Required)
 *   S  = Scope (U=Unchanged, C=Changed)
 *   C  = Confidentiality (N=None, L=Low, H=High)
 *   I  = Integrity (N=None, L=Low, H=High)
 *   A  = Availability (N=None, L=Low, H=High)
 */
export const RULE_VECTORS = {
    // T-001: Missing WAF — external attacker can reach internal services directly
    'T-001': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'L', I: 'H', A: 'H' },  // 9.8 → CRITICAL

    // T-002: Unauthenticated API from untrusted node
    'T-002': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },  // 9.1 → CRITICAL

    // T-003: Unencrypted DB connection (adjacent attacker can eavesdrop)
    'T-003': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },  // 5.9 → Medium

    // T-004: PII over plaintext (network-level interception)
    'T-004': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },  // 5.9 → Medium

    // T-005: Attacker has active data flow path
    'T-005': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' },  // 10.0 → CRITICAL

    // T-006: No audit trail — enables repudiation (low complexity but low direct impact)
    'T-006': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },  // 5.4 → Medium

    // T-007: Unauthenticated cache (network reachable)
    'T-007': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },  // 8.2 → High

    // T-008: Public object storage (directly exposed)
    'T-008': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },  // 7.5 → High

    // T-009: Single point of failure — DoS
    'T-009': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'H' },  // 7.5 → High

    // T-010: Lateral movement to data store
    'T-010': { AV: 'N', AC: 'H', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' },  // 8.2 → High

    // T-011: HTTP on external channel (MITM — needs network position)
    'T-011': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },  // 7.4 → High

    // T-012: No centralized IdP (architectural weakness, not direct exploit)
    'T-012': { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'N' },  // 4.2 → Medium

    // T-013: Excessive trust boundary traversal
    'T-013': { AV: 'N', AC: 'H', PR: 'L', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' },  // 8.2 → High

    // T-014: Sensitive data flows to low-trust node (direct disclosure)
    'T-014': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },  // 7.5 → High

    // T-015: Cyclic dependency — availability impact only
    'T-015': { AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'H' },  // 6.5 → Medium

    // T-016: Missing rate limiting on auth endpoint (brute force)
    'T-016': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'L' },  // 8.3 → High

    // T-017: Uncontrolled external dependency ingress (supply chain)
    'T-017': { AV: 'N', AC: 'H', PR: 'N', UI: 'R', S: 'C', C: 'H', I: 'H', A: 'H' },  // 8.3 → High

    // T-018: Missing data classification (architectural gap — medium risk)
    'T-018': { AV: 'N', AC: 'H', PR: 'L', UI: 'N', S: 'U', C: 'L', I: 'N', A: 'N' },  // 3.1 → Low

    // T-019: Deprecated TLS (known CVE exposure — POODLE/CRIME)
    'T-019': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },  // 7.4 → High

    // T-020: Weak auth method (Basic Auth)
    'T-020': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },  // 6.5 → Medium

    // T-021: Protocol outside allowed zone (SQL/Redis on internet)
    'T-021': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' },  // 9.8 → CRITICAL

    // R-001: Broken authentication (OWASP A07)
    'R-001': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },  // 9.1 → CRITICAL

    // R-002: Unencrypted database (OWASP A02)
    'R-002': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },  // 5.9 → Medium

    // R-003: Man-in-the-Middle (OWASP A02)
    'R-003': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'N' },  // 7.4 → High

    // R-004: Plaintext sensitive data (OWASP A02)
    'R-004': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' },  // 5.9 → Medium

    // R-005: Unauthorized data access (OWASP A01)
    'R-005': { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'N' },  // 8.2 → High

    // R-006: Privilege escalation path — full DB compromise (OWASP A01)
    'R-006': { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H' },  // 9.0 → CRITICAL
};

/**
 * Score a single threat object.
 * Returns the threat with .cvss attached.
 * Falls back to a severity-based default if no vector profile exists.
 */
export function scoreThreat(threat) {
    const vector = RULE_VECTORS[threat.id];
    if (vector) {
        threat.cvss = computeCVSS(vector);
    } else {
        // Fallback: derive a coarse score from qualitative severity
        const fallbackScores = { critical: 9.0, high: 7.5, medium: 5.0, low: 2.0 };
        const score = fallbackScores[threat.sev] ?? 5.0;
        threat.cvss = { score, rating: getRating(score), vector: 'N/A' };
    }
    return threat;
}

/**
 * Returns color for a CVSS score value (using standard color coding).
 */
export function cvssColor(score) {
    if (score >= 9.0) return '#ef4444'; // Critical — red
    if (score >= 7.0) return '#f97316'; // High — orange
    if (score >= 4.0) return '#facc15'; // Medium — yellow
    if (score > 0) return '#34d399'; // Low — green
    return '#6b7280';                   // None — gray
}
