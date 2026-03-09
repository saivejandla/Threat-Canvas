/**
 * THREAT DEDUPLICATION ENGINE  (Phase 1)
 *
 * S.threats = raw rule outputs — untouched, used for pills, badges, exports.
 * S.findings = deduplicated user-facing list returned by this module.
 *
 * Strategy
 * ---------
 * 1. Define dedup groups: sets of rule IDs that describe the same root cause.
 * 2. For each group, keep only the HIGHEST-severity threat as the PRIMARY finding.
 * 3. Demote the rest to `primary.evidence[]` (still shown in UI, but collapsed).
 * 4. Any threat not in any group passes through as-is (unique finding).
 * 5. Merge `affected` node arrays across all members of the group so the
 *    primary finding highlights all relevant nodes.
 */

/**
 * Groups of rule IDs that share the same root cause.
 * Key  = human-readable label for the group.
 * Value = array of rule-ID prefixes/exact IDs that belong together.
 *
 * Order within each group doesn't matter — we pick the highest severity anyway.
 */
const DEDUP_GROUPS = [
    {
        key: 'PLAINTEXT_CHANNEL',
        label: 'Plaintext / Unencrypted Channel',
        ids: ['T-003', 'T-004', 'T-011', 'T-019', 'R-002', 'R-003', 'R-004'],
    },
    {
        key: 'MISSING_AUTH',
        label: 'Missing or Broken Authentication',
        ids: ['T-002', 'T-020', 'R-001', 'R-005'],
    },
    {
        key: 'ACTIVE_ATTACK_PATH',
        label: 'Active Attack / Privilege Escalation Path',
        ids: ['T-005', 'R-006', 'PR-001', 'PR-002'],
    },
    {
        key: 'TRUST_BOUNDARY',
        label: 'Insecure Trust Boundary Crossing',
        // BV-* IDs are dynamic — matched by prefix below
        ids: ['T-013', 'BV-'],
    },
    {
        key: 'LATERAL_MOVEMENT',
        label: 'Lateral Movement to Data Store',
        ids: ['T-010', 'T-013'],
    },
    {
        key: 'PROTOCOL_ZONE_MISMATCH',
        label: 'Protocol / Trust Zone Mismatch',
        ids: ['T-021'],   // standalone — protocol violations get a dedicated card
    },
];

// Severity ordering (higher index = higher severity)
const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Returns true if `threatId` belongs to `group`.
 * Supports exact match AND prefix match (for BV-* etc).
 */
function matchesGroup(threatId, group) {
    return group.ids.some(pattern =>
        pattern.endsWith('-')
            ? threatId.startsWith(pattern)          // prefix match e.g. 'BV-'
            : threatId === pattern                  // exact match
    );
}

/**
 * Main deduplication function.
 * @param {ThreatObject[]} rawThreats - S.threats array after runAnalysis()
 * @returns {FindingObject[]} - deduplicated list for the UI
 */
export function deduplicateThreats(rawThreats) {
    if (!rawThreats || !rawThreats.length) return [];

    const assigned = new Set();   // threat IDs already merged
    const findings = [];

    // ── Pass 1: Process each dedup group ─────────────────────────────────────
    for (const group of DEDUP_GROUPS) {
        const members = rawThreats.filter(t =>
            !assigned.has(t.id) && matchesGroup(t.id, group)
        );
        if (!members.length) continue;

        // Pick the highest-severity member as primary
        const primary = [...members].sort(
            (a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev]
        )[0];

        const evidence = members.filter(t => t.id !== primary.id);

        // Merge all affected nodes from the group
        const mergedAffected = [...new Set(
            members.flatMap(t => t.affected || [])
        )];
        const mergedLocationNames = [...new Set(
            members.flatMap(t => t.locationNames || [])
        )];

        findings.push({
            ...primary,
            affected: mergedAffected,
            locationNames: mergedLocationNames,
            evidence,                       // corroborating rules
            dedupGroup: group.key,
            dedupLabel: group.label,
            isDeduplicated: evidence.length > 0,
        });

        members.forEach(t => assigned.add(t.id));
    }

    // ── Pass 2: Pass-through any threats not in any group ────────────────────
    rawThreats.forEach(t => {
        if (!assigned.has(t.id)) {
            findings.push({
                ...t,
                evidence: [],
                isDeduplicated: false,
            });
        }
    });

    // ── Sort: critical → high → medium → low, then by ID ────────────────────
    findings.sort((a, b) => {
        const sd = SEV_RANK[b.sev] - SEV_RANK[a.sev];
        if (sd !== 0) return sd;
        return a.id.localeCompare(b.id);
    });

    return findings;
}
