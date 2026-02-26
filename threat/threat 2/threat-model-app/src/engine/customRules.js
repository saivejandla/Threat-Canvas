/**
 * CUSTOM RULE ENGINE
 * Declarative rule definitions that can be created, edited, imported/exported
 * without touching source code.
 *
 * Rule format (JSON-serializable):
 * {
 *   id, name, stride, sev, like, imp, cat, ctrl, desc, mits[],
 *   enabled: true,
 *   pack: 'default',
 *   condition: { type, ...params }
 * }
 *
 * Supported condition types:
 *   missing-component     — fires if no node of nodeType exists
 *   component-count-below — fires if count(nodeType) < threshold
 *   node-missing-property — fires for each node of nodeType where props.key ≠ value
 *   edge-missing-property — fires for edges where a property is missing/wrong
 *   path-unguarded        — fires if path from srcType to dstType has no guard of guardType
 *   edge-to-node-type     — fires for edges targeting nodeType with bad property
 *   all-edges-check       — fires for every edge matching a condition
 *   node-zone-mismatch    — fires when node type is in wrong zone
 */

import { buildAdjacency, findPath, reachableFrom } from './graphEngine.js';

// ─── Storage ───
let _customRules = [];
const STORAGE_KEY = 'threatcanvas_custom_rules';

/** Load rules from localStorage on init */
export function loadCustomRulesFromStorage() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) _customRules = JSON.parse(raw);
    } catch (e) { console.warn('Failed to load custom rules:', e); }
}

/** Persist to localStorage */
function _persist() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(_customRules)); } catch (e) { /* quota */ }
}

// ─── CRUD ───
export function getCustomRules() { return _customRules; }

export function addCustomRule(rule) {
    if (!rule.id) rule.id = 'C-' + String(Date.now()).slice(-6);
    if (rule.enabled === undefined) rule.enabled = true;
    if (!rule.pack) rule.pack = 'custom';
    _customRules.push(rule);
    _persist();
    return rule;
}

export function updateCustomRule(id, updates) {
    const idx = _customRules.findIndex(r => r.id === id);
    if (idx === -1) return null;
    Object.assign(_customRules[idx], updates);
    _persist();
    return _customRules[idx];
}

export function deleteCustomRule(id) {
    _customRules = _customRules.filter(r => r.id !== id);
    _persist();
}

export function toggleCustomRule(id) {
    const rule = _customRules.find(r => r.id === id);
    if (rule) { rule.enabled = !rule.enabled; _persist(); }
}

// ─── Import / Export ───
export function exportRulePack(packName) {
    const rules = packName ? _customRules.filter(r => r.pack === packName) : _customRules;
    const pack = {
        formatVersion: '1.0',
        packName: packName || 'all-rules',
        exportedAt: new Date().toISOString(),
        rules
    };
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threatcanvas-rules-${pack.packName}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

export function importRulePack(jsonString, merge = true) {
    try {
        const pack = JSON.parse(jsonString);
        if (!pack.rules || !Array.isArray(pack.rules)) throw new Error('Invalid rule pack format');

        const imported = [];
        for (const rule of pack.rules) {
            // Validate required fields
            if (!rule.name || !rule.stride || !rule.condition) {
                console.warn('Skipping invalid rule:', rule.name || 'unnamed');
                continue;
            }
            // Auto-assign ID if missing
            if (!rule.id) rule.id = 'C-' + String(Date.now()).slice(-6) + '-' + Math.random().toString(36).slice(2, 5);
            if (rule.enabled === undefined) rule.enabled = true;
            if (!rule.pack) rule.pack = pack.packName || 'imported';

            if (merge) {
                // Replace if same ID exists, else add
                const existIdx = _customRules.findIndex(r => r.id === rule.id);
                if (existIdx !== -1) _customRules[existIdx] = rule;
                else _customRules.push(rule);
            } else {
                _customRules.push(rule);
            }
            imported.push(rule);
        }
        _persist();
        return { success: true, count: imported.length, packName: pack.packName };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

// ─── Pre-built Rule Packs ───
export const RULE_PACKS = {
    healthcare: {
        packName: 'healthcare',
        label: '🏥 Healthcare (HIPAA)',
        rules: [
            {
                id: 'HC-001', name: 'PHI Data Without Encryption at Rest', stride: 'I', sev: 'critical', like: 'High', imp: 'High',
                cat: 'Information Disclosure', ctrl: 'Confidentiality', pack: 'healthcare',
                desc: 'Protected Health Information (PHI) stored in databases without encryption violates HIPAA §164.312(a)(2)(iv). Requires encryption at rest for all ePHI.',
                mits: ['Enable TDE on all databases storing PHI', 'Use AES-256 encryption for ePHI columns', 'Implement HIPAA-compliant key management'],
                condition: { type: 'node-missing-property', nodeType: 'database', propKey: 'encryption', propValue: true, propDefault: true }
            },
            {
                id: 'HC-002', name: 'No Audit Trail for PHI Access', stride: 'R', sev: 'critical', like: 'High', imp: 'High',
                cat: 'Repudiation', ctrl: 'Non-Repudiation', pack: 'healthcare',
                desc: 'HIPAA §164.312(b) requires audit controls recording all access to ePHI. Missing SIEM/audit component means no compliance.',
                mits: ['Deploy SIEM with ePHI access dashboards', 'Log all SELECT/UPDATE on PHI tables', 'Retain audit logs for 6 years per HIPAA'],
                condition: { type: 'missing-component', nodeType: 'siem' }
            },
            {
                id: 'HC-003', name: 'PHI Transmitted Without TLS 1.2+', stride: 'I', sev: 'critical', like: 'High', imp: 'High',
                cat: 'Information Disclosure', ctrl: 'Confidentiality', pack: 'healthcare',
                desc: 'HIPAA §164.312(e)(1) requires transmission security for ePHI. Connections carrying PHI data must use TLS 1.2 or higher.',
                mits: ['Enforce TLS 1.2+ on all PHI flows', 'Disable SSL/TLS 1.0/1.1', 'Use HSTS headers on all endpoints'],
                condition: { type: 'edge-missing-property', propKey: 'encryption', badValues: ['None', 'TLS 1.0/1.1', 'TLS 1.2 (weak ciphers)'], dataClassFilter: ['PHI'] }
            },
            {
                id: 'HC-004', name: 'No Identity Provider for PHI Systems', stride: 'S', sev: 'high', like: 'Medium', imp: 'High',
                cat: 'Spoofing', ctrl: 'Authentication', pack: 'healthcare',
                desc: 'HIPAA §164.312(d) requires unique user identification. Without a centralized IdP, user access to ePHI cannot be consistently verified.',
                mits: ['Deploy centralized IdP with MFA', 'Enforce unique user IDs for all PHI access', 'Implement session timeout policies'],
                condition: { type: 'missing-component', nodeType: 'idp' }
            },
        ]
    },
    fintech: {
        packName: 'fintech',
        label: '🏦 Fintech (PCI-DSS)',
        rules: [
            {
                id: 'FT-001', name: 'Cardholder Data Without Encryption', stride: 'I', sev: 'critical', like: 'High', imp: 'High',
                cat: 'Information Disclosure', ctrl: 'Confidentiality', pack: 'fintech',
                desc: 'PCI-DSS Req 3.4: Render PAN unreadable anywhere it is stored. All databases must encrypt cardholder data at rest.',
                mits: ['Encrypt all PAN/CHD columns with AES-256', 'Implement tokenization for PAN storage', 'Use HSMs for key management'],
                condition: { type: 'node-missing-property', nodeType: 'database', propKey: 'encryption', propValue: true, propDefault: true }
            },
            {
                id: 'FT-002', name: 'PCI Data Over Non-TLS Channel', stride: 'I', sev: 'critical', like: 'High', imp: 'High',
                cat: 'Information Disclosure', ctrl: 'Confidentiality', pack: 'fintech',
                desc: 'PCI-DSS Req 4.1: Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission.',
                mits: ['Enforce TLS 1.2+ on all PCI flows', 'Implement certificate pinning for mobile apps', 'Disable all weak cipher suites'],
                condition: { type: 'edge-missing-property', propKey: 'encryption', badValues: ['None', 'TLS 1.0/1.1'], dataClassFilter: ['PCI'] }
            },
            {
                id: 'FT-003', name: 'No WAF Protecting Payment Endpoints', stride: 'T', sev: 'critical', like: 'High', imp: 'High',
                cat: 'Tampering', ctrl: 'Integrity', pack: 'fintech',
                desc: 'PCI-DSS Req 6.6: Install a web application firewall in front of public-facing web applications.',
                mits: ['Deploy WAF with OWASP ModSecurity CRS', 'Enable bot protection on payment pages', 'Log and review WAF alerts daily'],
                condition: { type: 'missing-component', nodeType: 'waf' }
            },
            {
                id: 'FT-004', name: 'Missing Network Segmentation (CDE)', stride: 'E', sev: 'high', like: 'Medium', imp: 'High',
                cat: 'Elevation of Privilege', ctrl: 'Authorization', pack: 'fintech',
                desc: 'PCI-DSS Req 1.3: Prohibit direct public access to CDE. Without firewall, the cardholder data environment is exposed.',
                mits: ['Implement firewall between public and CDE zones', 'Use network micro-segmentation', 'Restrict all traffic to allow-listed ports'],
                condition: { type: 'missing-component', nodeType: 'firewall' }
            },
            {
                id: 'FT-005', name: 'Unauthenticated Access to Payment API', stride: 'S', sev: 'critical', like: 'High', imp: 'High',
                cat: 'Spoofing', ctrl: 'Authentication', pack: 'fintech',
                desc: 'PCI-DSS Req 8.1: All users must have a unique ID and authenticate before accessing cardholder data.',
                mits: ['Require OAuth2 or mTLS on all payment APIs', 'Implement API key rotation policies', 'Log all authentication events'],
                condition: { type: 'edge-to-node-type', targetNodeType: 'api', propKey: 'auth', badValues: ['None'] }
            },
        ]
    },
    cloud_native: {
        packName: 'cloud-native',
        label: '☁️ Cloud-Native',
        rules: [
            {
                id: 'CN-001', name: 'Lambda Without VPC Isolation', stride: 'E', sev: 'high', like: 'Medium', imp: 'High',
                cat: 'Elevation of Privilege', ctrl: 'Authorization', pack: 'cloud-native',
                desc: 'Serverless functions running outside a VPC have unrestricted internet access and cannot be network-segmented.',
                mits: ['Deploy Lambda functions inside a VPC', 'Use VPC endpoints for AWS services', 'Configure security groups for function ENIs'],
                condition: { type: 'node-missing-property', nodeType: 'lambda', propKey: 'vpc', propValue: true, propDefault: false }
            },
            {
                id: 'CN-002', name: 'Admin IAM Privilege on Compute Node', stride: 'E', sev: 'critical', like: 'Medium', imp: 'High',
                cat: 'Elevation of Privilege', ctrl: 'Authorization', pack: 'cloud-native',
                desc: 'Compute nodes with admin IAM privileges can escalate to full account takeover if compromised.',
                mits: ['Use least-privilege IAM roles for all compute', 'Enable IAM Access Analyzer', 'Implement permission boundaries'],
                condition: { type: 'node-has-property', nodeTypes: ['webserver', 'api', 'microservice', 'lambda'], propKey: 'iamPriv', propValue: 'admin' }
            },
            {
                id: 'CN-003', name: 'Public Object Storage Bucket', stride: 'I', sev: 'critical', like: 'High', imp: 'High',
                cat: 'Information Disclosure', ctrl: 'Confidentiality', pack: 'cloud-native',
                desc: 'Object storage accessible from internet-zone nodes without authentication risks public data exposure.',
                mits: ['Enable S3 Block Public Access', 'Use bucket policies to deny public reads', 'Audit bucket ACLs with AWS Config rules'],
                condition: { type: 'path-unguarded', srcType: ['internet', 'user', 'attacker'], dstType: ['storage'], guardType: ['waf', 'firewall', 'idp'] }
            },
            {
                id: 'CN-004', name: 'No Service Mesh Between Microservices', stride: 'S', sev: 'medium', like: 'Medium', imp: 'Medium',
                cat: 'Spoofing', ctrl: 'Authentication', pack: 'cloud-native',
                desc: 'Microservice-to-microservice calls without mTLS allow service impersonation within the cluster.',
                mits: ['Deploy Istio or Linkerd service mesh', 'Enforce mTLS for all east-west traffic', 'Implement service identity verification'],
                condition: { type: 'all-edges-check', fromNodeType: 'microservice', toNodeType: 'microservice', propKey: 'auth', badValues: ['None'] }
            },
        ]
    },
    zero_trust: {
        packName: 'zero-trust',
        label: '🔒 Zero Trust',
        rules: [
            {
                id: 'ZT-001', name: 'Unauthenticated Internal Data Flow', stride: 'S', sev: 'high', like: 'High', imp: 'High',
                cat: 'Spoofing', ctrl: 'Authentication', pack: 'zero-trust',
                desc: 'Zero Trust principle: never trust, always verify. Every data flow must be authenticated regardless of network zone.',
                mits: ['Require authentication on ALL connections', 'Implement mTLS for service-to-service', 'Use identity-aware proxies'],
                condition: { type: 'all-edges-check', propKey: 'auth', badValues: ['None'] }
            },
            {
                id: 'ZT-002', name: 'Missing Micro-Segmentation', stride: 'E', sev: 'medium', like: 'Medium', imp: 'High',
                cat: 'Elevation of Privilege', ctrl: 'Authorization', pack: 'zero-trust',
                desc: 'Zero Trust requires micro-segmentation. All zones should have firewall or WAF enforcement.',
                mits: ['Deploy firewall between every trust zone', 'Implement network policies (Calico/Cilium)', 'Use security groups per workload'],
                condition: { type: 'missing-component', nodeType: 'firewall' }
            },
            {
                id: 'ZT-003', name: 'No Continuous Verification (IdP Missing)', stride: 'S', sev: 'high', like: 'Medium', imp: 'High',
                cat: 'Spoofing', ctrl: 'Authentication', pack: 'zero-trust',
                desc: 'Zero Trust requires continuous identity verification. Without an IdP, there is no centralized authentication authority.',
                mits: ['Deploy centralized IdP (Okta, Azure AD, Keycloak)', 'Implement session re-validation on privilege change', 'Use short-lived tokens (15 min)'],
                condition: { type: 'missing-component', nodeType: 'idp' }
            },
        ]
    }
};

// ─── Install a pre-built pack ───
export function installRulePack(packKey) {
    const pack = RULE_PACKS[packKey];
    if (!pack) return { success: false, error: 'Unknown pack: ' + packKey };
    let added = 0;
    for (const rule of pack.rules) {
        const exists = _customRules.find(r => r.id === rule.id);
        if (!exists) {
            _customRules.push({ ...rule, enabled: true });
            added++;
        }
    }
    _persist();
    return { success: true, count: added, packName: pack.packName };
}

export function uninstallRulePack(packKey) {
    const pack = RULE_PACKS[packKey];
    if (!pack) return;
    const ids = new Set(pack.rules.map(r => r.id));
    _customRules = _customRules.filter(r => !ids.has(r.id));
    _persist();
}

// ═══════════════════════════════════════════════════
// CONDITION EVALUATOR — converts declarative JSON
// conditions into graph-aware check functions
// ═══════════════════════════════════════════════════

export function evaluateCondition(condition, nodes, edges, adj) {
    const N = nodes;
    const E = edges;
    const nodeArr = Object.values(N);

    switch (condition.type) {

        // ── 1. No node of given type exists ──
        case 'missing-component': {
            const exists = nodeArr.some(n => n.type === condition.nodeType);
            return exists ? null : { aff: [] };
        }

        // ── 2. Count of nodeType below threshold ──
        case 'component-count-below': {
            const count = nodeArr.filter(n => n.type === condition.nodeType).length;
            return count < (condition.threshold || 1) ? { aff: [] } : null;
        }

        // ── 3. Nodes of type X missing property Y ──
        case 'node-missing-property': {
            const targets = nodeArr.filter(n => n.type === condition.nodeType);
            const aff = [];
            for (const nd of targets) {
                const val = nd.props?.[condition.propKey] ?? nd[condition.propKey] ?? condition.propDefault;
                if (val !== condition.propValue) aff.push(nd.id);
            }
            return aff.length ? { aff } : null;
        }

        // ── 3b. Nodes of type(s) that HAVE a bad property value ──
        case 'node-has-property': {
            const types = Array.isArray(condition.nodeTypes) ? condition.nodeTypes : [condition.nodeTypes];
            const targets = nodeArr.filter(n => types.includes(n.type));
            const aff = [];
            for (const nd of targets) {
                const val = nd.props?.[condition.propKey] ?? nd[condition.propKey];
                if (val === condition.propValue) aff.push(nd.id);
            }
            return aff.length ? { aff } : null;
        }

        // ── 4. Edges with bad property values ──
        case 'edge-missing-property': {
            const badVals = condition.badValues || ['None'];
            const dataFilter = condition.dataClassFilter;
            const aff = [];
            for (const e of E) {
                if (dataFilter && dataFilter.length) {
                    const dc = e.dataClass || e.dataClassification || 'Public';
                    if (!dataFilter.includes(dc)) continue;
                }
                const val = e[condition.propKey];
                if (!val || badVals.includes(val)) aff.push(e.to);
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        }

        // ── 5. Edges targeting a specific node type with bad property ──
        case 'edge-to-node-type': {
            const badVals = condition.badValues || ['None'];
            const aff = [];
            for (const e of E) {
                const tgt = N[e.to];
                if (!tgt || tgt.type !== condition.targetNodeType) continue;
                const val = e[condition.propKey];
                if (!val || badVals.includes(val)) aff.push(e.to);
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        }

        // ── 6. All edges matching a criteria (optionally filtered by from/to type) ──
        case 'all-edges-check': {
            const badVals = condition.badValues || ['None'];
            const aff = [];
            for (const e of E) {
                if (condition.fromNodeType) {
                    const f = N[e.from];
                    if (!f || f.type !== condition.fromNodeType) continue;
                }
                if (condition.toNodeType) {
                    const t = N[e.to];
                    if (!t || t.type !== condition.toNodeType) continue;
                }
                const val = e[condition.propKey];
                if (!val || badVals.includes(val)) {
                    aff.push(e.to);
                    if (e.from) aff.push(e.from);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        }

        // ── 7. Path from srcType to dstType with no guard ──
        case 'path-unguarded': {
            const srcTypes = Array.isArray(condition.srcType) ? condition.srcType : [condition.srcType];
            const dstTypes = Array.isArray(condition.dstType) ? condition.dstType : [condition.dstType];
            const guardTypes = Array.isArray(condition.guardType) ? condition.guardType : [condition.guardType];

            const sources = nodeArr.filter(n => srcTypes.includes(n.type));
            const targets = nodeArr.filter(n => dstTypes.includes(n.type));
            const aff = [];

            for (const src of sources) {
                for (const tgt of targets) {
                    const path = findPath(src.id, tgt.id, adj);
                    if (!path) continue;
                    const hasGuard = path.slice(1, -1).some(id => guardTypes.includes(N[id]?.type));
                    if (!hasGuard) aff.push(tgt.id);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        }

        // ── 8. Node type in wrong zone ──
        case 'node-zone-mismatch': {
            const targets = nodeArr.filter(n => n.type === condition.nodeType);
            const aff = [];
            for (const nd of targets) {
                const zone = nd.zone || nd.trustZone;
                if (condition.expectedZones && !condition.expectedZones.includes(zone)) {
                    aff.push(nd.id);
                }
            }
            return aff.length ? { aff } : null;
        }

        default:
            console.warn('Unknown custom rule condition type:', condition.type);
            return null;
    }
}

/**
 * Evaluate all enabled custom rules and return threat objects.
 * Called by runAnalysis() in threatEngine.js
 */
export function evaluateCustomRules(nodes, edges, adj) {
    const results = [];
    for (const rule of _customRules) {
        if (!rule.enabled || !rule.condition) continue;
        try {
            const res = evaluateCondition(rule.condition, nodes, edges, adj);
            if (res) {
                results.push({
                    ...rule,
                    affected: res.aff || [],
                    isCustom: true,
                    // Provide a no-op check function for compatibility with built-in rules
                    check: () => res
                });
            }
        } catch (e) {
            console.warn(`Custom rule ${rule.id} failed:`, e);
        }
    }
    return results;
}
