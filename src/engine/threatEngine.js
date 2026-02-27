/**
 * THREAT ENGINE — OWASP STRIDE Rule Evaluation
 * Contains the RULES array and the runAnalysis() orchestrator.
 * Now also evaluates custom rules from the declarative rule engine.
 */
import { S, S_attackPaths, S_boundaryFindings } from '../state/state.js';
import { DEFS } from './componentDefs.js';
import { buildAdjacency, findPath, reachableFrom, trustBoundaryCrossings } from './graphEngine.js';
import { sc } from '../utils/helpers.js';
import { runFullAnalysis } from './attackPaths.js';
import { renderDetected } from '../ui/assessUI.js';
import { renderCM } from '../ui/assessUI.js';
import { evaluateCustomRules, getCustomRules } from './customRules.js';

// ═══ THREAT RULES (OWASP STRIDE) ═══
export const RULES = [
    {
        id: 'T-001', name: 'Missing WAF / Firewall', stride: 'T', sev: 'critical', like: 'High', imp: 'High', cat: 'Tampering', ctrl: 'Integrity',
        check: (N, E, adj) => {
            const ext = Object.values(N).filter(n => ['internet', 'user', 'attacker'].includes(n.type));
            const svcs = Object.values(N).filter(n => ['webserver', 'api'].includes(n.type));
            const guards = new Set(Object.values(N).filter(n => ['waf', 'firewall'].includes(n.type)).map(n => n.id));
            if (!ext.length || !svcs.length || guards.size) return null;
            const aff = [...new Set(svcs.filter(svc => ext.some(e => findPath(e.id, svc.id, adj))).map(s => s.id))];
            return aff.length ? { aff } : null;
        },
        desc: 'External traffic can reach internal services without passing through any WAF or Firewall. Enables direct exploitation of web vulnerabilities.',
        mits: ['Deploy WAF (AWS WAF, Cloudflare, ModSecurity)', 'Add firewall with deny-by-default rules', 'Implement DMZ and network segmentation']
    },

    {
        id: 'T-002', name: 'Unauthenticated API Reachable from Untrusted Node', stride: 'S', sev: 'critical', like: 'High', imp: 'High', cat: 'Spoofing', ctrl: 'Authentication',
        check: (N, E, adj) => {
            const untrusted = Object.values(N).filter(n => ['untrusted', 'hostile'].includes(n.trust));
            const apis = Object.values(N).filter(n => n.type === 'api');
            const aff = [];
            for (const src of untrusted) {
                for (const api of apis) {
                    const inEdges = E.filter(e => e.to === api.id && e.auth === 'None');
                    if (inEdges.length && findPath(src.id, api.id, adj)) aff.push(api.id);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'An untrusted node can reach an API endpoint with no authentication through one or more hops. Any actor can spoof identity and make unauthorized calls.',
        mits: ['Require JWT or OAuth2 on all API endpoints', 'Implement API gateway with mandatory auth', 'Add rate limiting and IP allowlisting']
    },

    {
        id: 'T-003', name: 'Unencrypted Database Connection', stride: 'I', sev: 'high', like: 'Medium', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        check: (N, E, adj) => {
            const dbs = Object.values(N).filter(n => n.type === 'database');
            const aff = [];
            for (const db of dbs) {
                const badEdge = E.find(e => e.to === db.id && e.encryption === 'None');
                if (badEdge) aff.push(db.id);
            }
            return aff.length ? { aff } : null;
        },
        desc: 'Database connections transmit plaintext, exposing credentials and sensitive records to eavesdropping.',
        mits: ['Enable TLS/SSL for all DB connections', 'Use mTLS for service-to-DB authentication', 'Encrypt data at rest and in transit']
    },

    {
        id: 'T-004', name: 'PII / Sensitive Data over Plaintext', stride: 'I', sev: 'critical', like: 'High', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        check: (N, E, adj) => {
            const aff = [];
            for (const e of E) {
                if (['PII', 'PHI', 'PCI'].includes(e.dataClass) && e.encryption === 'None') aff.push(e.to);
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'PII, PHI, or PCI data transmitted without encryption. Violates GDPR, HIPAA, PCI-DSS requirements.',
        mits: ['Enforce TLS 1.2+ on all sensitive flows', 'Implement data masking at API layer', 'Classify and audit all data flows']
    },

    {
        id: 'T-005', name: 'Attacker Has Active Data Flow Path', stride: 'S', sev: 'critical', like: 'High', imp: 'High', cat: 'Spoofing', ctrl: 'Authentication',
        check: (N, E, adj) => {
            const atk = Object.values(N).find(n => n.type === 'attacker');
            if (!atk) return null;
            const reachable = reachableFrom(atk.id, adj);
            const highValue = Object.values(N).filter(n => ['internal', 'restricted'].includes(n.trust) && reachable.has(n.id));
            return highValue.length ? { aff: [atk.id, ...highValue.map(n => n.id)] } : null;
        },
        desc: 'Adversary node has a directed path to internal or restricted nodes. Models a live attack path into the protected architecture.',
        mits: ['Explicitly model attacker capabilities', 'Add detection (SIEM, IDS/IPS)', 'Implement zero-trust network segmentation']
    },

    {
        id: 'T-006', name: 'No Audit Trail / SIEM', stride: 'R', sev: 'medium', like: 'Medium', imp: 'Medium', cat: 'Repudiation', ctrl: 'Non-Repudiation',
        check: (N, E, adj) => {
            const s = Object.values(N).some(n => n.type === 'siem');
            return (Object.keys(N).length > 2 && !s) ? { aff: [] } : null;
        },
        desc: 'No SIEM or audit component. Operations are unlogged; attacks go undetected; repudiation is enabled.',
        mits: ['Deploy SIEM (Splunk, Elastic, Wazuh)', 'Enable centralized audit logging', 'Implement digital signatures on critical ops', 'Set up anomaly detection alerts']
    },

    {
        id: 'T-007', name: 'Unauthenticated Cache Access', stride: 'I', sev: 'high', like: 'Medium', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        check: (N, E, adj) => {
            const aff = [];
            for (const e of E) { const t = N[e.to]; if (t && t.type === 'cache' && e.auth === 'None') aff.push(t.id); }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Cache accessible without authentication leaks session data, tokens, or sensitive cached responses.',
        mits: ['Enable Redis AUTH / Memcached SASL', 'Restrict to localhost/private network only', 'Encrypt sensitive values before caching']
    },

    {
        id: 'T-008', name: 'Public Object Storage Exposure', stride: 'I', sev: 'high', like: 'High', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        check: (N, E, adj) => {
            const untrusted = Object.values(N).filter(n => ['internet', 'user', 'attacker'].includes(n.type));
            const stores = Object.values(N).filter(n => n.type === 'storage');
            const aff = [];
            for (const src of untrusted)
                for (const st of stores)
                    if (findPath(src.id, st.id, adj)) aff.push(st.id);
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Object storage is reachable from an untrusted node through one or more hops. Risk of public bucket misconfiguration or indirect access.',
        mits: ['Block all public access by default', 'Use pre-signed URLs with short TTL', 'Enable S3 Block Public Access policy']
    },

    {
        id: 'T-009', name: 'Single Point of Failure — No LB', stride: 'D', sev: 'medium', like: 'Medium', imp: 'Medium', cat: 'Denial of Service', ctrl: 'Availability',
        check: (N, E, adj) => {
            // Suppress for small models (≤5 nodes) — too noisy for beginners
            if (Object.keys(N).length <= 5) return null;
            const lb = Object.values(N).some(n => n.type === 'loadbalancer');
            const wc = Object.values(N).filter(n => ['webserver', 'api'].includes(n.type)).length;
            return (wc > 0 && !lb) ? { aff: [] } : null;
        },
        desc: 'No load balancer detected. A single server crash causes complete service outage.',
        mits: ['Add load balancer with health checks', 'Deploy across multiple availability zones', 'Implement circuit breaker patterns']
    },

    {
        id: 'T-010', name: 'Lateral Movement to Data Store', stride: 'E', sev: 'high', like: 'Medium', imp: 'High', cat: 'Elevation of Privilege', ctrl: 'Authorization',
        check: (N, E, adj) => {
            const aff = [];
            for (const e of E) {
                const f = N[e.from], t = N[e.to];
                if (f && t && f.trust === 'internal' && t.trust === 'restricted' && e.auth === 'None') aff.push(t.id);
            }
            const untrusted = Object.values(N).filter(n => ['untrusted', 'hostile'].includes(n.trust));
            const restricted = Object.values(N).filter(n => n.trust === 'restricted');
            for (const src of untrusted)
                for (const dst of restricted) {
                    const path = findPath(src.id, dst.id, adj);
                    if (path && path.length > 2) aff.push(dst.id);
                }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Direct or multi-hop path exists from internal/untrusted node to restricted data store without authentication. Enables lateral movement post-compromise.',
        mits: ['Require mTLS between services and data stores', 'Use service mesh with AuthZ policies', 'Least-privilege DB credentials per service']
    },

    {
        id: 'T-011', name: 'HTTP on External Channel', stride: 'I', sev: 'high', like: 'High', imp: 'Medium', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        check: (N, E, adj) => {
            const aff = [];
            for (const e of E) { const f = N[e.from]; if (f && ['internet', 'user'].includes(f.type) && e.protocol === 'HTTP') aff.push(e.to); }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Unencrypted HTTP on external-facing connections. Susceptible to MITM, credential theft, session hijacking.',
        mits: ['Enforce HTTPS via HSTS', 'Redirect all HTTP to HTTPS', 'Configure TLS 1.2+ with strong cipher suites']
    },

    {
        id: 'T-012', name: 'No Centralized Identity Provider', stride: 'S', sev: 'medium', like: 'Medium', imp: 'Medium', cat: 'Spoofing', ctrl: 'Authentication',
        check: (N, E, adj) => {
            // Suppress for small models (≤5 nodes) — too noisy for beginners
            if (Object.keys(N).length <= 5) return null;
            const idp = Object.values(N).some(n => n.type === 'idp');
            const usr = Object.values(N).some(n => n.type === 'user');
            return (usr && !idp) ? { aff: [] } : null;
        },
        desc: 'No centralized identity provider. Fragmented authentication increases credential exposure and inconsistent session handling.',
        mits: ['Implement SSO with SAML 2.0 or OIDC', 'Centralize AuthN in Identity Provider', 'Enable MFA for all user accounts']
    },

    {
        id: 'T-013', name: 'Excessive Trust Boundary Traversal', stride: 'E', sev: 'high', like: 'Medium', imp: 'High', cat: 'Elevation of Privilege', ctrl: 'Authorization',
        check: (N, E, adj) => {
            const untrusted = Object.values(N).filter(n => ['untrusted', 'hostile'].includes(n.trust));
            const restricted = Object.values(N).filter(n => n.trust === 'restricted');
            const aff = [];
            for (const src of untrusted)
                for (const dst of restricted) {
                    const path = findPath(src.id, dst.id, adj);
                    if (path && trustBoundaryCrossings(path, E) >= 2) aff.push(dst.id);
                }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'A path crosses two or more trust boundaries to reach a restricted node. Each boundary crossing is a privilege escalation opportunity if controls are inconsistent.',
        mits: ['Enforce re-authentication at each trust boundary', 'Implement consistent AuthZ policy across zones', 'Use network micro-segmentation between trust levels']
    },

    {
        id: 'T-014', name: 'Sensitive Data Flows to Low-Trust Node', stride: 'I', sev: 'critical', like: 'High', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        check: (N, E, adj) => {
            const aff = [];
            for (const e of E) {
                const tNode = N[e.to];
                if (!tNode) continue;
                if (['PII', 'PHI', 'PCI', 'Confidential', 'Restricted'].includes(e.dataClass) && ['untrusted', 'hostile'].includes(tNode.trust))
                    aff.push(tNode.id);
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Sensitive or regulated data (PII/PHI/PCI/Confidential) is being sent directly to an untrusted or hostile node. This is an unconditional data exposure.',
        mits: ['Never transmit classified data to untrusted endpoints', 'Enforce data classification policies at API layer', 'Add DLP controls and egress filtering']
    },

    {
        id: 'T-015', name: 'Cyclic Service Dependency', stride: 'D', sev: 'medium', like: 'Low', imp: 'High', cat: 'Denial of Service', ctrl: 'Availability',
        check: (N, E, adj) => {
            const internal = new Set(Object.values(N).filter(n => ['internal', 'restricted'].includes(n.trust)).map(n => n.id));
            const internalAdj = {};
            internal.forEach(id => { internalAdj[id] = (adj[id] || []).filter(({ to }) => internal.has(to)); });
            const WHITE = 0, GRAY = 1, BLACK = 2;
            const color = {}; internal.forEach(id => color[id] = WHITE);
            let cyclic = false;
            function dfs(u) { if (color[u] === GRAY) { cyclic = true; return; } if (color[u] === BLACK) return; color[u] = GRAY; (internalAdj[u] || []).forEach(({ to }) => dfs(to)); color[u] = BLACK; }
            internal.forEach(id => { if (color[id] === WHITE) dfs(id); });
            return cyclic ? { aff: [] } : null;
        },
        desc: 'Internal service graph contains a cycle. Circular dependencies create deadlock risk, cascading failures, and amplified DoS surface under load.',
        mits: ['Break cycles with async messaging (queues/events)', 'Introduce timeout and circuit-breaker patterns', 'Audit service call graph for unintentional loops']
    },

    {
        id: 'T-016', name: 'Missing Rate Limiting on Auth Endpoint', stride: 'D', sev: 'high', like: 'High', imp: 'Medium', cat: 'Denial of Service', ctrl: 'Availability',
        check: (N, E, adj) => {
            const aff = [];
            const external = Object.values(N).filter(n => ['internet', 'user', 'attacker'].includes(n.type));
            const authSvcs = Object.values(N).filter(n => ['api', 'webserver', 'idp'].includes(n.type));
            for (const src of external) {
                for (const svc of authSvcs) {
                    const path = findPath(src.id, svc.id, adj);
                    if (!path) continue;
                    const pathEdges = [];
                    for (let i = 0; i < path.length - 1; i++) { const e = E.find(ed => ed.from === path[i] && ed.to === path[i + 1]); if (e) pathEdges.push(e); }
                    const noProtection = pathEdges.every(e => e.auth === 'None');
                    const noGuard = !path.slice(1, -1).some(id => ['waf', 'firewall', 'loadbalancer'].includes(N[id]?.type));
                    if (noProtection && noGuard) aff.push(svc.id);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'An external actor can reach an authentication-handling service with no rate limiting or throttling controls on the path. Enables brute force and credential stuffing.',
        mits: ['Implement rate limiting at WAF or API gateway', 'Add CAPTCHA on login endpoints', 'Deploy account lockout and progressive delay policies']
    },

    {
        id: 'T-017', name: 'Uncontrolled External Dependency Ingress', stride: 'T', sev: 'high', like: 'Medium', imp: 'High', cat: 'Tampering', ctrl: 'Integrity',
        check: (N, E, adj) => {
            const internet = Object.values(N).filter(n => n.type === 'internet');
            const internal = Object.values(N).filter(n => ['internal', 'restricted'].includes(n.trust));
            const aff = [];
            for (const src of internet) {
                const reachable = reachableFrom(src.id, adj);
                internal.forEach(nd => { if (reachable.has(nd.id)) aff.push(nd.id); });
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Internet-facing nodes have a directed path to internal services with no explicit trust validation. Supply chain or dependency tampering can propagate inward.',
        mits: ['Pin and verify all external dependencies (SBOMs)', 'Enforce input validation at every trust boundary', 'Use network egress filtering to limit outbound connections']
    },

    {
        id: 'T-018', name: 'Missing Data Classification on Data Store', stride: 'I', sev: 'medium', like: 'Medium', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        check: (N, E, adj) => {
            const computeTypes = new Set(['webserver', 'api', 'microservice', 'lambda']);
            const dataTypes = new Set(['database', 'cache', 'storage']);
            const aff = [];
            for (const e of E) {
                const src = N[e.from], dst = N[e.to];
                if (!src || !dst) continue;
                if (computeTypes.has(src.type) && dataTypes.has(dst.type)) {
                    const dc = e.dataClass || e.dataClassification;
                    if (!dc || dc === 'Public') aff.push(dst.id);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'A compute node connects to a data store, but the data flow has no sensitivity classification. If this data store holds PII, financial data, or health records, this connection needs encryption and access controls. Set the data classification on this edge to get more targeted threat analysis.',
        mits: [
            'Classify the data flowing on this edge (PII, Internal, Confidential)',
            'Enable TLS/encryption on all data store connections',
            'Implement least-privilege database access controls',
            'In threat modeling, data classification drives your security decisions — start here'
        ]
    },

    // ── Enhanced Rule Engine (R-00x) ──
    {
        id: 'R-001', name: 'Broken Authentication', stride: 'S', sev: 'high', like: 'High', imp: 'High', cat: 'Spoofing', ctrl: 'Authentication',
        owasp: 'A07:2021 Identification and Authentication Failures',
        check: (N, E, adj) => {
            const aff = [];
            for (const nd of Object.values(N)) {
                if (nd.type === 'api') {
                    const propAuthFalse = nd.props && nd.props.auth === false;
                    const inEdges = E.filter(e => e.to === nd.id);
                    const allEdgesUnauthenticated = inEdges.length > 0 && inEdges.every(e => e.auth === 'None');
                    if (propAuthFalse || allEdgesUnauthenticated) aff.push(nd.id);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'API endpoint has authentication disabled. Any actor can make unauthorized calls, spoof identities, and access protected resources without credentials. Maps to OWASP A07:2021.',
        mits: ['Enable JWT or OAuth2 on all API endpoints', 'Implement API Gateway with mandatory authentication policy', 'Add MFA for privileged API operations', 'Audit all API routes for missing auth middleware']
    },

    {
        id: 'R-002', name: 'Sensitive Data Exposure — Unencrypted Database', stride: 'I', sev: 'critical', like: 'High', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        owasp: 'A02:2021 Cryptographic Failures',
        check: (N, E, adj) => {
            const aff = [];
            for (const nd of Object.values(N)) {
                if (nd.type === 'database') {
                    const propEncFalse = nd.props && nd.props.encryption === false;
                    const inEdges = E.filter(e => e.to === nd.id);
                    const hasUnencryptedInbound = inEdges.some(e => e.encryption === 'None');
                    if (propEncFalse || hasUnencryptedInbound) aff.push(nd.id);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Database lacks encryption at rest or receives unencrypted connections. Sensitive records, credentials, and PII are exposed to anyone with physical or logical access to storage. Maps to OWASP A02:2021.',
        mits: ['Enable transparent data encryption (TDE) at the database engine level', 'Encrypt all DB connection strings with TLS 1.2+', 'Use column-level encryption for PII/PCI/PHI fields', 'Rotate encryption keys on a regular schedule']
    },

    {
        id: 'R-003', name: 'Man-in-the-Middle Attack', stride: 'I', sev: 'high', like: 'High', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        owasp: 'A02:2021 Cryptographic Failures',
        check: (N, E, adj) => {
            const aff = [];
            for (const e of E) {
                const isHttp = e.protocol && e.protocol.toUpperCase() === 'HTTP';
                const noEnc = !e.encryption || e.encryption === 'None';
                if (isHttp && noEnc) { aff.push(e.to); if (e.from) aff.push(e.from); }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Data flow uses unencrypted HTTP with no transport security. An attacker positioned on the network can intercept, read, and modify all traffic between these components. Maps to OWASP A02:2021.',
        mits: ['Upgrade all connections to HTTPS/TLS 1.2+', 'Enforce HTTP Strict Transport Security (HSTS)', 'Redirect all HTTP requests to HTTPS at the load balancer', 'Use TLS 1.3 for maximum forward secrecy']
    },

    {
        id: 'R-004', name: 'Plaintext Sensitive Data Exposure', stride: 'I', sev: 'critical', like: 'High', imp: 'High', cat: 'Information Disclosure', ctrl: 'Confidentiality',
        owasp: 'A02:2021 Cryptographic Failures',
        check: (N, E, adj) => {
            const sensitiveClasses = ['PII', 'PHI', 'PCI', 'Confidential', 'Restricted', 'secret', 'pii', 'phi', 'pci', 'confidential', 'restricted'];
            const aff = [];
            for (const e of E) {
                const isSensitive = sensitiveClasses.includes(e.dataClass) || sensitiveClasses.includes(e.dataClassification);
                const noEnc = !e.encryption || e.encryption === 'None';
                if (isSensitive && noEnc) { aff.push(e.to); if (e.from) aff.push(e.from); }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Personally Identifiable Information (PII), secrets, or regulated data is transmitted without encryption. This violates GDPR, HIPAA, and PCI-DSS requirements and exposes individuals to identity theft. Maps to OWASP A02:2021.',
        mits: ['Enforce TLS 1.2+ on all channels carrying PII/secret data', 'Implement end-to-end encryption for sensitive payloads', 'Apply data minimization — transmit only essential fields', 'Audit all data flows against a data classification register']
    },

    {
        id: 'R-005', name: 'Unauthorized Data Access', stride: 'E', sev: 'high', like: 'High', imp: 'High', cat: 'Elevation of Privilege', ctrl: 'Authorization',
        owasp: 'A01:2021 Broken Access Control',
        check: (N, E, adj) => {
            const publicClasses = ['Public', 'public'];
            const aff = [];
            for (const e of E) {
                const noAuth = !e.auth || e.auth === 'None';
                const dataClass = e.dataClass || e.dataClassification || 'Public';
                const isNonPublic = !publicClasses.includes(dataClass);
                if (noAuth && isNonPublic) { aff.push(e.to); if (e.from) aff.push(e.from); }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'Non-public data flows across a connection with no authentication. Any actor with network access can read or exfiltrate internal, confidential, or regulated data without presenting credentials. Maps to OWASP A01:2021.',
        mits: ['Require authentication on every connection carrying non-public data', 'Implement zero-trust: authenticate every request regardless of network zone', 'Use API keys or JWT for service-to-service calls', 'Log and alert on unauthenticated access to sensitive endpoints']
    },

    {
        id: 'R-006', name: 'Privilege Escalation Path', stride: 'E', sev: 'critical', like: 'Medium', imp: 'High', cat: 'Elevation of Privilege', ctrl: 'Authorization',
        owasp: 'A01:2021 Broken Access Control',
        check: (N, E, adj) => {
            const aff = [];
            const clients = Object.values(N).filter(n => ['user', 'client', 'internet', 'attacker'].includes(n.type));
            const adminApis = Object.values(N).filter(n =>
                n.type === 'api' && (
                    (n.props && (n.props.role === 'admin' || n.props.role === 'service')) ||
                    n.iamPriv === 'admin' ||
                    n.trust === 'restricted'
                )
            );
            const dbs = Object.values(N).filter(n => n.type === 'database');
            for (const client of clients) {
                for (const api of adminApis) {
                    const pathToApi = findPath(client.id, api.id, adj);
                    if (!pathToApi) continue;
                    const edgeToApi = E.find(e => e.to === api.id && pathToApi.includes(e.from));
                    const apiEdgeUnauthenticated = !edgeToApi || edgeToApi.auth === 'None';
                    if (!apiEdgeUnauthenticated) continue;
                    for (const db of dbs) {
                        const pathToDb = findPath(api.id, db.id, adj);
                        if (!pathToDb) continue;
                        const edgeToDb = E.find(e => e.from === api.id && e.to === db.id);
                        const dbEdgeUnauthenticated = !edgeToDb || edgeToDb.auth === 'None';
                        if (dbEdgeUnauthenticated) { aff.push(client.id, api.id, db.id); }
                    }
                }
            }
            for (const e of E) {
                const fromNd = N[e.from]; const toNd = N[e.to];
                if (!fromNd || !toNd) continue;
                const fromIsAdmin = fromNd.iamPriv === 'admin' || (fromNd.props && fromNd.props.role === 'admin');
                const edgeNoAuth = !e.auth || e.auth === 'None';
                if (fromIsAdmin && edgeNoAuth && toNd.type === 'database') { aff.push(fromNd.id, toNd.id); }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'A privilege escalation path exists: a client can reach an admin-role API, and that API connects to a database without authentication. An attacker exploiting the unauthenticated API gains full database access via admin privileges. Maps to OWASP A01:2021.',
        mits: ['Enforce strict role-based access control (RBAC) on all API→DB connections', 'Require mTLS for service-to-database authentication', 'Apply least privilege: never use admin credentials for application DB connections', 'Implement database proxies (e.g. AWS RDS Proxy) to enforce connection-level AuthZ']
    },
];

/**
 * DATA MODEL NORMALIZATION
 */
export function normalizeNodes(nodes) {
    const zoneTZMap = { public: 'internet', dmz: 'dmz', private: 'internal', isolated: 'restricted' };
    Object.values(nodes).forEach(nd => {
        if (!nd.props) nd.props = {};
        if (!nd.trustZone) {
            const def = DEFS[nd.type];
            nd.trustZone = def?.trustZone || zoneTZMap[nd.zone || 'private'] || 'internal';
        }
        if (nd.props.dataClassification === undefined) {
            const tzDC = { internet: 'public', dmz: 'internal', internal: 'internal', restricted: 'secret' };
            nd.props.dataClassification = nd.type === 'database' ? 'secret' : (tzDC[nd.trustZone] || 'internal');
        }
        if (nd.props.auth === undefined) {
            nd.props.auth = !['api', 'webserver'].includes(nd.type);
        }
        if (nd.props.encryption === undefined) {
            nd.props.encryption = true;
        }
        if (nd.props.role === undefined) {
            nd.props.role = nd.iamPriv === 'admin' ? 'admin' : (nd.iamPriv === 'assumerole' ? 'service' : 'user');
        }
        if (nd.props.exposed === undefined) {
            nd.props.exposed = nd.zone === 'public' || ['internet', 'user', 'attacker'].includes(nd.type);
        }
    });
}

export function normalizeEdges(edges) {
    edges.forEach(e => {
        if (!e.normalizedProtocol) e.normalizedProtocol = (e.protocol || '').toUpperCase();
        if (!e.dataClassification) e.dataClassification = e.dataClass || 'Public';
    });
}

/**
 * runAnalysis — main orchestrator
 */
export function runAnalysis() {
    if (!Object.keys(S.nodes).length) { alert('Add components to the DFD first.'); return; }
    document.querySelectorAll('.node-pills').forEach(p => p.innerHTML = '');
    S.threats = [];
    // Step 1: Normalize
    normalizeNodes(S.nodes);
    normalizeEdges(S.edges);
    // Step 2: Build graph
    const adj = buildAdjacency(S.nodes, S.edges);
    // Step 3: Evaluate rules
    for (const rule of RULES) {
        const res = rule.check(S.nodes, S.edges, adj);
        if (res) {
            // Build location names from affected node IDs
            const affIds = res.aff || [];
            const locationNames = [...new Set(affIds.map(nid => S.nodes[nid]?.label || nid).filter(Boolean))];
            S.threats.push({ ...rule, affected: affIds, locationNames });
            affIds.forEach(nid => {
                const pp2 = document.getElementById('pills-' + nid);
                if (pp2 && !pp2.querySelector(`[data-t="${rule.id}"]`)) {
                    const pill = document.createElement('span');
                    pill.className = 'pill';
                    pill.dataset.t = rule.id;
                    pill.style.cssText = `background:${sc(rule.sev)}22;color:${sc(rule.sev)};border:1px solid ${sc(rule.sev)}55`;
                    pill.textContent = rule.id;
                    pp2.appendChild(pill);
                }
            });
            if (!S.cmRows[rule.id]) S.cmRows[rule.id] = { response: 'Mitigate', status: 'Non-Mitigated' };
        }
    }
    // Step 3b: Evaluate custom rules (declarative engine)
    const customThreats = evaluateCustomRules(S.nodes, S.edges, adj);
    for (const ct of customThreats) {
        const ctAffIds = ct.affected || [];
        const ctLocationNames = [...new Set(ctAffIds.map(nid => S.nodes[nid]?.label || nid).filter(Boolean))];
        S.threats.push({ ...ct, affected: ctAffIds, locationNames: ctLocationNames });
        ctAffIds.forEach(nid => {
            const pp2 = document.getElementById('pills-' + nid);
            if (pp2 && !pp2.querySelector(`[data-t="${ct.id}"]`)) {
                const pill = document.createElement('span');
                pill.className = 'pill';
                pill.dataset.t = ct.id;
                pill.style.cssText = `background:${sc(ct.sev)}22;color:${sc(ct.sev)};border:1px solid ${sc(ct.sev)}55`;
                pill.textContent = ct.id;
                pp2.appendChild(pill);
            }
        });
        if (!S.cmRows[ct.id]) S.cmRows[ct.id] = { response: 'Mitigate', status: 'Non-Mitigated' };
    }
    // Step 4: Full unified analysis pipeline
    runFullAnalysis(S.nodes, S.edges);

    renderDetected();
    const cnts = { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 };
    S.threats.forEach(t => cnts[t.stride] = (cnts[t.stride] || 0) + 1);
    Object.entries(cnts).forEach(([k, v]) => { const el = document.getElementById('c' + k); if (el) el.textContent = v; });
    const apCount = S_attackPaths.length;
    const bvCount = S_boundaryFindings.length;
    document.getElementById('statusBar').textContent =
        `Analysis complete — ${S.threats.length} threats · ${apCount} attack paths · ${bvCount} boundary violations`;
    document.getElementById('stab3').classList.add('done');
    const apBadge = document.getElementById('apTabBadge');
    if (apBadge) apBadge.textContent = apCount + bvCount;

    // Step 5: Render threat count badges on canvas nodes
    document.querySelectorAll('.node-threat-badge').forEach(b => b.remove());
    const nodeThreatCount = {};
    S.threats.forEach(t => {
        (t.affected || []).forEach(nid => {
            nodeThreatCount[nid] = (nodeThreatCount[nid] || 0) + 1;
        });
    });
    for (const [nid, count] of Object.entries(nodeThreatCount)) {
        const nodeEl = document.getElementById(nid);
        if (!nodeEl) continue;
        const badge = document.createElement('div');
        badge.className = 'node-threat-badge';
        badge.textContent = count;
        badge.title = `${count} threat${count > 1 ? 's' : ''} affecting this component`;
        // Severity-based color: red if any critical, orange if high, yellow otherwise
        const nodeThreats = S.threats.filter(t => (t.affected || []).includes(nid));
        const hasCrit = nodeThreats.some(t => t.sev === 'critical');
        const hasHigh = nodeThreats.some(t => t.sev === 'high');
        if (hasCrit) badge.classList.add('badge-critical');
        else if (hasHigh) badge.classList.add('badge-high');
        else badge.classList.add('badge-medium');
        nodeEl.appendChild(badge);
    }
}
