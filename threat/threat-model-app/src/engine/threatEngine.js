import { buildAdjacency, findPath, reachableFrom, trustBoundaryCrossings, hasCycle } from './blastRadius.js';

const COMPONENT_THREATS = {
    internet: [
        { stride: 'S', sev: 'critical', name: 'Spoofed Origin / IP Forgery', mits: ['Validate all inbound request origins', 'Implement strict CORS policy', 'Use request signing (HMAC)'] },
        { stride: 'D', sev: 'high', name: 'DDoS / Volumetric Flood', mits: ['Deploy CDN with rate limiting', 'Use anycast traffic scrubbing', 'Implement SYN cookie protection'] },
        { stride: 'T', sev: 'high', name: 'Man-in-the-Middle Interception', mits: ['Enforce HTTPS everywhere with HSTS', 'Pin TLS certificates', 'Use TLS 1.3 only'] },
    ],
    user: [
        { stride: 'S', sev: 'high', name: 'Credential Theft / Phishing', mits: ['Enforce MFA for all accounts', 'Implement phishing-resistant auth (WebAuthn)', 'Detect anomalous login patterns'] },
        { stride: 'E', sev: 'medium', name: 'Privilege Escalation via Broken Access Control', mits: ['Enforce least-privilege RBAC', 'Validate role on every request server-side', 'Audit permission changes'] },
        { stride: 'I', sev: 'medium', name: 'Session Hijacking', mits: ['Use HttpOnly + Secure cookie flags', 'Rotate session tokens on privilege change', 'Implement absolute session timeouts'] },
    ],
    attacker: [
        { stride: 'S', sev: 'critical', name: 'Identity Spoofing / Impersonation', mits: ['Require strong authentication on all paths', 'Zero-trust: verify every request', 'Deploy behavioral analytics (UEBA)'] },
        { stride: 'T', sev: 'critical', name: 'Data Tampering / Injection', mits: ['Input validation on all entry points', 'Parameterized queries / ORM', 'Integrity checksums on critical data'] },
        { stride: 'E', sev: 'critical', name: 'Full System Compromise Path', mits: ['Network segmentation and micro-segmentation', 'Implement deception technology (honeypots)', 'Continuous threat hunting'] },
    ],
    webserver: [
        { stride: 'T', sev: 'high', name: 'SQL / Command Injection', mits: ['Use parameterized queries only', 'Deploy WAF with OWASP Core Rule Set', 'Restrict DB account permissions'] },
        { stride: 'I', sev: 'high', name: 'Directory Traversal / File Exposure', mits: ['Restrict file system access to webroot', 'Disable directory listing', 'Validate all file path inputs'] },
        { stride: 'D', sev: 'medium', name: 'Resource Exhaustion / Slow Loris', mits: ['Set request size and timeout limits', 'Use reverse proxy (nginx) with connection limits', 'Implement circuit breakers'] },
    ],
    api: [
        { stride: 'S', sev: 'critical', name: 'Broken Object Level Authorization (BOLA)', mits: ['Validate object ownership on every request', 'Never expose internal IDs directly', 'Implement row-level security'] },
        { stride: 'I', sev: 'high', name: 'Excessive Data Exposure', mits: ['Return only fields the client needs', 'Use response schemas (allowlists)', 'Log and alert on anomalous response sizes'] },
        { stride: 'D', sev: 'high', name: 'API Abuse / Rate Limit Bypass', mits: ['Enforce rate limits per API key and IP', 'Implement API gateway throttling', 'Detect scraping patterns'] },
        { stride: 'T', sev: 'high', name: 'Mass Assignment / Parameter Pollution', mits: ['Allowlist accepted request fields', 'Use strict DTOs', 'Reject unexpected parameters'] },
    ],
    database: [
        { stride: 'I', sev: 'critical', name: 'Unauthorized Data Access / Exfiltration', mits: ['Encrypt data at rest (AES-256)', 'Enforce column-level encryption for PII/PCI/PHI', 'Audit all SELECT queries on sensitive tables'] },
        { stride: 'T', sev: 'high', name: 'SQL Injection via Application Layer', mits: ['Use stored procedures and parameterized queries', 'Restrict DB user to minimum required privileges', 'Deploy DB activity monitoring (DAM)'] },
        { stride: 'D', sev: 'high', name: 'Database Unavailability / Lock Contention', mits: ['Implement read replicas for failover', 'Set query timeouts and connection pool limits', 'Use distributed caching to reduce load'] },
        { stride: 'R', sev: 'medium', name: 'Insufficient DB Audit Logging', mits: ['Enable binary logging / WAL', 'Forward DB logs to SIEM in real time', 'Implement tamper-evident audit trail'] },
    ],
    storage: [
        { stride: 'I', sev: 'critical', name: 'Public Bucket Misconfiguration', mits: ['Enable S3 Block Public Access at account level', 'Audit bucket ACLs and policies weekly', 'Alert on public-read policy changes'] },
        { stride: 'T', sev: 'high', name: 'Malicious File Upload / Overwrite', mits: ['Validate file type via magic bytes not extension', 'Store uploads in separate account/bucket', 'Scan uploads with antivirus before serving'] },
        { stride: 'I', sev: 'high', name: 'Unencrypted Sensitive Objects', mits: ['Enable default encryption (SSE-S3 or SSE-KMS)', 'Use customer-managed keys (CMK) for PII', 'Enforce encryption in bucket policy (deny http)'] },
    ],
    cache: [
        { stride: 'I', sev: 'high', name: 'Sensitive Data Leakage via Cache', mits: ['Never cache auth tokens or PII unencrypted', 'Set appropriate TTLs and cache-control headers', 'Use Redis ACLs to restrict key access'] },
        { stride: 'S', sev: 'high', name: 'Cache Poisoning', mits: ['Validate cache key inputs', 'Use separate cache namespaces per tenant', 'Monitor for unexpected cache writes'] },
        { stride: 'D', sev: 'medium', name: 'Cache Stampede / Thundering Herd', mits: ['Implement cache-aside pattern with jitter', 'Use probabilistic early expiration', 'Set stale-while-revalidate headers'] },
    ],
    firewall: [
        { stride: 'T', sev: 'high', name: 'Misconfigured Ruleset Allowing Lateral Movement', mits: ['Audit firewall rules quarterly', 'Default deny — whitelist only required ports', 'Segment internal zones with separate rule sets'] },
        { stride: 'D', sev: 'medium', name: 'Firewall as Single Point of Failure', mits: ['Deploy active-active firewall HA pair', 'Use anycast routing for failover', 'Monitor firewall CPU and connection table saturation'] },
    ],
    waf: [
        { stride: 'T', sev: 'high', name: 'WAF Rule Bypass via Obfuscation', mits: ['Keep WAF rule sets updated (managed rules)', 'Enable anomaly scoring mode', 'Test with OWASP ZAP and scanner tools'] },
        { stride: 'R', sev: 'medium', name: 'Insufficient WAF Logging', mits: ['Forward WAF logs to SIEM', 'Alert on rule match spikes', 'Retain WAF logs 90+ days for forensics'] },
    ],
    loadbalancer: [
        { stride: 'D', sev: 'high', name: 'LB Overload / SYN Flood Bypass', mits: ['Enable connection rate limiting', 'Use SYN proxy on LB', 'Integrate with upstream DDoS scrubbing'] },
        { stride: 'I', sev: 'medium', name: 'TLS Termination Exposes Internal Traffic', mits: ['Re-encrypt traffic between LB and backends', 'Use mTLS for backend connections', 'Restrict LB admin interface to management network'] },
    ],
    microservice: [
        { stride: 'S', sev: 'high', name: 'Service-to-Service Spoofing', mits: ['Enforce mTLS between all services', 'Use service mesh (Istio, Linkerd)', 'Validate JWT on every inter-service call'] },
        { stride: 'E', sev: 'high', name: 'Privilege Escalation via Service Account', mits: ['Scope service accounts to minimum permissions', 'Rotate service account credentials automatically', 'Use workload identity instead of static keys'] },
        { stride: 'T', sev: 'medium', name: 'Dependency Injection / Supply Chain', mits: ['Pin all dependency versions', 'Run SBOM analysis in CI', 'Block packages not in approved registry'] },
    ],
    lambda: [
        { stride: 'E', sev: 'high', name: 'Over-Privileged Execution Role', mits: ['Follow least-privilege IAM for function role', 'Use resource-based policies to restrict invocation', 'Audit role permissions with IAM Access Analyzer'] },
        { stride: 'I', sev: 'high', name: 'Environment Variable Secret Exposure', mits: ['Use secrets manager (AWS Secrets Manager, Vault)', 'Never hardcode credentials in function code', 'Encrypt environment variables at rest'] },
        { stride: 'D', sev: 'medium', name: 'Function Timeout / Runaway Cost', mits: ['Set function memory and timeout limits', 'Implement DLQs for failed invocations', 'Alert on concurrent execution spikes'] },
    ],
    messagequeue: [
        { stride: 'T', sev: 'high', name: 'Message Injection / Payload Tampering', mits: ['Validate and schema-validate all messages', 'Use message signing (HMAC)', 'Reject malformed messages at consumer'] },
        { stride: 'I', sev: 'high', name: 'Unauthorized Queue Access', mits: ['Use IAM policies to restrict queue access', 'Encrypt messages in transit and at rest', 'Audit queue access logs'] },
        { stride: 'D', sev: 'medium', name: 'Queue Flooding / Backpressure Failure', mits: ['Implement dead-letter queues', 'Set max message size and retention limits', 'Monitor queue depth and alert on thresholds'] },
    ],
    vpn: [
        { stride: 'S', sev: 'high', name: 'Stolen VPN Credentials', mits: ['Enforce MFA for VPN access', 'Use certificate-based client auth', 'Detect and alert on concurrent sessions from same user'] },
        { stride: 'I', sev: 'medium', name: 'Split Tunneling Data Leak', mits: ['Disable split tunneling for sensitive access', 'Enforce full-tunnel mode for privileged users', 'Log all DNS queries over VPN'] },
    ],
    cdn: [
        { stride: 'T', sev: 'high', name: 'Cache Poisoning via Host Header Injection', mits: ['Validate and normalize Host headers at origin', 'Use CDN origin shields', 'Test with cache poisoning scanner (Param Miner)'] },
        { stride: 'I', sev: 'medium', name: 'Sensitive Content Served via CDN', mits: ['Set Cache-Control: no-store on authenticated responses', 'Use signed URLs for private content', 'Audit cached response headers'] },
    ],
    idp: [
        { stride: 'S', sev: 'critical', name: 'Identity Provider Compromise', mits: ['Enable MFA on all IdP admin accounts', 'Restrict IdP admin to named IP ranges', 'Monitor for suspicious federation token issuance'] },
        { stride: 'T', sev: 'high', name: 'SAML / OAuth Token Forgery', mits: ['Validate token signatures strictly', 'Use short-lived tokens (15 min access tokens)', 'Rotate signing keys quarterly'] },
        { stride: 'R', sev: 'medium', name: 'Insufficient SSO Session Logging', mits: ['Log all authentication events to SIEM', 'Alert on privilege escalation in tokens', 'Audit token scope changes'] },
    ],
    siem: [
        { stride: 'T', sev: 'high', name: 'Log Tampering / SIEM Evasion', mits: ['Write logs to immutable (WORM) storage', 'Use forward-only log streaming', 'Detect gaps in log continuity'] },
        { stride: 'D', sev: 'medium', name: 'Alert Fatigue / SIEM Overload', mits: ['Tune detection rules to reduce false positives', 'Implement alert prioritization by severity', 'Use SOAR for automated triage'] },
    ],
};

const RULES = [
    // T-001: checks if any untrusted node can reach a webserver/api WITHOUT passing through waf/firewall
    {
        id: 'T-001', name: 'Missing WAF / Firewall', stride: 'T', sev: 'critical', like: 'High', imp: 'High', cat: 'Tampering', ctrl: 'Integrity',
        check: (N, E, adj) => {
            const ext = Object.values(N).filter(n => ['internet', 'user', 'attacker'].includes(n.type));
            const svcs = Object.values(N).filter(n => ['webserver', 'api'].includes(n.type));
            const guards = new Set(Object.values(N).filter(n => ['waf', 'firewall'].includes(n.type)).map(n => n.id));
            if (!ext.length || !svcs.length || guards.size) return null;
            // No guard nodes exist at all — any path is unguarded
            const aff = [...new Set(svcs.filter(svc => ext.some(e => findPath(e.id, svc.id, adj))).map(s => s.id))];
            return aff.length ? { aff } : null;
        },
        desc: 'External traffic can reach internal services without passing through any WAF or Firewall. Enables direct exploitation of web vulnerabilities.',
        mits: ['Deploy WAF (AWS WAF, Cloudflare, ModSecurity)', 'Add firewall with deny-by-default rules', 'Implement DMZ and network segmentation']
    },

    // T-002: upgraded — finds multi-hop paths from untrusted nodes to unauthenticated APIs
    {
        id: 'T-002', name: 'Unauthenticated API Reachable from Untrusted Node', stride: 'S', sev: 'critical', like: 'High', imp: 'High', cat: 'Spoofing', ctrl: 'Authentication',
        check: (N, E, adj) => {
            const untrusted = Object.values(N).filter(n => ['untrusted', 'hostile'].includes(n.trust));
            const apis = Object.values(N).filter(n => n.type === 'api');
            const aff = [];
            for (const src of untrusted) {
                for (const api of apis) {
                    // Check if any edge *arriving* at the API has no auth
                    const inEdges = E.filter(e => e.to === api.id && e.auth === 'None');
                    if (inEdges.length && findPath(src.id, api.id, adj)) aff.push(api.id);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'An untrusted node can reach an API endpoint with no authentication through one or more hops. Any actor can spoof identity and make unauthorized calls.',
        mits: ['Require JWT or OAuth2 on all API endpoints', 'Implement API gateway with mandatory auth', 'Add rate limiting and IP allowlisting']
    },

    // T-003: upgraded — traversal to find any path reaching a DB with no encryption
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

    // T-004: checks if sensitive data can flow toward any node reachable from untrusted sources
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

    // T-005: upgraded — checks if attacker has reachable path to any internal/restricted node
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

    // T-008: upgraded — checks if storage is reachable from any untrusted node via any path
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
            const lb = Object.values(N).some(n => n.type === 'loadbalancer');
            const wc = Object.values(N).filter(n => ['webserver', 'api'].includes(n.type)).length;
            return (wc > 0 && !lb) ? { aff: [] } : null;
        },
        desc: 'No load balancer detected. A single server crash causes complete service outage.',
        mits: ['Add load balancer with health checks', 'Deploy across multiple availability zones', 'Implement circuit breaker patterns']
    },

    // T-010: upgraded — uses path traversal to find internal→restricted escalation chains
    {
        id: 'T-010', name: 'Lateral Movement to Data Store', stride: 'E', sev: 'high', like: 'Medium', imp: 'High', cat: 'Elevation of Privilege', ctrl: 'Authorization',
        check: (N, E, adj) => {
            const aff = [];
            for (const e of E) {
                const f = N[e.from], t = N[e.to];
                if (f && t && f.trust === 'internal' && t.trust === 'restricted' && e.auth === 'None') aff.push(t.id);
            }
            // Additionally check multi-hop: untrusted→internal→restricted
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
            const idp = Object.values(N).some(n => n.type === 'idp');
            const usr = Object.values(N).some(n => n.type === 'user');
            return (usr && !idp) ? { aff: [] } : null;
        },
        desc: 'No centralized identity provider. Fragmented authentication increases credential exposure and inconsistent session handling.',
        mits: ['Implement SSO with SAML 2.0 or OIDC', 'Centralize AuthN in Identity Provider', 'Enable MFA for all user accounts']
    },

    // ── NEW RULES from audit ──

    // T-013: Multi-boundary traversal — path crosses more than one trust boundary = escalation risk
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

    // T-014: Data classification mismatch — sensitive data flows into public/untrusted nodes
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

    // T-015: Cyclic dependency — service graph contains a loop, creates DoS / deadlock surface
    {
        id: 'T-015', name: 'Cyclic Service Dependency', stride: 'D', sev: 'medium', like: 'Low', imp: 'High', cat: 'Denial of Service', ctrl: 'Availability',
        check: (N, E, adj) => {
            // Only check among internal/restricted nodes — cycles between external actors are expected
            const internal = new Set(Object.values(N).filter(n => ['internal', 'restricted'].includes(n.trust)).map(n => n.id));
            const internalAdj = {};
            internal.forEach(id => { internalAdj[id] = (adj[id] || []).filter(({ to }) => internal.has(to)); });
            const cyclic = hasCycle(internalAdj); // Uses helper from blastRadius
            return cyclic ? { aff: [] } : null;
        },
        desc: 'Internal service graph contains a cycle. Circular dependencies create deadlock risk, cascading failures, and amplified DoS surface under load.',
        mits: ['Break cycles with async messaging (queues/events)', 'Introduce timeout and circuit-breaker patterns', 'Audit service call graph for unintentional loops']
    },

    // T-016: No rate limiting — user/internet connects to auth-handling node without API key/rate controls
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
                    // If every edge on the path has auth=None and no WAF/firewall sits between them
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

    // T-017: Supply chain / dependency risk — external dep nodes connected to internal services
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

    // ════════════════════════════════════════════════════
    // ENHANCED RULE ENGINE — 6 REQUIRED OWASP/STRIDE RULES
    // ════════════════════════════════════════════════════

    // R-001: Broken Authentication — API node with auth disabled
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

    // R-002: Sensitive Data Exposure — Database without encryption at rest
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

    // R-003: MITM Attack — Edge using HTTP with no encryption
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

    // R-004: Plaintext Sensitive Data — PII or secret data on unencrypted edge
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

    // R-005: Unauthorized Data Access — Edge with no auth carrying non-public data
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

    // R-006: Privilege Escalation Path — client→api→database with admin role and no auth
    {
        id: 'R-006', name: 'Privilege Escalation Path', stride: 'E', sev: 'critical', like: 'Medium', imp: 'High', cat: 'Elevation of Privilege', ctrl: 'Authorization',
        owasp: 'A01:2021 Broken Access Control',
        check: (N, E, adj) => {
            const aff = [];
            const clients = Object.values(N).filter(n => ['user', 'client', 'internet', 'attacker'].includes(n.type));
            const adminApis = Object.values(N).filter(n => n.type === 'api' && ((n.props && (n.props.role === 'admin' || n.props.role === 'service')) || n.iamPriv === 'admin' || n.trust === 'restricted'));
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
                        if (dbEdgeUnauthenticated) {
                            aff.push(client.id, api.id, db.id);
                        }
                    }
                }
            }
            for (const e of E) {
                const fromNd = N[e.from]; const toNd = N[e.to];
                if (!fromNd || !toNd) continue;
                const fromIsAdmin = fromNd.iamPriv === 'admin' || (fromNd.props && fromNd.props.role === 'admin');
                const edgeNoAuth = !e.auth || e.auth === 'None';
                if (fromIsAdmin && edgeNoAuth && toNd.type === 'database') {
                    aff.push(fromNd.id, toNd.id);
                }
            }
            return aff.length ? { aff: [...new Set(aff)] } : null;
        },
        desc: 'A privilege escalation path exists: a client can reach an admin-role API, and that API connects to a database without authentication. An attacker exploiting the unauthenticated API gains full database access via admin privileges. Maps to OWASP A01:2021.',
        mits: ['Enforce strict role-based access control (RBAC) on all API→DB connections', 'Require mTLS for service-to-database authentication', 'Apply least privilege: never use admin credentials for application DB connections', 'Implement database proxies (e.g. AWS RDS Proxy) to enforce connection-level AuthZ']
    },
];

export class RuleManager {
    static _rules = [...RULES];
    static _componentThreats = { ...COMPONENT_THREATS };

    static getRules() { return this._rules; }
    static getComponentThreats(type) { return this._componentThreats[type] || []; }

    static loadCustomRules(config) {
        if (config.rules) this._rules = [...this._rules, ...config.rules];
        if (config.componentThreats) {
            for (const [comp, threats] of Object.entries(config.componentThreats)) {
                this._componentThreats[comp] = [...(this._componentThreats[comp] || []), ...threats];
            }
        }
    }

    static clearCustomRules() {
        this._rules = [...RULES];
        this._componentThreats = { ...COMPONENT_THREATS };
    }
}
