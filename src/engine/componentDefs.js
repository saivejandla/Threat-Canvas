/**
 * COMPONENT DEFINITIONS
 * Maps node type keys → default visual and security properties.
 */
export const DEFS = {
    internet: { label: 'Internet', icon: '🌐', color: '#ff6b6b', body: 'External Network', trust: 'untrusted', zone: 'public', trustZone: 'internet', iamPriv: 'none' },
    user: { label: 'User', icon: '👤', color: '#4d9de0', body: 'Client / Browser', trust: 'untrusted', zone: 'public', trustZone: 'internet', iamPriv: 'none' },
    attacker: { label: 'Attacker', icon: '☠️', color: '#ff4444', body: 'Threat Actor', trust: 'hostile', zone: 'public', trustZone: 'internet', iamPriv: 'none' },
    firewall: { label: 'Firewall', icon: '🔥', color: '#ff8c00', body: 'Rules Engine', trust: 'trusted', zone: 'dmz', trustZone: 'dmz', iamPriv: 'none', isDetector: true },
    loadbalancer: { label: 'Load Balancer', icon: '⚖️', color: '#f59e0b', body: 'L7 LB', trust: 'trusted', zone: 'dmz', trustZone: 'dmz', iamPriv: 'none' },
    vpn: { label: 'VPN Gateway', icon: '🔒', color: '#4d9de0', body: 'Encrypted Tunnel', trust: 'trusted', zone: 'dmz', trustZone: 'dmz', iamPriv: 'none' },
    cdn: { label: 'CDN', icon: '☁️', color: '#60a5fa', body: 'Edge Cache', trust: 'trusted', zone: 'public', trustZone: 'internet', iamPriv: 'none' },
    webserver: { label: 'Web Server', icon: '🖥', color: '#0066ff', body: 'nginx / Apache', trust: 'internal', zone: 'private', trustZone: 'internal', iamPriv: 'standard' },
    api: { label: 'API Server', icon: '⚡', color: '#f59e0b', body: 'REST / GraphQL', trust: 'internal', zone: 'private', trustZone: 'internal', iamPriv: 'standard' },
    microservice: { label: 'Microservice', icon: '🔧', color: '#4d9de0', body: 'Service Mesh', trust: 'internal', zone: 'private', trustZone: 'internal', iamPriv: 'standard' },
    lambda: { label: 'Serverless', icon: 'λ', color: '#ff8c00', body: 'FaaS', trust: 'internal', zone: 'private', trustZone: 'internal', iamPriv: 'standard' },
    database: { label: 'Database', icon: '🗄', color: '#ff6b6b', body: 'PostgreSQL/MySQL', trust: 'restricted', zone: 'isolated', trustZone: 'restricted', iamPriv: 'none' },
    cache: { label: 'Cache', icon: '⚡', color: '#ffd93d', body: 'Redis/Memcached', trust: 'restricted', zone: 'isolated', trustZone: 'restricted', iamPriv: 'none' },
    storage: { label: 'Object Storage', icon: '📦', color: '#60a5fa', body: 'S3 / GCS', trust: 'restricted', zone: 'isolated', trustZone: 'restricted', iamPriv: 'none' },
    messagequeue: { label: 'Message Queue', icon: '📨', color: '#4d9de0', body: 'Kafka/RabbitMQ', trust: 'internal', zone: 'private', trustZone: 'internal', iamPriv: 'none' },
    waf: { label: 'WAF', icon: '🛡', color: '#ff8c00', body: 'Web App Firewall', trust: 'trusted', zone: 'dmz', trustZone: 'dmz', iamPriv: 'none', isDetector: true },
    idp: { label: 'Identity Provider', icon: '🔑', color: '#f59e0b', body: 'OAuth2/SAML', trust: 'trusted', zone: 'private', trustZone: 'internal', iamPriv: 'none' },
    siem: { label: 'SIEM', icon: '👁', color: '#ff4444', body: 'Log Analytics', trust: 'trusted', zone: 'private', trustZone: 'internal', iamPriv: 'none', isDetector: true },
};

/**
 * DETECTOR PROBABILITIES
 * Each detector node type adds detection probability during blast radius BFS.
 */
export const DETECTOR_PROBS = {
    siem: 0.85,
    waf: 0.60,
    firewall: 0.45,
    idp: 0.70,
};

/**
 * COMPONENT THREAT PROFILES
 * Per-node-type STRIDE threat library.
 */
export const COMPONENT_THREATS = {
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
