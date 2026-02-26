/**
 * THREAT GLOSSARY — Beginner-friendly definitions for security terms
 * Used to inject hover tooltips into threat descriptions and mitigations.
 */

export const THREAT_GLOSSARY = {
    'Lateral Movement': 'When an attacker who has compromised one server uses it as a stepping stone to reach other systems on the internal network.',
    'Trust Boundary': 'A line between two zones with different security levels (e.g., the public internet vs. your internal network). Data crossing this line needs extra protection.',
    'Spoofing': 'When an attacker pretends to be someone or something else to gain unauthorized access.',
    'Tampering': 'When an attacker modifies data or code without authorization — like changing a price in a shopping cart request.',
    'Repudiation': 'When someone can deny performing an action because there are no logs or audit trails to prove it happened.',
    'Information Disclosure': 'When sensitive data is exposed to people who shouldn\'t have access — like passwords appearing in plain text.',
    'Denial of Service': 'An attack that overwhelms a system so legitimate users can\'t access it — like flooding a website with fake traffic.',
    'Elevation of Privilege': 'When an attacker gains higher access rights than they should have — like a regular user getting admin permissions.',
    'STRIDE': 'A framework for categorizing threats: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.',
    'Blast Radius': 'How far an attacker could reach if they compromised a single node. Think of it like an explosion — how much damage spreads from the point of compromise.',
    'WAF': 'Web Application Firewall — a security tool that filters and monitors HTTP traffic between a web application and the Internet.',
    'PII': 'Personally Identifiable Information — data that can identify a person, like names, emails, SSNs, or credit card numbers.',
    'mTLS': 'Mutual TLS — both the client and server verify each other\'s identity using certificates, not just the server.',
    'SIEM': 'Security Information and Event Management — a tool that collects and analyzes security logs from across your infrastructure to detect attacks.',
    'DLP': 'Data Loss Prevention — tools and policies that prevent sensitive data from leaving your organization\'s network.',
    'HSTS': 'HTTP Strict Transport Security — tells browsers to only connect to your site using HTTPS, never plain HTTP.',
    'JWT': 'JSON Web Token — a compact, URL-safe token used to securely transmit information between parties for authentication.',
    'OAuth2': 'An authorization framework that lets users grant third-party apps limited access to their accounts without sharing passwords.',
    'Zero Trust': 'A security model that assumes no one is trusted by default — every request must be authenticated and authorized, even from inside the network.',
    'DMZ': 'Demilitarized Zone — a network segment that sits between the public internet and your private internal network, acting as a buffer.',
    'RBAC': 'Role-Based Access Control — users are assigned roles (like admin, viewer, editor) and each role has specific permissions.',
    'Data Classification': 'Labeling data by sensitivity level (Public, Internal, Confidential, PII) so you know how to protect it. This is the foundation of threat modeling.',
    'Micro-segmentation': 'Dividing your network into very small zones so that even if an attacker gets in, they can only access a tiny part of it.',
    'Circuit Breaker': 'A design pattern that stops calling a failing service after repeated failures, preventing cascading crashes across your system.',
};

/**
 * Wraps known glossary terms in a given HTML string with tooltip spans.
 * Only replaces terms that appear as whole words (not inside HTML tags).
 * @param {string} html - The HTML string to process
 * @returns {string} HTML with glossary terms wrapped in tooltip spans
 */
export function injectGlossaryTooltips(html) {
    // Sort terms by length (longest first) to avoid partial matches
    const terms = Object.keys(THREAT_GLOSSARY).sort((a, b) => b.length - a.length);
    let result = html;
    const replaced = new Set();
    for (const term of terms) {
        if (replaced.has(term)) continue;
        const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // Simple word-boundary match, skip if already inside an HTML tag
        const regex = new RegExp(`\\b(${escaped})\\b`, 'g');
        const tooltip = THREAT_GLOSSARY[term].replace(/'/g, '&#39;').replace(/"/g, '&quot;');
        // Only replace in text, not inside HTML tags
        result = result.replace(regex, (match, p1, offset) => {
            // Check if we're inside an HTML tag by looking for < before >
            const before = result.substring(Math.max(0, offset - 200), offset);
            const lastOpen = before.lastIndexOf('<');
            const lastClose = before.lastIndexOf('>');
            if (lastOpen > lastClose) return match; // Inside a tag
            // Check if already wrapped
            const nearBefore = result.substring(Math.max(0, offset - 50), offset);
            if (nearBefore.includes('glossary-term')) return match;
            replaced.add(term);
            return `<span class="glossary-term" title="${tooltip}">${p1} <span class="glossary-icon">\u2139</span></span>`;
        });
    }
    return result;
}
