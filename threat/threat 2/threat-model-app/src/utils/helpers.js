/**
 * UTILITY FUNCTIONS
 * Shared helpers used across UI and engine modules.
 */

/** Severity → hex color */
export function sc(s) {
    return { critical: '#ef4444', high: '#f97316', medium: '#facc15', low: '#34d399' }[s] || '#888';
}

/** STRIDE letter → full name */
export function sn(s) {
    return { S: 'Spoofing', T: 'Tampering', R: 'Repudiation', I: 'Information Disclosure', D: 'Denial of Service', E: 'Elevation of Privilege' }[s] || s;
}

/** STRIDE letter → hex color */
export function scolor(s) {
    return { S: '#9b59b6', T: '#e67e22', R: '#3498db', I: '#e74c3c', D: '#2ecc71', E: '#ff6b6b' }[s] || '#888';
}

/** Risk Rating matrix: (likelihood, impact) → risk level */
export function rr(l, i) {
    const m = {
        'High,High': 'Critical', 'High,Medium': 'High', 'High,Low': 'Medium',
        'Medium,High': 'High', 'Medium,Medium': 'Medium', 'Medium,Low': 'Low',
        'Low,High': 'Medium', 'Low,Medium': 'Low', 'Low,Low': 'Low'
    };
    return m[`${l},${i}`] || 'Medium';
}

/** Promise-based delay */
export function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/** Show/hide the empty hint on the DFD canvas */
export function upHint(nodes) {
    const hint = document.getElementById('emptyHint');
    if (hint) hint.style.display = Object.keys(nodes).length ? 'none' : 'block';
}
