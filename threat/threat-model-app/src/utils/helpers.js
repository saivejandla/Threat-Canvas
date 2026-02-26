export const sc = (s) => ({
    critical: '#ef4444',
    high: '#f97316',
    medium: '#facc15',
    low: '#34d399'
}[s]);

export const sn = (s) => ({
    S: 'Spoofing',
    T: 'Tampering',
    R: 'Repudiation',
    I: 'Info Disclosure',
    D: 'Denial of Service',
    E: 'Elev. of Privilege'
}[s]);

export const scolor = (s) => ({
    S: '#9b59b6',
    T: '#e67e22',
    R: '#3498db',
    I: '#e74c3c',
    D: '#2ecc71',
    E: '#ff6b6b'
}[s]);

export const rr = (s, l, ip) => {
    const m = { critical: 4, high: 3, medium: 2, low: 1 };
    const score = m[l.toLowerCase()] * m[ip.toLowerCase()];
    return score >= 12 ? 'Critical' : score >= 6 ? 'High' : score >= 4 ? 'Medium' : 'Low';
};

export const escapeHTML = (str) => {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
};
