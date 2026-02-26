import { getState, setCmRows, setThreats } from '../state/state.js';
import { RuleManager } from './threatEngine.js';
import { buildAdjacency, findPath, trustBoundaryCrossings } from './blastRadius.js';
import { renderDetected, renderCM, drawAttackPathsList, setAnalysisModePanel } from '../ui/dom.js';
import { sc, sn } from '../utils/helpers.js';

export let S_attackPaths = [];
export let S_boundaryFindings = [];

function normalizeNodes(N) {
    Object.values(N).forEach(n => {
        if (!n.props) n.props = {};
        if (n.props.auth === undefined) n.props.auth = true;
        if (n.props.encryption === undefined) n.props.encryption = true;
    });
}

function normalizeEdges(E) {
    E.forEach(e => {
        e.protocol = e.protocol || 'HTTPS';
        e.dataClass = e.dataClass || 'Internal';
        e.auth = e.auth || 'API Key';
        e.encryption = e.encryption || 'TLS 1.2+';
        e.credScope = e.credScope || 'shared';
        e.networkRoute = e.networkRoute || 'direct';
        e.trustBoundary = e.trustBoundary || 'No';
    });
}

export function runFullAnalysis(N, E) {
    S_attackPaths = [];
    S_boundaryFindings = [];

    const untrusted = Object.values(N).filter(n => ['untrusted', 'hostile'].includes(n.trust));
    const restricted = Object.values(N).filter(n => n.trust === 'restricted');
    const dbs = Object.values(N).filter(n => n.type === 'database');
    const adj = buildAdjacency(N, E);

    // 1: Multi-hop unauthenticated path to DB
    for (const src of untrusted) {
        for (const db of dbs) {
            const path = findPath(src.id, db.id, adj);
            if (!path) continue;
            const noAuthPath = path.slice(0, -1).every((id, idx) => {
                const edge = E.find(e => e.from === id && e.to === path[idx + 1]);
                return edge && edge.auth === 'None';
            });
            if (noAuthPath) {
                S_attackPaths.push({
                    severity: 'critical',
                    name: 'Unauthenticated Path to Database',
                    desc: 'A full path exists from an untrusted source to a restricted database where every connection lacks authentication.',
                    path: path
                });
            }
        }
    }

    // 2: Multi-boundary traversal
    for (const src of untrusted) {
        for (const dst of restricted) {
            const path = findPath(src.id, dst.id, adj);
            if (path && trustBoundaryCrossings(path, E) >= 2) {
                S_boundaryFindings.push({
                    severity: 'high',
                    name: 'Excessive Boundary Traversal',
                    desc: 'Path crosses multiple trust boundaries, increasing privilege escalation risk.',
                    path: path,
                    edges: path.map((id, idx) => {
                        if (idx === path.length - 1) return null;
                        const ed = E.find(e => e.from === id && e.to === path[idx + 1]);
                        return ed ? ed.id : null;
                    }).filter(Boolean)
                });
            }
        }
    }
}

export function runAnalysis() {
    const S = getState();
    if (!Object.keys(S.nodes).length) { alert('Add components to the DFD first.'); return; }

    document.querySelectorAll('.node-pills').forEach(p => p.innerHTML = '');
    setThreats([]);

    const N = S.nodes;
    const E = S.edges;
    normalizeNodes(N);
    normalizeEdges(E);

    const adj = buildAdjacency(N, E);
    const newThreats = [];
    const cmRows = S.cmRows;

    for (const rule of RuleManager.getRules()) {
        const res = rule.check(N, E, adj);
        if (res) {
            newThreats.push({ ...rule, affected: res.aff || [] });
            (res.aff || []).forEach(nid => {
                const pp2 = document.getElementById('pills-' + nid);
                if (pp2 && !pp2.querySelector(`[data-t="${rule.id}"]`)) {
                    const pill = document.createElement('span');
                    pill.className = 'pill'; pill.dataset.t = rule.id;
                    pill.style.cssText = `background:${sc(rule.sev)}22;color:${sc(rule.sev)};border:1px solid ${sc(rule.sev)}55`;
                    pill.textContent = rule.id;
                    pp2.appendChild(pill);
                }
            });
            if (!cmRows[rule.id]) cmRows[rule.id] = { response: 'Mitigate', status: 'Non-Mitigated' };
        }
    }

    setThreats(newThreats);
    setCmRows(cmRows);
    runFullAnalysis(N, E);

    renderDetected(getState());
    const cnts = { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 };
    newThreats.forEach(t => cnts[t.stride] = (cnts[t.stride] || 0) + 1);
    Object.entries(cnts).forEach(([k, v]) => { const el = document.getElementById('c' + k); if (el) el.textContent = v; });

    const apCount = S_attackPaths.length;
    const bvCount = S_boundaryFindings.length;
    document.getElementById('statusBar').textContent = `Analysis complete — ${newThreats.length} threats · ${apCount} attack paths · ${bvCount} boundary violations`;
    document.getElementById('stab3').classList.add('done');

    const apBadge = document.getElementById('apTabBadge');
    if (apBadge) apBadge.textContent = apCount + bvCount;

    // Update UI Panels
    drawAttackPathsList(S_attackPaths, S_boundaryFindings, S);
    renderCM();
}
