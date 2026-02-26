/**
 * ATTACK PATH DETECTION & BOUNDARY VIOLATION ANALYSIS
 */
import {
    S, S_attackPaths, S_boundaryFindings, S_pathFindings,
    setAttackPathState, _highlightedPathIdx, setHighlightedPathIdx
} from '../state/state.js';
import { buildGraph, findAllPaths, getEntryNodes, resolveNode } from './graphEngine.js';
import { sc } from '../utils/helpers.js';
import { redraw, pp } from '../ui/renderSVG.js';
import { renderTrustZoneOverlays } from '../ui/trustZones.js';

export const TZ_ORDER = { internet: 0, dmz: 1, internal: 2, restricted: 3 };

export function detectAttackPaths(nodes, edges) {
    let apIdx = 1;
    const graph = buildGraph(nodes, edges);
    const entryNodes = getEntryNodes(nodes);
    const attackPaths = [];

    entryNodes.forEach(entry => {
        const allPaths = findAllPaths(graph, entry.id, 6);
        allPaths.forEach(path => {
            if (path.length < 2) return;
            const targetId = path[path.length - 1];
            const targetNode = resolveNode(nodes, targetId);
            if (!targetNode) return;

            const isHighValue =
                targetNode.type === 'database' ||
                targetNode.type === 'storage' ||
                targetNode.trustZone === 'restricted' ||
                ['secret', 'pii', 'phi', 'pci'].includes((targetNode.props?.dataClassification || '').toLowerCase());

            if (!isHighValue) return;

            const pathEdges = [];
            for (let i = 0; i < path.length - 1; i++) {
                const e = edges.find(ed => (ed.from || ed.source) === path[i] && (ed.to || ed.target) === path[i + 1]);
                if (e) pathEdges.push(e);
            }
            const hasUnencrypted = pathEdges.some(e => !e.encryption || e.encryption === 'None' || e.encryption === 'none');
            const hasNoAuth = pathEdges.some(e => !e.auth || e.auth === 'None' || e.auth === 'none');
            const crossesBoundary = path.some((nid, i) => {
                if (i === 0) return false;
                const prev = resolveNode(nodes, path[i - 1]);
                const cur = resolveNode(nodes, nid);
                if (!prev || !cur) return false;
                return (prev.trustZone || 'internal') !== (cur.trustZone || 'internal');
            });

            let risk = 'HIGH';
            let reasons = [];
            if (entry.type === 'attacker') risk = 'CRITICAL';
            if (targetNode.trustZone === 'restricted' || targetNode.type === 'database') {
                if (hasUnencrypted && hasNoAuth) risk = 'CRITICAL';
            }
            if (hasUnencrypted) reasons.push('plaintext channel');
            if (hasNoAuth) reasons.push('unauthenticated edge');
            if (crossesBoundary) reasons.push('trust boundary crossed');

            attackPaths.push({
                id: 'AP-' + (apIdx++),
                path,
                pathLabels: path.map(id => { const n = resolveNode(nodes, id); return n ? n.label : id; }),
                risk, entryNode: entry, targetNode, reasons,
                reason: reasons.length ? reasons.join(', ') : 'Path from internet to sensitive data',
                owasp: 'A01:2021 Broken Access Control',
                hasUnencrypted, hasNoAuth, crossesBoundary, pathEdges,
            });
        });
    });

    const seen = new Map();
    attackPaths.forEach(ap => {
        const key = ap.path[0] + ':' + ap.path[ap.path.length - 1];
        const riskOrd = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        const existing = seen.get(key);
        if (!existing || riskOrd[ap.risk] < riskOrd[existing.risk]) seen.set(key, ap);
    });
    return [...seen.values()].sort((a, b) => {
        const ord = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        return ord[a.risk] - ord[b.risk];
    });
}

export function detectBoundaryViolations(nodes, edges) {
    const findings = [];
    edges.forEach(edge => {
        const srcId = edge.source || edge.from;
        const tgtId = edge.target || edge.to;
        const source = resolveNode(nodes, srcId);
        const target = resolveNode(nodes, tgtId);
        if (!source || !target) return;

        const srcZone = source.trustZone || source.zone || 'internal';
        const tgtZone = target.trustZone || target.zone || 'internal';
        if (srcZone === tgtZone) return;

        const noAuth = !edge.auth || edge.auth === 'None' || edge.auth === 'none';
        const noEnc = !edge.encryption || edge.encryption === 'None' || edge.encryption === 'none';
        const isEscalating = TZ_ORDER[srcZone] === undefined || TZ_ORDER[tgtZone] === undefined
            ? false : TZ_ORDER[srcZone] < TZ_ORDER[tgtZone];

        let severity = 'Medium', sevKey = 'medium';
        if (noAuth && noEnc && isEscalating) { severity = 'Critical'; sevKey = 'critical'; }
        else if (noAuth || noEnc) { severity = 'High'; sevKey = 'high'; }

        if (noAuth || noEnc) {
            findings.push({
                id: 'BV-' + edge.id, type: 'boundary', ruleType: 'edge',
                threat: 'Insecure Trust Boundary Crossing', name: 'Insecure Trust Boundary Crossing',
                stride: 'E', sev: sevKey, owasp: 'A01:2021 Broken Access Control',
                severity, edgeId: edge.id, srcZone, tgtZone,
                sourceName: source.label || srcId, targetName: target.label || tgtId,
                sourceId: srcId, targetId: tgtId, isEscalating, noAuth, noEnc,
                desc: `${source.label || srcId} (${srcZone}) → ${target.label || tgtId} (${tgtZone}) crosses a trust boundary without ${noAuth && noEnc ? 'authentication or encryption' : noAuth ? 'authentication' : 'encryption'}. This allows unauthorized access across security zones.`,
                like: 'High', imp: 'High',
                mits: ['Enforce mTLS at every trust boundary crossing', 'Require strong authentication (JWT/OAuth2) for cross-zone calls', 'Deploy an API gateway or service mesh at zone boundaries', 'Use network micro-segmentation to enforce zone isolation'],
                affected: [srcId, tgtId],
            });
        }
    });
    return findings;
}

export function evaluatePathRules(graph, nodes, edges) {
    const findings = [];
    const entryNodes = getEntryNodes(nodes);

    // PR-001: Privilege escalation path
    const pathPrivEscRule = {
        id: 'PR-001', name: 'Privilege Escalation Path (Graph)', stride: 'E', sev: 'critical',
        like: 'Medium', imp: 'High', owasp: 'A01:2021 Broken Access Control',
        desc: 'A traversal path exists containing an admin-privileged node reachable via an unauthenticated edge. An attacker can exploit the missing auth to inherit elevated privileges.',
        mits: ['Enforce authentication on every edge involving admin-role nodes', 'Implement least-privilege: no admin credentials for application paths', 'Add network-layer ACLs to block unauthenticated admin access'],
    };
    entryNodes.forEach(entry => {
        const allPaths = findAllPaths(graph, entry.id, 5);
        allPaths.forEach(path => {
            const hasAdmin = path.some(nid => { const n = resolveNode(nodes, nid); return n?.iamPriv === 'admin' || (n?.props?.role === 'admin'); });
            if (!hasAdmin) return;
            const hasNoAuthEdge = path.some((_, i) => {
                if (i === 0) return false;
                const e = edges.find(ed => (ed.from || ed.source) === path[i - 1] && (ed.to || ed.target) === path[i]);
                return e && (!e.auth || e.auth === 'None' || e.auth === 'none');
            });
            if (hasAdmin && hasNoAuthEdge) {
                const aff = [...new Set(path)];
                if (!findings.find(f => f.id === pathPrivEscRule.id)) {
                    findings.push({
                        ...pathPrivEscRule, affected: aff,
                        desc: pathPrivEscRule.desc + ` Path: ${path.map(id => { const n = resolveNode(nodes, id); return n?.label || id; }).join(' → ')}`
                    });
                }
            }
        });
    });

    // PR-002: Deep penetration path
    const deepPenetrateRule = {
        id: 'PR-002', name: 'Deep Penetration Path (Internet → Restricted Zone)', stride: 'E', sev: 'critical',
        like: 'High', imp: 'High', owasp: 'A01:2021 Broken Access Control',
        desc: 'An internet-origin actor can traverse through intermediate zones to reach a restricted zone via a path with insufficient controls.',
        mits: ['Add WAF and firewall between internet and internal zones', 'Enforce zero-trust: every hop must authenticate', 'Deploy intrusion detection on zone boundary traffic'],
    };
    entryNodes.forEach(entry => {
        const allPaths = findAllPaths(graph, entry.id, 6);
        allPaths.forEach(path => {
            const zones = path.map(nid => { const n = resolveNode(nodes, nid); return n?.trustZone || 'internal'; });
            const hasInternet = zones[0] === 'internet';
            const hasRestricted = zones[zones.length - 1] === 'restricted';
            if (!hasInternet || !hasRestricted || path.length < 3) return;
            const pathEdges = [];
            for (let i = 0; i < path.length - 1; i++) {
                const e = edges.find(ed => (ed.from || ed.source) === path[i] && (ed.to || ed.target) === path[i + 1]);
                if (e) pathEdges.push(e);
            }
            const hasNoAuth = pathEdges.some(e => !e.auth || e.auth === 'None' || e.auth === 'none');
            const hasNoEnc = pathEdges.some(e => !e.encryption || e.encryption === 'None' || e.encryption === 'none');
            if (hasNoAuth && hasNoEnc) {
                const pathLabels = path.map(id => { const n = resolveNode(nodes, id); return n?.label || id; }).join(' → ');
                const existingRule = findings.find(f => f.id === deepPenetrateRule.id);
                if (!existingRule) {
                    findings.push({
                        ...deepPenetrateRule, affected: [...new Set(path)],
                        desc: `Multi-zone penetration path detected: ${pathLabels}. An internet-origin actor can traverse through intermediate zones to reach the restricted zone via unauthenticated, unencrypted connections.`,
                    });
                }
            }
        });
    });

    return findings;
}

/** Highlight a specific attack path on the canvas */
export function highlightAttackPath(apIdx) {
    clearAttackPathHighlights();
    const ap = S_attackPaths[apIdx];
    if (!ap) return;
    setHighlightedPathIdx(apIdx);

    ap.path.forEach((nid, i) => {
        const el = document.getElementById(nid);
        if (!el) return;
        if (i === 0) el.classList.add('atk-path-entry');
        else if (i === ap.path.length - 1) el.classList.add('atk-path-critical');
        else el.classList.add('atk-path-high');
    });

    _renderSVGWithAttackPath(ap);
}

export function clearAttackPathHighlights() {
    document.querySelectorAll('.node').forEach(el => {
        el.classList.remove('atk-path-critical', 'atk-path-high', 'atk-path-entry');
    });
    setHighlightedPathIdx(-1);
    redraw();
}

function _renderSVGWithAttackPath(ap) {
    const svg = document.getElementById('svgLayer');
    svg.querySelectorAll('.ap-edge-overlay').forEach(el => el.remove());

    const pathEdgeSet = new Set();
    for (let i = 0; i < ap.path.length - 1; i++) {
        pathEdgeSet.add(ap.path[i] + '->' + ap.path[i + 1]);
    }

    S.edges.forEach(e => {
        const from = e.from || e.source;
        const to = e.to || e.target;
        if (!pathEdgeSet.has(from + '->' + to)) return;
        const f = pp(from, 'r'), t = pp(to, 'l');
        if (!f || !t) return;
        const dx = (t.x - f.x) * .4;
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`);
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke', '#ef4444');
        path.setAttribute('stroke-width', '3');
        path.setAttribute('stroke-dasharray', '8 4');
        path.setAttribute('class', 'ap-edge-overlay');
        path.setAttribute('filter', 'drop-shadow(0 0 6px #ef4444)');
        path.style.animation = 'dash 1s linear infinite';
        svg.appendChild(path);
    });
}

/** Render the Attack Paths right panel */
export function renderAttackPaths() {
    const con = document.getElementById('attackPathsContainer');
    if (!con) return;

    if (!S_attackPaths.length && !S_boundaryFindings.length && !S_pathFindings.length) {
        con.innerHTML = '<div style="text-align:center;color:var(--text3);padding:16px 0;font-size:11px">No attack paths detected.<br>Run analysis first.</div>';
        return;
    }

    const riskColor = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#facc15', LOW: '#34d399' };
    const tzColor = { internet: '#ff6b6b', dmz: '#ff8c00', internal: '#60a5fa', secure: '#34d399' };

    let html = '';

    if (S_attackPaths.length) {
        html += `<div style="font-size:10px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:var(--text3);margin-bottom:7px">⚔️ Attack Paths (${S_attackPaths.length})</div>`;
        S_attackPaths.forEach((ap, i) => {
            const rc = riskColor[ap.risk] || '#f97316';
            const pathViz = ap.pathLabels.map((lbl, j) =>
                `<span class="ap-node-chip ${j === 0 ? 'ap-entry' : j === ap.pathLabels.length - 1 ? 'ap-target' : ''}">${lbl}</span>` +
                (j < ap.pathLabels.length - 1 ? '<span class="ap-arrow">→</span>' : '')
            ).join('');
            html += `<div class="ap-panel" data-ap-idx="${i}" title="Click to highlight on canvas">
        <div class="ap-header">
          <span class="ap-risk-badge" style="background:${rc}22;color:${rc};border:1px solid ${rc}44">${ap.risk}</span>
          <span style="font-size:10px;font-weight:700;color:var(--text)">Path ${i + 1}</span>
          <span style="font-size:9px;color:var(--text3);margin-left:auto">${ap.path.length} hops</span>
        </div>
        <div class="ap-path-viz">${pathViz}</div>
        <div class="ap-reason">${ap.reason}</div>
        <div class="ap-owasp">🔗 ${ap.owasp}</div>
      </div>`;
        });
    }

    if (S_pathFindings.length) {
        html += `<div style="font-size:10px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:var(--text3);margin:10px 0 7px">🔗 Path Rules (${S_pathFindings.length})</div>`;
        S_pathFindings.forEach(f => {
            html += `<div class="ap-panel" style="border-color:rgba(249,115,22,.3)">
        <div class="ap-header">
          <span class="ap-risk-badge" style="background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)">${f.sev.toUpperCase()}</span>
          <span style="font-size:10px;font-weight:700;color:var(--text)">${f.name}</span>
        </div>
        <div class="ap-reason" style="margin-top:4px">${f.desc}</div>
        <div class="ap-owasp">🔗 ${f.owasp || ''}</div>
      </div>`;
        });
    }

    if (S_boundaryFindings.length) {
        html += `<div style="font-size:10px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:var(--text3);margin:10px 0 7px">🚧 Boundary Violations (${S_boundaryFindings.length})</div>`;
        S_boundaryFindings.forEach(bv => {
            const sc2 = bv.severity === 'Critical' ? '#ef4444' : bv.severity === 'High' ? '#f97316' : '#facc15';
            html += `<div class="bv-card">
        <div class="bv-flow">
          <span class="bv-zone" style="background:${(tzColor[bv.srcZone] || '#888')}22;color:${tzColor[bv.srcZone] || '#888'}">${bv.srcZone.toUpperCase()}</span>
          <span>→</span>
          <span class="bv-zone" style="background:${(tzColor[bv.tgtZone] || '#888')}22;color:${tzColor[bv.tgtZone] || '#888'}">${bv.tgtZone.toUpperCase()}</span>
          <span style="margin-left:auto;font-size:9px;font-weight:800;color:${sc2}">${bv.severity.toUpperCase()}</span>
        </div>
        <div style="font-size:10px;color:var(--text2)">${bv.sourceName} → ${bv.targetName}</div>
        <div style="font-size:9px;color:var(--text3);margin-top:3px">${bv.noAuth ? '❌ No Auth' : ''}${bv.noAuth && bv.noEnc ? ' · ' : ''}${bv.noEnc ? '❌ No Encryption' : ''}</div>
        <div class="ap-owasp">🔗 ${bv.owasp}</div>
      </div>`;
        });
    }

    con.innerHTML = html || '<div style="text-align:center;color:var(--low);padding:12px 0;font-size:11px">✅ No attack paths or violations</div>';

    // Attach event listeners to AP panels
    con.querySelectorAll('.ap-panel[data-ap-idx]').forEach(panel => {
        panel.addEventListener('click', () => {
            highlightAttackPath(parseInt(panel.dataset.apIdx));
        });
    });
}

/** Full unified analysis pipeline */
export function runFullAnalysis(nodes, edges) {
    const graph = buildGraph(nodes, edges);
    const paths = detectAttackPaths(nodes, edges);
    const boundary = detectBoundaryViolations(nodes, edges);
    const pathF = evaluatePathRules(graph, nodes, edges);
    setAttackPathState(paths, boundary, pathF);

    const mergeAsThreats = (findings) => {
        findings.forEach(f => {
            if (!S.threats.find(t => t.id === f.id)) {
                S.threats.push({ ...f });
                (f.affected || []).forEach(nid => {
                    const pp2 = document.getElementById('pills-' + nid);
                    if (pp2 && !pp2.querySelector('[data-t="' + f.id + '"]')) {
                        const pill = document.createElement('span');
                        pill.className = 'pill';
                        pill.dataset.t = f.id;
                        pill.style.cssText = `background:${sc(f.sev)}22;color:${sc(f.sev)};border:1px solid ${sc(f.sev)}55`;
                        pill.textContent = f.id;
                        pp2.appendChild(pill);
                    }
                });
                if (!S.cmRows[f.id]) S.cmRows[f.id] = { response: 'Mitigate', status: 'Non-Mitigated' };
            }
        });
    };

    mergeAsThreats(boundary);
    mergeAsThreats(pathF);

    boundary.forEach(bv => {
        const srcEl = document.getElementById(bv.sourceId);
        const tgtEl = document.getElementById(bv.targetId);
        if (srcEl) srcEl.classList.add('boundary-violation');
        if (tgtEl) tgtEl.classList.add('boundary-violation');
    });

    renderAttackPaths();
    renderTrustZoneOverlays();
}
