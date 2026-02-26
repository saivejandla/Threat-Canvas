/**
 * BLAST RADIUS — 6-Factor Theoretical Attack Path Model
 * BFS from a compromised source node, evaluating each outbound edge.
 */
import {
    S, blastSourceId, setBlastSourceId, setBlastState, resetBlastState,
    _lastBlastDist, _lastBlockedEdges, _lastPrivEscNodes
} from '../state/state.js';
import { DETECTOR_PROBS } from './componentDefs.js';
import { redraw, redrawWithBlast } from '../ui/renderSVG.js';

// ── Factor 1: TLS strength ──
export function tlsStrength(enc) {
    if (enc === 'TLS 1.3' || enc === 'TLS 1.2 (strong)') return 2;
    if (enc === 'TLS 1.2 (weak ciphers)' || enc === 'TLS 1.0/1.1') return 1;
    return 0;
}

// ── Factor 2: Credential possession ──
export function canPossessCredential(edge, compromisedNodeId, compromisedNode) {
    if (!edge.credScope || edge.credScope === 'shared') return true;
    if (edge.credScope === 'service-bound') return edge.from === compromisedNodeId;
    if (edge.credScope === 'vault') return ['admin', 'assumerole'].includes(compromisedNode?.iamPriv);
    return true;
}

// ── Factor 3: Network route ──
export function hasNetworkRoute(edge, fromNode, toNode) {
    if (!edge.networkRoute || edge.networkRoute === 'direct') return true;
    if (edge.networkRoute === 'vpc-peering') return true;
    if (edge.networkRoute === 'none') return false;
    return true;
}

// ── Factor 4: High impact compromise ──
export function isHighImpactCompromise(node) {
    return node?.compromiseImpact === 'high' || node?.iamPriv === 'admin';
}

// ── Factor 6: Privilege escalation targets ──
export function getPrivEscTargets(nodeId, node, allNodes, edges) {
    if (!['admin', 'assumerole'].includes(node?.iamPriv)) return new Set();
    const targets = new Set();
    Object.values(allNodes).forEach(n => {
        if (n.id === nodeId) return;
        if (node.iamPriv === 'admin') {
            targets.add(n.id);
        } else if (node.iamPriv === 'assumerole') {
            if (n.zone === node.zone || ['standard', 'none'].includes(n.iamPriv)) {
                targets.add(n.id);
            }
        }
    });
    return targets;
}

// ── Master traversal check ──
export function evaluateEdge(edge, fromNodeId, compromisedPath, allNodes) {
    const fromNode = allNodes[fromNodeId];
    const toNode = allNodes[edge.to];
    const isExternal = ['untrusted', 'hostile'].includes(fromNode?.trust);
    const isHighImpact = isHighImpactCompromise(fromNode);

    if (!hasNetworkRoute(edge, fromNode, toNode)) {
        return { traversable: false, blockReason: 'no-network-route', detectionAdded: 0 };
    }

    if (isExternal) {
        const strongAuth = ['JWT', 'OAuth2', 'mTLS', 'IAM Role', 'API Key', 'Basic Auth'];
        const hasAuth = strongAuth.includes(edge.auth);
        const encStr = tlsStrength(edge.encryption);
        if (hasAuth && encStr >= 2) {
            return { traversable: false, blockReason: 'auth-and-strong-tls', detectionAdded: 0 };
        }
        if (hasAuth && encStr === 1) {
            return { traversable: true, blockReason: null, detectionAdded: 0.15 };
        }
    }

    if (!isExternal && !isHighImpact) {
        if (!canPossessCredential(edge, fromNodeId, fromNode)) {
            return { traversable: false, blockReason: 'credential-not-scoped', detectionAdded: 0 };
        }
    }

    const encStr = tlsStrength(edge.encryption);
    const detAdded = encStr === 0 ? 0.05 : 0;
    return { traversable: true, blockReason: null, detectionAdded: detAdded };
}

// ── Helper: add detection badge ──
function _addDetectBadge(el, prob, label) {
    if (prob === undefined) return;
    const pct = Math.round((prob || 0) * 100);
    const badge = document.createElement('div');
    badge.className = 'detect-badge ' + (pct > 70 ? 'detect-high' : pct > 35 ? 'detect-med' : 'detect-low');
    badge.textContent = label || `${pct}% det`;
    el.appendChild(badge);
}

// ── Main blast BFS ──
export function runBlast(sourceId) {
    clearBlast(false);
    setBlastSourceId(sourceId);
    const sourceNode = S.nodes[sourceId];

    const dist = {};
    const detectScores = {};
    const blockedEdges = new Set();
    const blockedReasons = {};
    const privEscNodes = new Set();

    const srcDetect = DETECTOR_PROBS[sourceNode?.type] || 0;
    detectScores[sourceId] = srcDetect;

    const queue = [{ id: sourceId, d: 0, detect: srcDetect }];
    while (queue.length) {
        const { id: cur, d, detect } = queue.shift();
        if (dist[cur] !== undefined) continue;
        dist[cur] = d;
        detectScores[cur] = detect;

        S.edges.forEach(e => {
            if (e.from !== cur) return;
            const result = evaluateEdge(e, cur, dist, S.nodes);
            const toNode = S.nodes[e.to];

            if (result.traversable) {
                const nodeDetect = DETECTOR_PROBS[toNode?.type] || 0;
                const edgeDetect = result.detectionAdded || 0;
                const prevUndetected = 1 - (detect || 0);
                const newUndetected = prevUndetected * (1 - nodeDetect) * (1 - edgeDetect);
                const newDetect = Math.min(0.99, 1 - newUndetected);
                queue.push({ id: e.to, d: d + 1, detect: newDetect });
            } else {
                blockedEdges.add(e.id);
                blockedReasons[e.id] = result.blockReason;
            }
        });
    }

    // Factor 6: privilege escalation
    if (['admin', 'assumerole'].includes(sourceNode?.iamPriv)) {
        const escalatableTargets = getPrivEscTargets(sourceId, sourceNode, S.nodes, S.edges);
        escalatableTargets.forEach(tid => {
            if (dist[tid] === undefined) {
                privEscNodes.add(tid);
                const toNode = S.nodes[tid];
                const nodeDetect = DETECTOR_PROBS[toNode?.type] || 0;
                detectScores[tid] = Math.min(0.99, 1 - (1 - (detectScores[sourceId] || 0)) * (1 - nodeDetect) * (1 - 0.4));
            }
        });
    }

    setBlastState(dist, blockedEdges, detectScores, privEscNodes);

    // Apply visual classes
    Object.keys(S.nodes).forEach(id => {
        const el = document.getElementById(id); if (!el) return;
        el.classList.remove('blast-source', 'blast-reached', 'blast-reached-2', 'blast-safe', 'stride-highlight');
        el.querySelector('.detect-badge')?.remove();

        if (id === sourceId) {
            el.classList.add('blast-source');
        } else if (privEscNodes.has(id)) {
            el.classList.add('blast-reached-2');
            _addDetectBadge(el, detectScores[id], 'PRIV-ESC');
        } else if (dist[id] === 1) {
            el.classList.add('blast-reached');
            _addDetectBadge(el, detectScores[id]);
        } else if (dist[id] !== undefined && dist[id] >= 2) {
            el.classList.add('blast-reached-2');
            _addDetectBadge(el, detectScores[id]);
        } else {
            el.classList.add('blast-safe');
        }
    });

    // Summary panel
    const reached = Object.keys(dist).filter(id => id !== sourceId).length + privEscNodes.size;
    const total = Object.keys(S.nodes).length - 1;
    const pct = total > 0 ? Math.round(reached / total * 100) : 0;
    const blocked = blockedEdges.size;
    const privEscCount = privEscNodes.size;

    const reachableDetects = [...Object.entries(detectScores)].filter(([id]) => id !== sourceId).map(([, v]) => v);
    const privDetects = [...privEscNodes].map(id => detectScores[id] || 0);
    const allDetects = [...reachableDetects, ...privDetects];
    const avgDetect = allDetects.length ? allDetects.reduce((a, b) => a + b, 0) / allDetects.length : 0;
    const detectPct = Math.round(avgDetect * 100);

    const reasonCounts = {};
    Object.values(blockedReasons).forEach(r => { reasonCounts[r] = (reasonCounts[r] || 0) + 1; });
    const reasonSummary = Object.entries(reasonCounts).map(([k, v]) => {
        const labels = { 'no-network-route': '🚧 no network route', 'auth-and-strong-tls': '🛡 auth+TLS', 'credential-not-scoped': '🔑 scoped credentials' };
        return `${v}× ${labels[k] || k}`;
    }).join(', ');

    document.getElementById('blastCount').innerHTML =
        `<strong style="color:#ef4444">${reached}</strong>/${total} nodes reachable (${pct}%)` +
        (privEscCount ? ` · <span style="color:#a78bfa">${privEscCount} via priv-esc</span>` : '') + '<br>' +
        (blocked ? `<span style="color:#34d399">Blocked: ${reasonSummary}</span><br>` : '<span style="color:var(--text3)">No edges blocked</span><br>') +
        `<span style="color:${detectPct > 70 ? '#34d399' : detectPct > 35 ? '#facc15' : '#ef4444'}">Avg detection prob: ${detectPct}%</span>`;

    redrawWithBlast(dist, blockedEdges, blockedReasons, privEscNodes);
}

export function clearBlast(resetMode = true) {
    setBlastSourceId(null);
    resetBlastState();
    Object.keys(S.nodes).forEach(id => {
        const el = document.getElementById(id); if (!el) return;
        el.classList.remove('blast-source', 'blast-reached', 'blast-reached-2', 'blast-safe', 'atk-path-critical', 'atk-path-high', 'atk-path-entry', 'boundary-violation');
        el.querySelector('.detect-badge')?.remove();
    });
    const countEl = document.getElementById('blastCount');
    if (countEl) countEl.textContent = 'Click a node to simulate compromise';
    redraw();
}
