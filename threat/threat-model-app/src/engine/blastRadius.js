import { getState } from '../state/state.js';

// === GRAPH TRAVERSAL ENGINE ===
// Builds a directed adjacency map once per analysis run — O(E)
export function buildAdjacency(nodes, edges) {
    const adj = {};
    Object.keys(nodes).forEach(id => adj[id] = []);
    edges.forEach(e => { if (adj[e.from]) adj[e.from].push({ to: e.to, edge: e }); });
    return adj;
}

// BFS: can srcId reach dstId through any directed path? Returns the path array or null.
export function findPath(srcId, dstId, adj) {
    if (srcId === dstId) return [srcId];
    const visited = new Set();
    const queue = [[srcId, [srcId]]];
    while (queue.length) {
        const [cur, path] = queue.shift();
        if (visited.has(cur)) continue;
        visited.add(cur);
        for (const { to } of (adj[cur] || [])) {
            if (to === dstId) return [...path, to];
            if (!visited.has(to)) queue.push([to, [...path, to]]);
        }
    }
    return null;
}

// Returns Set of all node IDs reachable from srcId (not including src itself)
export function reachableFrom(srcId, adj) {
    const visited = new Set();
    const queue = [srcId];
    while (queue.length) {
        const cur = queue.shift();
        if (visited.has(cur)) continue;
        visited.add(cur);
        (adj[cur] || []).forEach(({ to }) => queue.push(to));
    }
    visited.delete(srcId);
    return visited;
}

// Detect cycles via DFS — returns true if any cycle exists
export function hasCycle(adj) {
    const WHITE = 0, GRAY = 1, BLACK = 2;
    const color = {};
    Object.keys(adj).forEach(id => color[id] = WHITE);
    function dfs(u) {
        color[u] = GRAY;
        for (const { to } of (adj[u] || [])) {
            if (color[to] === GRAY) return true;
            if (color[to] === WHITE && dfs(to)) return true;
        }
        color[u] = BLACK; return false;
    }
    return Object.keys(adj).some(id => color[id] === WHITE && dfs(id));
}

// Count how many trust-level escalations exist on the best path between two nodes
export function trustBoundaryCrossings(path, edges) {
    let count = 0;
    const S = getState();
    const boundaries = S.boundaries || [];
    const nodes = S.nodes;

    for (let i = 0; i < path.length - 1; i++) {
        const n1 = nodes[path[i]];
        const n2 = nodes[path[i + 1]];

        if (n1 && n2) {
            boundaries.forEach(b => {
                const inB1 = (n1.x >= b.x && n1.x <= b.x + b.w && n1.y >= b.y && n1.y <= b.y + b.h);
                const inB2 = (n2.x >= b.x && n2.x <= b.x + b.w && n2.y >= b.y && n2.y <= b.y + b.h);
                if (inB1 !== inB2) count++;
            });
        }

        const e = edges.find(ed => ed.from === path[i] && ed.to === path[i + 1]);
        if (e && e.trustBoundary !== 'No') count++;
    }
    return count;
}


// ===========================================================
// BLAST RADIUS — 6-FACTOR THEORETICAL ATTACK PATH MODEL
// ===========================================================

export let _lastBlastDist = null;
export let _lastBlockedEdges = new Set();
export let _lastDetectScores = {};
export let _lastPrivEscNodes = new Set();

// === Factor 1: TLS strength score (0=none, 1=weak, 2=strong) ===
export function tlsStrength(enc) {
    if (enc === 'TLS 1.3' || enc === 'TLS 1.2 (strong)') return 2;
    if (enc === 'TLS 1.2 (weak ciphers)' || enc === 'TLS 1.0/1.1') return 1;
    return 0; // None
}

// ── Factor 2: Can a compromised node actually possess this edge's credential? ──
export function canPossessCredential(edge, compromisedNodeId, compromisedNode) {
    if (!edge.credScope || edge.credScope === 'shared') return true;
    if (edge.credScope === 'service-bound') {
        return edge.from === compromisedNodeId;
    }
    if (edge.credScope === 'vault') {
        return ['admin', 'assumerole', 'network-bypass'].includes(compromisedNode?.iamPriv);
    }
    return true;
}

// ── Factor 3: Network route exists between zones? ──
export function hasNetworkRoute(edge, fromNode, toNode) {
    if (!edge.networkRoute || edge.networkRoute === 'direct') return true;
    if (edge.networkRoute === 'vpc-peering') return true;
    if (edge.networkRoute === 'none') return false;
    return true;
}

// ── Factor 4: Compromise impact — high-impact nodes bypass credential checks ──
export function isHighImpactCompromise(node) {
    return node?.compromiseImpact === 'high' || ['admin', 'network-bypass'].includes(node?.iamPriv);
}

export const SimulationConfig = {
    detectorProbs: {
        siem: 0.85,
        waf: 0.60,
        firewall: 0.45,
        idp: 0.70,
    },
    defaultEdgeDetection: 0.05,
    weakTlsDetection: 0.15,
    privEscPenalty: 0.4,
};

// ── Factor 6: Privilege escalation paths ──
export function getPrivEscTargets(nodeId, node, allNodes, edges) {
    const priv = node?.iamPriv || 'none';
    const activePrivs = ['admin', 'assumerole', 'write', 'network-bypass'];
    if (!activePrivs.includes(priv)) return new Set();

    const targets = new Set();
    Object.values(allNodes).forEach(n => {
        if (n.id === nodeId) return;
        const targetPriv = n.iamPriv || 'none';

        if (priv === 'admin') {
            targets.add(n.id);
        } else if (priv === 'network-bypass') {
            if (['none', 'standard', 'read-only', 'write', 'assumerole'].includes(targetPriv)) {
                targets.add(n.id);
            }
        } else if (priv === 'assumerole') {
            if (n.zone === node.zone || ['standard', 'none', 'read-only'].includes(targetPriv)) {
                targets.add(n.id);
            }
        } else if (priv === 'write') {
            if (n.zone === node.zone && ['none', 'standard', 'read-only'].includes(targetPriv)) {
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
            return { traversable: true, blockReason: null, detectionAdded: SimulationConfig.weakTlsDetection };
        }
    }

    if (!isExternal && !isHighImpact) {
        if (!canPossessCredential(edge, fromNodeId, fromNode)) {
            return { traversable: false, blockReason: 'credential-not-scoped', detectionAdded: 0 };
        }
    }

    const encStr = tlsStrength(edge.encryption);
    const detAdded = encStr === 0 ? SimulationConfig.defaultEdgeDetection : 0;

    return { traversable: true, blockReason: null, detectionAdded: detAdded };
}

export function runBlastLogic(sourceId, nodes, edges) {
    const sourceNode = nodes[sourceId];

    const dist = {};
    const detectScores = {};
    const blockedEdges = new Set();
    const blockedReasons = {};
    const privEscNodes = new Set();

    const srcDetect = SimulationConfig.detectorProbs[sourceNode?.type] || 0;
    detectScores[sourceId] = srcDetect;

    const queue = [{ id: sourceId, d: 0, detect: srcDetect }];
    while (queue.length) {
        const { id: cur, d, detect } = queue.shift();
        if (dist[cur] !== undefined) continue;
        dist[cur] = d;
        detectScores[cur] = detect;

        edges.forEach(e => {
            if (e.from !== cur) return;
            const result = evaluateEdge(e, cur, dist, nodes);
            const toNode = nodes[e.to];

            if (result.traversable) {
                const nodeDetect = SimulationConfig.detectorProbs[toNode?.type] || 0;
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

    if (['admin', 'assumerole', 'write', 'network-bypass'].includes(sourceNode?.iamPriv)) {
        const escalatableTargets = getPrivEscTargets(sourceId, sourceNode, nodes, edges);
        escalatableTargets.forEach(tid => {
            if (dist[tid] === undefined) {
                privEscNodes.add(tid);
                const toNode = nodes[tid];
                const nodeDetect = SimulationConfig.detectorProbs[toNode?.type] || 0;
                detectScores[tid] = Math.min(0.99, 1 - (1 - (detectScores[sourceId] || 0)) * (1 - nodeDetect) * (1 - SimulationConfig.privEscPenalty));
            }
        });
    }

    _lastBlastDist = dist;
    _lastBlockedEdges = blockedEdges;
    _lastDetectScores = detectScores;
    _lastPrivEscNodes = privEscNodes;

    return { dist, blockedEdges, blockedReasons, privEscNodes, detectScores };
}

export function clearBlastEngineState() {
    _lastBlastDist = null;
    _lastBlockedEdges = new Set();
    _lastDetectScores = {};
    _lastPrivEscNodes = new Set();
}
