/**
 * GRAPH TRAVERSAL ENGINE
 * Pure functions for graph analysis — no DOM dependencies.
 */

/** Build directed adjacency map — O(E) */
export function buildAdjacency(nodes, edges) {
    const adj = {};
    Object.keys(nodes).forEach(id => adj[id] = []);
    edges.forEach(e => { if (adj[e.from]) adj[e.from].push({ to: e.to, edge: e }); });
    return adj;
}

/** BFS: find shortest path from srcId to dstId, returns path array or null */
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

/** BFS: returns Set of all node IDs reachable from srcId (not including src) */
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

/** DFS cycle detection — returns true if any cycle exists */
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

/** Count trust-boundary crossings on a path */
export function trustBoundaryCrossings(path, edges) {
    let count = 0;
    for (let i = 0; i < path.length - 1; i++) {
        const e = edges.find(ed => ed.from === path[i] && ed.to === path[i + 1]);
        if (e && e.trustBoundary !== 'No') count++;
    }
    return count;
}

/** Build adjacency list for the attack path engine (supports source/from aliases) */
export function buildGraph(nodes, edges) {
    const graph = {};
    const nodeArr = Array.isArray(nodes) ? nodes : Object.values(nodes);
    nodeArr.forEach(n => { graph[n.id] = []; });
    edges.forEach(e => {
        const src = e.source || e.from;
        const tgt = e.target || e.to;
        if (graph[src] !== undefined) graph[src].push({ target: tgt, edge: e });
    });
    return graph;
}

/** BFS: find ALL paths from startNode up to maxDepth hops */
export function findAllPaths(graph, startNode, maxDepth = 5) {
    const paths = [];
    const queue = [[startNode]];
    const MAX_PATHS = 200;
    while (queue.length > 0 && paths.length < MAX_PATHS) {
        const path = queue.shift();
        const last = path[path.length - 1];
        if (path.length > maxDepth) continue;
        const neighbors = graph[last] || [];
        for (const neighbor of neighbors) {
            if (path.includes(neighbor.target)) continue;
            const newPath = [...path, neighbor.target];
            paths.push(newPath);
            queue.push(newPath);
        }
    }
    return paths;
}

/** Return all nodes in the 'internet' trust zone (BFS entry points) */
export function getEntryNodes(nodes) {
    const nodeArr = Array.isArray(nodes) ? nodes : Object.values(nodes);
    return nodeArr.filter(n =>
        n.trustZone === 'internet' ||
        n.zone === 'public' ||
        ['internet', 'user', 'attacker'].includes(n.type)
    );
}

/** Resolve a nodeId to the node object from either array or object map */
export function resolveNode(nodes, id) {
    if (Array.isArray(nodes)) return nodes.find(n => n.id === id);
    return nodes[id];
}
