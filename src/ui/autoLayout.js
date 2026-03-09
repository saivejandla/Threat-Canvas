/**
 * AUTO-LAYOUT ENGINE
 * Implements a Sugiyama-style layered left-to-right layout.
 * No external dependencies — pure JS, works with the existing S.nodes / S.edges state.
 *
 * Algorithm steps:
 *  1. Assign each node a "rank" (column) using longest-path layering.
 *  2. Sort nodes within each rank to minimise edge crossings (barycenter heuristic).
 *  3. Assign final (x, y) positions with even spacing.
 *  4. Apply positions to DOM elements and update S.nodes.
 *  5. Call redraw() + zoomFit() to refresh edges and viewport.
 */
import { S } from '../state/state.js';
import { redraw } from './renderSVG.js';
import { zoomFit } from './zoomPan.js';
import { renderTrustZoneOverlays } from './trustZones.js';

const COL_GAP = 220;   // px between columns (ranks)
const ROW_GAP = 130;   // px between rows within a column
const START_X = 60;    // left margin
const START_Y = 60;    // top margin

/**
 * Main entry point — call this when the user clicks "Auto Layout".
 */
export function autoLayout() {
    const nodes = S.nodes;
    const edges = S.edges;

    if (!Object.keys(nodes).length) return;

    // Build adjacency (directed: from → to)
    const ids = Object.keys(nodes);
    const adjOut = {};   // nodeId → [nodeId]
    const adjIn = {};   // nodeId → [nodeId]
    ids.forEach(id => { adjOut[id] = []; adjIn[id] = []; });
    edges.forEach(e => {
        const f = e.from || e.source;
        const t = e.to || e.target;
        if (f && t && adjOut[f] && adjOut[t]) {
            adjOut[f].push(t);
            adjIn[t].push(f);
        }
    });

    // ── Step 1: Longest-path rank assignment ─────────────────────────────────
    const rank = {};
    const visited = new Set();

    function dfsRank(id) {
        if (visited.has(id)) return rank[id] ?? 0;
        visited.add(id);
        if (!adjIn[id] || adjIn[id].length === 0) {
            rank[id] = 0;
            return 0;
        }
        const maxPredRank = Math.max(...adjIn[id].map(dfsRank));
        rank[id] = maxPredRank + 1;
        return rank[id];
    }
    ids.forEach(id => dfsRank(id));

    // ── Step 2: Group nodes into columns by rank ──────────────────────────────
    const maxRank = Math.max(...Object.values(rank));
    const cols = Array.from({ length: maxRank + 1 }, () => []);
    ids.forEach(id => cols[rank[id]].push(id));

    // ── Step 3: Barycenter heuristic to reduce crossings (2 passes) ──────────
    for (let pass = 0; pass < 2; pass++) {
        // Left-to-right pass
        for (let r = 1; r <= maxRank; r++) {
            cols[r].sort((a, b) => {
                const bcA = adjIn[a].length
                    ? adjIn[a].reduce((s, id) => s + (cols[r - 1].indexOf(id) + 1), 0) / adjIn[a].length
                    : Infinity;
                const bcB = adjIn[b].length
                    ? adjIn[b].reduce((s, id) => s + (cols[r - 1].indexOf(id) + 1), 0) / adjIn[b].length
                    : Infinity;
                return bcA - bcB;
            });
        }
        // Right-to-left pass
        for (let r = maxRank - 1; r >= 0; r--) {
            cols[r].sort((a, b) => {
                const bcA = adjOut[a].length
                    ? adjOut[a].reduce((s, id) => s + (cols[r + 1].indexOf(id) + 1), 0) / adjOut[a].length
                    : Infinity;
                const bcB = adjOut[b].length
                    ? adjOut[b].reduce((s, id) => s + (cols[r + 1].indexOf(id) + 1), 0) / adjOut[b].length
                    : Infinity;
                return bcA - bcB;
            });
        }
    }

    // ── Step 4: Assign final pixel positions ─────────────────────────────────
    cols.forEach((col, c) => {
        const colHeight = col.length * ROW_GAP;
        const topPad = START_Y;
        col.forEach((id, r) => {
            const x = START_X + c * COL_GAP;
            const y = topPad + r * ROW_GAP;
            nodes[id].x = x;
            nodes[id].y = y;
            const el = document.getElementById(id);
            if (el) {
                el.style.left = x + 'px';
                el.style.top = y + 'px';
            }
        });
    });

    // ── Step 5: Animate a brief flash, then redraw edges + fit view ──────────
    // Flash nodes so user sees the layout changed
    document.querySelectorAll('.node').forEach(el => {
        el.style.transition = 'left 0.35s cubic-bezier(0.4,0,0.2,1), top 0.35s cubic-bezier(0.4,0,0.2,1)';
    });
    setTimeout(() => {
        document.querySelectorAll('.node').forEach(el => el.style.transition = '');
    }, 400);

    redraw();
    setTimeout(() => {
        zoomFit();
        renderTrustZoneOverlays();
    }, 50);
}
