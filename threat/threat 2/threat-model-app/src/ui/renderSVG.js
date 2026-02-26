/**
 * SVG EDGE RENDERING
 */
import { S, blastSourceId } from '../state/state.js';
import { openEdgeEditor } from './panelUI.js';

/** Port position calculator */
export function pp(id, side) {
    const nd = S.nodes[id];
    const el = document.getElementById(id);
    if (!nd || !el) return { x: 0, y: 0 };
    return side === 'r'
        ? { x: nd.x + el.offsetWidth, y: nd.y + el.offsetHeight / 2 }
        : { x: nd.x, y: nd.y + el.offsetHeight / 2 };
}

/** Edge color logic */
export function ec(e) {
    if (e.encryption === 'None') return '#ef4444';
    if (e.auth === 'None') return '#facc15';
    return '#f59e0b';
}

/** Full SVG edge re-render */
export function redraw() {
    const svg = document.getElementById('svgLayer');
    svg.querySelectorAll('path,text,rect').forEach(el => el.remove());
    S.edges.forEach(e => {
        const f = pp(e.from, 'r'), t = pp(e.to, 'l'); if (!f || !t) return;
        const dx = (t.x - f.x) * .4;
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`);
        path.setAttribute('fill', 'none'); path.setAttribute('stroke', e._atkColor || ec(e)); path.setAttribute('stroke-width', e._atk ? '2.5' : '1.5');
        path.setAttribute('class', 'c-norm' + (e._atk ? ' c-atk' : ''));
        if (e._atk) path.setAttribute('filter', `drop-shadow(0 0 4px ${e._atkColor})`);
        svg.appendChild(path);
        // Invisible hit area
        const hit = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        hit.setAttribute('d', `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`);
        hit.setAttribute('fill', 'none'); hit.setAttribute('stroke', 'transparent'); hit.setAttribute('stroke-width', '18');
        hit.setAttribute('class', 'edge-hit'); hit.dataset.eid = e.id;
        hit.addEventListener('click', ev => { ev.stopPropagation(); openEdgeEditor(e.id); });
        hit.addEventListener('contextmenu', ev => { ev.preventDefault(); openEdgeEditor(e.id); });
        svg.appendChild(hit);
        const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        lbl.setAttribute('x', (f.x + t.x) / 2); lbl.setAttribute('y', (f.y + t.y) / 2 - 6); lbl.setAttribute('text-anchor', 'middle'); lbl.setAttribute('fill', ec(e)); lbl.setAttribute('font-size', '9'); lbl.setAttribute('font-family', 'JetBrains Mono,monospace');
        lbl.setAttribute('class', 'edge-hit'); lbl.dataset.eid = e.id;
        lbl.style.cssText = 'text-decoration:underline dotted;cursor:pointer;';
        const srcNd = S.nodes[e.from || e.source], tgtNd = S.nodes[e.to || e.target];
        const isBV = srcNd && tgtNd && (srcNd.trustZone || 'internal') !== (tgtNd.trustZone || 'internal');
        lbl.textContent = e.protocol + (isBV ? ' 🚧' : '') + (e.trustBoundary !== 'No' ? ' ⚠' : '');
        lbl.addEventListener('click', ev => { ev.stopPropagation(); openEdgeEditor(e.id); });
        lbl.addEventListener('contextmenu', ev => { ev.preventDefault(); openEdgeEditor(e.id); });
        svg.appendChild(lbl);
    });
}

/** Blast-mode SVG rendering */
export function redrawWithBlast(dist, blockedEdges = new Set(), blockedReasons = {}, privEscNodes = new Set()) {
    const svg = document.getElementById('svgLayer');
    svg.querySelectorAll('path,text,rect').forEach(el => el.remove());
    S.edges.forEach(e => {
        const f = pp(e.from, 'r'), t = pp(e.to, 'l'); if (!f || !t) return;
        const dx = (t.x - f.x) * .4;
        const isTraversed = dist && dist[e.from] !== undefined && dist[e.to] !== undefined && dist[e.to] === dist[e.from] + 1;
        const isBlocked = blockedEdges.has(e.id);
        const reason = blockedReasons[e.id];
        const isPrivEscPath = privEscNodes.has(e.to);

        const strokeColor = isTraversed ? '#ef4444' : isPrivEscPath ? '#a78bfa' : isBlocked ? (reason === 'no-network-route' ? '#374151' : '#34d399') : (e._atkColor || ec(e));
        const strokeWidth = isTraversed || isPrivEscPath ? '2.5' : isBlocked ? '1.5' : (e._atk ? '2.5' : '1.5');

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`);
        path.setAttribute('fill', 'none'); path.setAttribute('stroke', strokeColor); path.setAttribute('stroke-width', strokeWidth);
        path.setAttribute('class', 'c-norm' + (e._atk ? ' c-atk' : ''));
        if (isTraversed) path.setAttribute('filter', 'drop-shadow(0 0 5px #ef4444)');
        if (isPrivEscPath) path.setAttribute('filter', 'drop-shadow(0 0 4px #a78bfa)');
        if (isBlocked) path.setAttribute('stroke-dasharray', '3 4');
        if (reason === 'no-network-route') path.setAttribute('stroke-dasharray', '2 6');
        svg.appendChild(path);

        const hit = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        hit.setAttribute('d', `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`);
        hit.setAttribute('fill', 'none'); hit.setAttribute('stroke', 'transparent'); hit.setAttribute('stroke-width', '18');
        hit.setAttribute('class', 'edge-hit'); hit.dataset.eid = e.id;
        hit.addEventListener('click', ev => { ev.stopPropagation(); openEdgeEditor(e.id); });
        hit.addEventListener('contextmenu', ev => { ev.preventDefault(); openEdgeEditor(e.id); });
        svg.appendChild(hit);

        const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        const prefix = isBlocked ? (reason === 'no-network-route' ? '🚧 ' : reason === 'credential-not-scoped' ? '🔑 ' : '🛡 ') : (isPrivEscPath ? '⬆️ ' : '');
        lbl.setAttribute('x', (f.x + t.x) / 2); lbl.setAttribute('y', (f.y + t.y) / 2 - 6);
        lbl.setAttribute('text-anchor', 'middle'); lbl.setAttribute('fill', strokeColor);
        lbl.setAttribute('font-size', '9'); lbl.setAttribute('font-family', 'JetBrains Mono,monospace');
        lbl.setAttribute('class', 'edge-hit'); lbl.dataset.eid = e.id;
        lbl.style.cssText = 'text-decoration:underline dotted;cursor:pointer;';
        lbl.textContent = prefix + e.protocol + (e.trustBoundary !== 'No' ? ' ⚠' : '');
        lbl.addEventListener('click', ev => { ev.stopPropagation(); openEdgeEditor(e.id); });
        lbl.addEventListener('contextmenu', ev => { ev.preventDefault(); openEdgeEditor(e.id); });
        svg.appendChild(lbl);
    });
}
