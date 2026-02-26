import { getState, addNode, updateNode, removeNode, addEdge, removeEdge, updateEdge } from '../state/state.js';
import { openEdgeEditor, showComponentThreats } from './dom.js';

// ZOOM & PAN ENGINE
const ZOOM_STEPS = [0.5, 0.67, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0];
export let vpZ = 1.0;
export let vpX = 0;
export let vpY = 0;

let _tzTimer = 0;
export function _debounceTZOverlay() {
    clearTimeout(_tzTimer);
    _tzTimer = setTimeout(renderTrustZoneOverlays, 60);
}

export function _applyViewport() {
    const vp = document.getElementById('viewport');
    if (!vp) return;
    vp.style.transform = `translate(${vpX}px,${vpY}px) scale(${vpZ})`;
    document.getElementById('zoomPct').textContent = Math.round(vpZ * 100) + '%';
}

export function zoomStep(dir) {
    const idx = ZOOM_STEPS.findIndex(z => Math.abs(z - vpZ) < 0.01);
    const cur = idx < 0 ? 4 : idx;
    const next = Math.max(0, Math.min(ZOOM_STEPS.length - 1, cur + dir));
    _zoomAround(ZOOM_STEPS[next], _canvasMid());
}

export function _zoomAround(newZ, pivot) {
    vpX = pivot.x - (pivot.x - vpX) * (newZ / vpZ);
    vpY = pivot.y - (pivot.y - vpY) * (newZ / vpZ);
    vpZ = newZ;
    _applyViewport();
}

function _canvasMid() {
    const cw = document.getElementById('canvasWrap');
    if (!cw) return { x: 0, y: 0 };
    const r = cw.getBoundingClientRect();
    return { x: r.width / 2, y: r.height / 2 };
}

export function zoomFit() {
    const S = getState();
    const nodes = Object.values(S.nodes);
    if (!nodes.length) return;
    const cw = document.getElementById('canvasWrap');
    const r = cw.getBoundingClientRect();
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(nd => {
        const el = document.getElementById(nd.id);
        const w = el && el.offsetWidth > 0 ? el.offsetWidth : 160;
        const h = el && el.offsetHeight > 0 ? el.offsetHeight : 75;
        minX = Math.min(minX, nd.x); minY = Math.min(minY, nd.y);
        maxX = Math.max(maxX, nd.x + w); maxY = Math.max(maxY, nd.y + h);
    });
    const PAD = 40;
    const scaleX = (r.width - PAD * 2) / (maxX - minX);
    const scaleY = (r.height - PAD * 2) / (maxY - minY);
    const z = Math.min(scaleX, scaleY, 2.0);
    const snapped = ZOOM_STEPS.reduce((a, b) => Math.abs(b - z) < Math.abs(a - z) ? b : a);
    vpZ = snapped;
    vpX = PAD - minX * vpZ + (r.width - PAD * 2 - (maxX - minX) * vpZ) / 2;
    vpY = PAD - minY * vpZ + (r.height - PAD * 2 - (maxY - minY) * vpZ) / 2;
    _applyViewport();
}

export function zoomReset() {
    vpZ = 1.0; vpX = 16; vpY = 16;
    _applyViewport();
}

// DRAG/DROP & NODE CREATION
export let dragType = null;
export function setDragType(t) { dragType = t; }

let selNodeId = null;
let appMode = 'analyze'; // Needs to come from state mostly but we pass it down
export function setCanvasAppMode(mode) { appMode = mode; }
export function getSelNodeId() { return selNodeId; }

export function selNode(id) {
    if (selNodeId) {
        const p = document.getElementById(selNodeId);
        if (p) p.classList.remove('selected');
    }
    selNodeId = id;
    const el = document.getElementById(id);
    if (el) el.classList.add('selected');

    if (appMode === 'blast') {
        runBlast(id);
    } else {
        showComponentThreats(id);
        document.getElementById('edgeEditorSection').style.display = 'none';
    }
}

export function createNode(type, x, y) {
    const S = getState();
    const def = DEFS[type]; if (!def) return;

    // Auto increment
    const idNum = S.nextId || 1;
    const id = 'n' + idNum;

    // trustZone map from zone string for nodes not explicitly defined
    const _zoneTZ = { public: 'internet', dmz: 'dmz', private: 'internal', isolated: 'restricted' };

    addNode(id, {
        id, type, x, y, label: def.label, trust: def.trust,
        zone: def.zone || 'private',
        trustZone: def.trustZone || _zoneTZ[def.zone || 'private'] || 'internal',
        iamPriv: def.iamPriv || 'standard',
        compromiseImpact: 'medium',
        isDetector: !!def.isDetector
    });
    // Need to increment nextId
    import('../state/state.js').then(module => {
        module.setState({ nextId: idNum + 1 });
    });

    const el = document.createElement('div'); el.className = 'node'; el.id = id;
    el.style.left = x + 'px'; el.style.top = y + 'px';

    el.innerHTML = `<div class="node-hdr" style="background:${def.color}18"><span class="node-ico"></span><span class="node-title" style="color:${def.color}"></span></div><div class="node-body"><span class="node-body-text"></span><br><span style="color:var(--text3);font-size:9px"></span></div><div class="node-pills" id="pills-${id}"></div><div class="port port-r" data-node="${id}"></div><div class="port port-l" data-node="${id}"></div>`;
    el.querySelector('.node-ico').textContent = def.icon;
    el.querySelector('.node-title').textContent = def.label;
    el.querySelector('.node-body-text').textContent = def.body;
    el.querySelectorAll('.node-body span')[1].textContent = def.trust.toUpperCase();

    el.querySelectorAll('.port').forEach(p => p.addEventListener('mousedown', e => { e.stopPropagation(); handlePort(id, p); }));

    let _clickX, _clickY;
    el.addEventListener('mousedown', e => { if (e.target.classList.contains('port')) return; _clickX = e.clientX; _clickY = e.clientY; });
    el.addEventListener('mouseup', e => {
        if (e.target.classList.contains('port')) return;
        if (Math.abs(e.clientX - _clickX) < 5 && Math.abs(e.clientY - _clickY) < 5) selNode(id);
    });

    makeDrag(el, id);
    const tz = S.nodes[id]?.trustZone || 'internal';
    el.classList.add('tz-' + tz + '-node');
    document.getElementById('canvas').appendChild(el);
    return id;
}

export function createBoundary(x, y) {
    import('../state/state.js').then(m => {
        const id = 'bnd' + Date.now();
        m.addBoundary({ id, x: x - 100, y: y - 100, w: 200, h: 200, name: 'Trust Boundary' });
    });
}

export function updateEdgesForNode(nodeId) {
    const S = getState();
    const svg = document.getElementById('svgLayer');
    if (!svg) return;

    // Find all edges connected to this node
    const connectedEdges = S.edges.filter(e => e.from === nodeId || e.to === nodeId);

    connectedEdges.forEach(e => {
        const f = pp(e.from, 'r'), t = pp(e.to, 'l'); if (!f || !t) return;
        const dx = (t.x - f.x) * .4;
        const dStr = `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`;

        // Find path
        const path = svg.querySelector(`path.edge-path[data-eid="${e.id}"]`);
        if (path) path.setAttribute('d', dStr);

        // Find hit
        const hit = svg.querySelector(`path.edge-hit[data-eid="${e.id}"]`);
        if (hit) hit.setAttribute('d', dStr);

        // Find label
        const lbl = svg.querySelector(`text.edge-lbl[data-eid="${e.id}"]`);
        if (lbl) {
            lbl.setAttribute('x', (f.x + t.x) / 2);
            lbl.setAttribute('y', (f.y + t.y) / 2 - 6);
        }
    });
}

export function makeDrag(el, id) {
    let sx, sy, sl, st, moved = false;
    let dragFrame = null;
    el.addEventListener('mousedown', e => {
        if (e.target.classList.contains('port')) return;
        e.preventDefault();

        const S = getState();
        const nd = S.nodes[id];

        sx = e.clientX; sy = e.clientY; sl = nd.x; st = nd.y; moved = false;

        const mv = e2 => {
            if (dragFrame) cancelAnimationFrame(dragFrame);
            dragFrame = requestAnimationFrame(() => {
                const dx = (e2.clientX - sx) / vpZ, dy = (e2.clientY - sy) / vpZ;
                if (Math.abs(dx) > 3 || Math.abs(dy) > 3) moved = true;
                nd.x = sl + dx; nd.y = st + dy;
                el.style.left = nd.x + 'px'; el.style.top = nd.y + 'px';

                updateNode(id, { x: nd.x, y: nd.y });
                updateEdgesForNode(id);
                _debounceTZOverlay();
            });
        };
        const up = () => {
            if (dragFrame) cancelAnimationFrame(dragFrame);
            document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up);
        };
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
    });
}

// CONNECTIONS
let connecting = null;
let pendConn = null;

export function handlePort(nodeId, portEl) {
    const canvas = document.getElementById('canvas');
    if (!connecting) {
        connecting = { nodeId, portEl };
        portEl.classList.add('active');
        canvas.style.cursor = 'crosshair';
    } else {
        if (connecting.nodeId === nodeId) {
            connecting.portEl.classList.remove('active');
            connecting = null;
            canvas.style.cursor = '';
            return;
        }
        connecting.portEl.classList.remove('active');
        pendConn = { from: connecting.nodeId, to: nodeId };
        connecting = null;
        canvas.style.cursor = '';
        document.getElementById('connModal').style.display = 'flex';
    }
}

export function cancelConn() {
    pendConn = null;
    document.getElementById('connModal').style.display = 'none';
}

export function confirmConn() {
    if (!pendConn) return;
    const S = getState();
    const e = {
        id: 'e' + S.nextId, from: pendConn.from, to: pendConn.to,
        protocol: document.getElementById('cp').value,
        dataClass: document.getElementById('cd').value,
        auth: document.getElementById('ca').value,
        encryption: document.getElementById('ce').value,
        credScope: document.getElementById('ccs').value,
        networkRoute: document.getElementById('cnr').value,
        trustBoundary: document.getElementById('ctb').value,
        _atk: false, _atkColor: null
    };

    if (!S.edges.find(x => x.from === e.from && x.to === e.to)) {
        addEdge(e);
        import('../state/state.js').then(module => { module.setState({ nextId: S.nextId + 1 }); });
    }

    pendConn = null;
    document.getElementById('connModal').style.display = 'none';
    redraw();
}

// RENDER EDGES
export function pp(id, side) {
    const S = getState();
    const nd = S.nodes[id];
    const el = document.getElementById(id);
    if (!nd || !el) return { x: 0, y: 0 };
    return side === 'r' ? { x: nd.x + el.offsetWidth, y: nd.y + el.offsetHeight / 2 } : { x: nd.x, y: nd.y + el.offsetHeight / 2 };
}

export function ec(e) {
    if (e.encryption === 'None') return '#ef4444';
    if (e.auth === 'None') return '#facc15';
    return '#f59e0b';
}

function drawBoundaries() {
    document.querySelectorAll('.bnd-box').forEach(el => el.remove());
    const S = getState();
    const cw = document.getElementById('canvas');
    if (!cw) return;

    S.boundaries.forEach(b => {
        const div = document.createElement('div');
        div.className = 'bnd-box';
        div.id = b.id;
        div.style.left = b.x + 'px';
        div.style.top = b.y + 'px';
        div.style.width = b.w + 'px';
        div.style.height = b.h + 'px';
        div.style.position = 'absolute';
        div.style.border = '2px dashed var(--accent)';
        div.style.backgroundColor = 'rgba(245, 158, 11, 0.05)';
        div.style.borderRadius = '8px';
        div.style.zIndex = '1';

        const resizer = document.createElement('div');
        resizer.style.position = 'absolute';
        resizer.style.bottom = '0';
        resizer.style.right = '0';
        resizer.style.width = '16px';
        resizer.style.height = '16px';
        resizer.style.cursor = 'nwse-resize';
        resizer.style.background = 'linear-gradient(135deg, transparent 50%, var(--accent) 50%)';
        resizer.style.borderBottomRightRadius = '6px';

        const lbl = document.createElement('div');
        lbl.style.position = 'absolute';
        lbl.style.top = '-12px';
        lbl.style.left = '8px';
        lbl.style.background = 'var(--bg)';
        lbl.style.padding = '0 6px';
        lbl.style.color = 'var(--accent)';
        lbl.style.fontSize = '10px';
        lbl.style.fontWeight = 'bold';
        lbl.style.cursor = 'text';
        lbl.textContent = b.name;

        lbl.addEventListener('dblclick', e => {
            e.stopPropagation();
            const n = prompt('Boundary Name:', b.name);
            if (n) {
                import('../state/state.js').then(m => {
                    m.updateBoundary(b.id, { name: n });
                    redraw();
                });
            }
        });

        const del = document.createElement('div');
        del.innerHTML = '✕';
        del.style.position = 'absolute';
        del.style.top = '4px';
        del.style.right = '4px';
        del.style.cursor = 'pointer';
        del.style.color = '#fff';
        del.style.background = 'var(--crit)';
        del.style.borderRadius = '50%';
        del.style.width = '14px';
        del.style.height = '14px';
        del.style.fontSize = '9px';
        del.style.display = 'flex';
        del.style.alignItems = 'center';
        del.style.justifyContent = 'center';
        del.style.opacity = '0';
        del.style.transition = 'opacity 0.2s';

        div.addEventListener('mouseenter', () => del.style.opacity = '1');
        div.addEventListener('mouseleave', () => del.style.opacity = '0');
        del.addEventListener('click', e => {
            e.stopPropagation();
            import('../state/state.js').then(m => {
                m.removeBoundary(b.id);
                redraw();
            });
        });

        div.appendChild(lbl);
        div.appendChild(resizer);
        div.appendChild(del);
        cw.appendChild(div);

        let isDragging = false, isResizing = false;
        let sx, sy, bx, by, bw, bh;
        div.addEventListener('mousedown', e => {
            if (e.target === resizer) isResizing = true;
            else isDragging = true;

            sx = e.clientX; sy = e.clientY;
            bx = b.x; by = b.y; bw = b.w; bh = b.h;
            e.stopPropagation();
            e.preventDefault();
        });

        const mv = e2 => {
            const dx = (e2.clientX - sx) / vpZ;
            const dy = (e2.clientY - sy) / vpZ;
            if (isResizing) {
                b.w = Math.max(50, bw + dx);
                b.h = Math.max(50, bh + dy);
                div.style.width = b.w + 'px';
                div.style.height = b.h + 'px';
            } else if (isDragging) {
                b.x = bx + dx;
                b.y = by + dy;
                div.style.left = b.x + 'px';
                div.style.top = b.y + 'px';
            }
            if (isResizing || isDragging) {
                import('../state/state.js').then(m => m.updateBoundary(b.id, { x: b.x, y: b.y, w: b.w, h: b.h }));
            }
        };

        const up = () => { isDragging = false; isResizing = false; };

        document.addEventListener('mousemove', mv);
        document.addEventListener('mouseup', up);
    });
}

export function redraw() {
    const svg = document.getElementById('svgLayer');
    if (!svg) return;
    svg.querySelectorAll('path,text,rect').forEach(el => el.remove());
    renderTrustZoneOverlays();
    drawBoundaries();

    const S = getState();

    S.edges.forEach(e => {
        const f = pp(e.from, 'r'), t = pp(e.to, 'l'); if (!f || !t) return;
        const dx = (t.x - f.x) * .4;
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`);
        path.setAttribute('fill', 'none'); path.setAttribute('stroke', e._atkColor || ec(e)); path.setAttribute('stroke-width', e._atk ? '2.5' : '1.5');
        path.setAttribute('class', 'c-norm edge-path' + (e._atk ? ' c-atk' : ''));
        path.dataset.eid = e.id;
        if (e._atk) path.setAttribute('filter', `drop-shadow(0 0 4px ${e._atkColor})`);
        svg.appendChild(path);

        const hit = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        hit.setAttribute('d', `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`);
        hit.setAttribute('fill', 'none'); hit.setAttribute('stroke', 'transparent'); hit.setAttribute('stroke-width', '18');
        hit.setAttribute('class', 'edge-hit'); hit.dataset.eid = e.id;
        hit.addEventListener('click', ev => { ev.stopPropagation(); openEdgeEditor(e.id); });
        hit.addEventListener('contextmenu', ev => { ev.preventDefault(); openEdgeEditor(e.id); });
        svg.appendChild(hit);

        const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        lbl.setAttribute('x', (f.x + t.x) / 2); lbl.setAttribute('y', (f.y + t.y) / 2 - 6);
        lbl.setAttribute('text-anchor', 'middle'); lbl.setAttribute('fill', e._atkColor || ec(e));
        lbl.setAttribute('font-size', '9'); lbl.setAttribute('font-family', 'JetBrains Mono,monospace');
        lbl.setAttribute('class', 'edge-hit edge-lbl'); lbl.dataset.eid = e.id;
        lbl.style.cssText = 'text-decoration:underline dotted;cursor:pointer;';
        lbl.textContent = e.protocol + (e.trustBoundary !== 'No' ? ' ⚠' : '');
        lbl.addEventListener('click', ev => { ev.stopPropagation(); openEdgeEditor(e.id); });
        lbl.addEventListener('contextmenu', ev => { ev.preventDefault(); openEdgeEditor(e.id); });
        svg.appendChild(lbl);
    });
}

export function renderTrustZoneOverlays() {
    const svg = document.getElementById('svgLayer');
    if (!svg) return;
    svg.querySelectorAll('.tz-rect, .tz-lbl').forEach(e => e.remove());

    const S = getState();
    const zones = { internet: [], dmz: [], internal: [], restricted: [] };
    Object.values(S.nodes).forEach(nd => {
        const _z = nd.trustZone || 'internal';
        if (zones[_z]) zones[_z].push(nd);
    });

    const colors = { internet: '#ff6b6b', dmz: '#ff8c00', internal: '#60a5fa', restricted: '#34d399' };
    const names = { internet: 'EXT', dmz: 'DMZ', internal: 'INT', restricted: 'SEC' };

    Object.entries(zones).forEach(([z, nds]) => {
        if (!nds.length) return;
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        nds.forEach(nd => {
            const el = document.getElementById(nd.id);
            const w = el && el.offsetWidth > 0 ? el.offsetWidth : 160;
            const h = el && el.offsetHeight > 0 ? el.offsetHeight : 75;
            minX = Math.min(minX, nd.x); minY = Math.min(minY, nd.y);
            maxX = Math.max(maxX, nd.x + w); maxY = Math.max(maxY, nd.y + h);
        });
        const P = 24;
        const width = maxX - minX + P * 2;
        const height = maxY - minY + P * 2;
        if (width < 0 || height < 0) return;

        const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        rect.setAttribute('x', minX - P); rect.setAttribute('y', minY - P);
        rect.setAttribute('width', width); rect.setAttribute('height', height);
        rect.setAttribute('rx', 8); rect.setAttribute('ry', 8);
        rect.setAttribute('fill', 'none'); rect.setAttribute('stroke', colors[z]);
        rect.setAttribute('stroke-width', 1); rect.setAttribute('stroke-dasharray', '4 4');
        rect.setAttribute('class', 'tz-rect');
        svg.insertBefore(rect, svg.firstChild);

        const lbl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        lbl.setAttribute('x', minX - P + 8); lbl.setAttribute('y', minY - P - 6);
        lbl.setAttribute('fill', colors[z]); lbl.setAttribute('font-size', 9);
        lbl.setAttribute('font-weight', 'bold'); lbl.setAttribute('letter-spacing', 1);
        lbl.setAttribute('class', 'tz-lbl');
        lbl.textContent = `ZONE: ${names[z]}`;
        svg.insertBefore(lbl, svg.firstChild);
    });
}

// DRAW BLAST VIEW
export function redrawWithBlast(dist, blockedEdges = new Set(), blockedReasons = {}, privEscNodes = new Set()) {
    const svg = document.getElementById('svgLayer');
    if (!svg) return;
    svg.querySelectorAll('path,text,rect').forEach(el => el.remove());
    renderTrustZoneOverlays();
    drawBoundaries();

    const S = getState();

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
        path.setAttribute('class', 'c-norm edge-path' + (e._atk ? ' c-atk' : ''));
        path.dataset.eid = e.id;
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
        lbl.setAttribute('class', 'edge-hit edge-lbl'); lbl.dataset.eid = e.id;
        lbl.style.cssText = 'text-decoration:underline dotted;cursor:pointer;';
        lbl.textContent = prefix + e.protocol + (e.trustBoundary !== 'No' ? ' ⚠' : '');
        lbl.addEventListener('click', ev => { ev.stopPropagation(); openEdgeEditor(e.id); });
        lbl.addEventListener('contextmenu', ev => { ev.preventDefault(); openEdgeEditor(e.id); });
        svg.appendChild(lbl);
    });
}
