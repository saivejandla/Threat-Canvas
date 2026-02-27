/**
 * CANVAS UI — Node creation, drag, selection, port connections
 */
import {
    S, appMode, blastSourceId, setDragType, dragType,
    S_attackPaths, S_boundaryFindings, S_pathFindings, setAttackPathState, setHighlightedPathIdx,
    selectedElementId, setSelectedElementId
} from '../state/state.js';
import { DEFS } from '../engine/componentDefs.js';
import { runBlast } from '../engine/blastRadius.js';
import { redraw, redrawWithBlast } from './renderSVG.js';
import { vpZ, vpX, vpY, _debounceTZOverlay } from './zoomPan.js';
import { _lastBlastDist, _lastBlockedEdges, _lastPrivEscNodes } from '../state/state.js';
import { showComponentThreats, setMode } from './panelUI.js';
import { runAnalysis } from '../engine/threatEngine.js';
import { upHint } from '../utils/helpers.js';
import { renderDetected } from './assessUI.js';

export function createNode(type, x, y) {
    const def = DEFS[type]; if (!def) return;
    const id = 'n' + S.nextId++;
    const _zoneTZ = { public: 'internet', dmz: 'dmz', private: 'internal', isolated: 'restricted' };
    S.nodes[id] = {
        id, type, x, y, label: def.label, trust: def.trust,
        zone: def.zone || 'private',
        trustZone: def.trustZone || _zoneTZ[def.zone || 'private'] || 'internal',
        iamPriv: def.iamPriv || 'standard',
        compromiseImpact: 'medium',
        isDetector: !!def.isDetector
    };
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
    makeDrag(el, S.nodes[id]);
    const tz = S.nodes[id].trustZone || 'internal';
    el.classList.add('tz-' + tz + '-node');
    document.getElementById('canvas').appendChild(el);
    return id;
}

export function makeDrag(el, nd) {
    let sx, sy, sl, st, moved = false;
    el.addEventListener('mousedown', e => {
        if (e.target.classList.contains('port')) return;
        e.preventDefault(); sx = e.clientX; sy = e.clientY; sl = nd.x; st = nd.y; moved = false;
        const mv = e2 => {
            const dx = (e2.clientX - sx) / vpZ, dy = (e2.clientY - sy) / vpZ;
            if (Math.abs(dx) > 3 || Math.abs(dy) > 3) moved = true;
            nd.x = sl + dx; nd.y = st + dy; el.style.left = nd.x + 'px'; el.style.top = nd.y + 'px';
            if (blastSourceId) redrawWithBlast(_lastBlastDist, _lastBlockedEdges, {}, _lastPrivEscNodes); else redraw();
            _debounceTZOverlay();
        };
        const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); };
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
    });
}

export function selNode(id) {
    if (S.sel) { const p = document.getElementById(S.sel); if (p) p.classList.remove('selected'); }
    S.sel = id;
    const el = document.getElementById(id); if (el) el.classList.add('selected');
    if (appMode === 'blast') {
        runBlast(id);
    } else {
        showComponentThreats(id);
        document.getElementById('edgeEditorSection').style.display = 'none';
        // Click-to-filter: filter threat list to this node
        setSelectedElementId(id);
        if (S.threats.length) renderDetected();
    }
}

export function handlePort(nodeId, portEl) {
    if (!S.connecting) { S.connecting = { nodeId, portEl }; portEl.classList.add('active'); document.getElementById('canvas').style.cursor = 'crosshair'; }
    else {
        if (S.connecting.nodeId === nodeId) { S.connecting.portEl.classList.remove('active'); S.connecting = null; document.getElementById('canvas').style.cursor = ''; return; }
        S.connecting.portEl.classList.remove('active');
        S.pendConn = { from: S.connecting.nodeId, to: nodeId };
        S.connecting = null;
        document.getElementById('canvas').style.cursor = '';
        document.getElementById('connModal').style.display = 'flex';
    }
}

export function cancelConn() { S.pendConn = null; document.getElementById('connModal').style.display = 'none'; }

export function confirmConn() {
    if (!S.pendConn) return;
    const e = {
        id: 'e' + S.nextId++, from: S.pendConn.from, to: S.pendConn.to,
        protocol: document.getElementById('cp').value,
        dataClass: document.getElementById('cd').value,
        auth: document.getElementById('ca').value,
        encryption: document.getElementById('ce').value,
        credScope: document.getElementById('ccs').value,
        networkRoute: document.getElementById('cnr').value,
        trustBoundary: document.getElementById('ctb').value,
        _atk: false, _atkColor: null
    };
    if (!S.edges.find(x => x.from === e.from && x.to === e.to)) S.edges.push(e);
    S.pendConn = null; document.getElementById('connModal').style.display = 'none'; redraw();
}

export function clearCanvas() {
    setAttackPathState([], [], []);
    setHighlightedPathIdx(-1);
    const apBadge = document.getElementById('apTabBadge'); if (apBadge) apBadge.textContent = '0';
    const apCon = document.getElementById('attackPathsContainer');
    if (apCon) apCon.innerHTML = '<div style="text-align:center;color:var(--text3);padding:24px 0;font-size:12px">Run analysis to detect attack paths</div>';
    document.querySelectorAll('.trust-zone-overlay').forEach(el => el.remove());
    Object.keys(S.nodes).forEach(id => { const el = document.getElementById(id); if (el) el.remove(); });
    S.nodes = {}; S.edges = []; S.threats = []; S.cmRows = {}; S.nextId = 1;
    import('../state/state.js').then(mod => { mod.setBlastSourceId(null); mod.resetBlastState(); });
    document.getElementById('svgLayer').querySelectorAll('path,text,rect').forEach(e => e.remove());
    document.getElementById('detectedThreats').innerHTML = '<div style="text-align:center;color:var(--text3);padding:24px 0;font-size:12px">Build DFD then press Analyze</div>';
    document.getElementById('ctpSection').style.display = 'none';
    document.getElementById('edgeEditorSection').style.display = 'none';
    const countEl = document.getElementById('blastCount'); if (countEl) countEl.textContent = 'Click a node to simulate compromise';
    upHint(S.nodes);
}

/** Initialize canvas drop zone and keyboard shortcuts */
export function initCanvas() {
    // Palette drag
    document.querySelectorAll('.pal-item[draggable]').forEach(el => {
        el.addEventListener('dragstart', e => { setDragType(el.dataset.type); e.dataTransfer.effectAllowed = 'copy'; });
    });

    const canvasWrap = document.getElementById('canvasWrap');
    canvasWrap.addEventListener('dragover', e => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    canvasWrap.addEventListener('drop', e => {
        e.preventDefault(); if (!dragType) return;
        const r = canvasWrap.getBoundingClientRect();
        const x = (e.clientX - r.left - vpX) / vpZ - 58;
        const y = (e.clientY - r.top - vpY) / vpZ - 28;
        const id = createNode(dragType, x, y);
        setDragType(null); upHint(S.nodes);
        if (id) { setMode('analyze'); showComponentThreats(id); }
    });

    // Click canvas background → clear node filter
    canvasWrap.addEventListener('mousedown', e => {
        // Only trigger on direct canvas background click, not on nodes/ports/edges
        if (e.target === canvasWrap || e.target.id === 'canvas' || e.target.id === 'viewport') {
            if (selectedElementId) {
                setSelectedElementId(null);
                if (S.threats.length) renderDetected();
            }
            if (S.sel) {
                const prev = document.getElementById(S.sel);
                if (prev) prev.classList.remove('selected');
                S.sel = null;
            }
        }
    });

    // Keyboard
    document.addEventListener('keydown', e => {
        if ((e.key === 'Delete' || e.key === 'Backspace') && S.sel && document.activeElement.tagName === 'BODY') {
            const el = document.getElementById(S.sel); if (el) el.remove();
            delete S.nodes[S.sel];
            S.edges = S.edges.filter(ed => ed.from !== S.sel && ed.to !== S.sel);
            S.sel = null; redraw(); upHint(S.nodes);
        }
        if (e.key === 'a' && document.activeElement.tagName === 'BODY') runAnalysis();
    });
}
