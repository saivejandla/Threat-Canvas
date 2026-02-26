import { getState, setSimState } from '../state/state.js';
import { clearAnalysisHighlights, highlightPath } from '../ui/dom.js';
import { redraw } from '../ui/canvas.js';
import { runBlastLogic, _lastBlastDist, _lastBlockedEdges, _lastPrivEscNodes, _lastDetectScores } from '../engine/blastRadius.js';

export function runBlast(sourceId) {
    const S = getState();
    clearBlast(false);

    // UI manipulation from Canvas - setting a global
    window._currentBlastState = { blastSourceId: sourceId };

    const { dist, blockedEdges, blockedReasons, privEscNodes, detectScores }
        = runBlastLogic(sourceId, S.nodes, S.edges);

    window._currentBlastState = { blastSourceId: sourceId, dist, blockedEdges, privEscNodes };

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

    // Summary panel logic
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

    const blastCountEl = document.getElementById('blastCount');
    if (blastCountEl) {
        blastCountEl.innerHTML =
            `<strong style="color:#ef4444">${reached}</strong>/${total} nodes reachable (${pct}%)` +
            (privEscCount ? ` · <span style="color:#a78bfa">${privEscCount} via priv-esc</span>` : '') + '<br>' +
            (blocked ? `<span style="color:#34d399">Blocked: ${reasonSummary}</span><br>` : '<span style="color:var(--text3)">No edges blocked</span><br>') +
            `<span style="color:${detectPct > 70 ? '#34d399' : detectPct > 35 ? '#facc15' : '#ef4444'}">Avg detection prob: ${detectPct}%</span>`;
    }

    import('../ui/canvas.js').then(c => c.redrawWithBlast(dist, blockedEdges, blockedReasons, privEscNodes));
}

function _addDetectBadge(el, prob, label) {
    if (prob === undefined) return;
    const pct = Math.round((prob || 0) * 100);
    const badge = document.createElement('div');
    badge.className = 'detect-badge ' + (pct > 70 ? 'detect-high' : pct > 35 ? 'detect-med' : 'detect-low');
    badge.textContent = label || `${pct}% det`;
    el.appendChild(badge);
}

export function clearBlast(resetMode = true) {
    const S = getState();
    window._currentBlastState = null;
    import('../engine/blastRadius.js').then(b => b.clearBlastEngineState());

    Object.keys(S.nodes).forEach(id => {
        const el = document.getElementById(id); if (!el) return;
        el.classList.remove('blast-source', 'blast-reached', 'blast-reached-2', 'blast-safe', 'atk-path-critical', 'atk-path-high', 'atk-path-entry', 'boundary-violation');
        el.querySelector('.detect-badge')?.remove();
    });
    const countEl = document.getElementById('blastCount');
    if (countEl) countEl.textContent = 'Click a node to simulate compromise';
    redraw();
}

// ═══════════════════════════════════════════════════════════
// TRAFFIC SIMULATION ENGINE
// ═══════════════════════════════════════════════════════════
export function toggleSim() {
    const S = getState();
    const isRunning = !S.simRunning;

    setSimState(isRunning, isRunning ? 0 : S.pkt, isRunning ? S.simInt : null, isRunning ? 0 : S.trig);
    const btn = document.getElementById('simToggleBtn');

    if (isRunning) {
        btn.innerHTML = '⏹ Stop Simulation';
        btn.classList.add('active');
        document.getElementById('simLbl').textContent = 'SIMULATING NORMAL TRAFFIC';
        document.getElementById('simLbl').style.color = 'var(--text)';
        document.getElementById('simDot').style.background = '#34d399';
        document.getElementById('simDot').style.animation = 'pulse 1s infinite';

        const simInt = setInterval(simTick, 800);
        setSimState(true, undefined, simInt, undefined);
    } else {
        btn.innerHTML = '▶ Start Traffic Sim';
        btn.classList.remove('active');
        clearInterval(S.simInt);
        document.getElementById('simLbl').textContent = 'IDLE';
        document.getElementById('simLbl').style.color = 'var(--text3)';
        document.getElementById('simDot').style.background = 'var(--text3)';
        document.getElementById('simDot').style.animation = 'none';

        const svg = document.getElementById('svgLayer');
        if (svg) svg.querySelectorAll('.pkt').forEach(p => p.remove());

        clearAnalysisHighlights();
    }
}

function simTick() {
    const S = getState();
    if (!S.edges.length) return;

    setSimState(undefined, S.pkt + 1, undefined, undefined);
    document.getElementById('pktCnt').textContent = S.pkt;
    const svg = document.getElementById('svgLayer');

    // Clean up old
    svg.querySelectorAll('.pkt').forEach(p => { const age = parseInt(p.dataset.age || 0); if (age > 4) p.remove(); else p.dataset.age = age + 1; });

    const e = S.edges[Math.floor(Math.random() * S.edges.length)];
    const S2 = getState();
    const fNode = S2.nodes[e.from];
    const tNode = S2.nodes[e.to];
    if (!fNode || !tNode) return;

    const fEl = document.getElementById(e.from);
    const tEl = document.getElementById(e.to);
    if (!fEl || !tEl) return;

    const f = { x: fNode.x + fEl.offsetWidth, y: fNode.y + fEl.offsetHeight / 2 };
    const t = { x: tNode.x, y: tNode.y + tEl.offsetHeight / 2 };
    const dx = (t.x - f.x) * .4;

    const p = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    p.setAttribute('r', '4');
    p.setAttribute('fill', e._atkColor || '#4d9de0');
    if (e._atkColor) p.setAttribute('filter', `drop-shadow(0 0 6px ${e._atkColor})`);
    p.setAttribute('class', 'pkt');
    p.dataset.age = 0;

    const am = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
    am.setAttribute('dur', '0.8s');
    am.setAttribute('fill', 'freeze');
    am.setAttribute('path', `M${f.x},${f.y} C${f.x + dx},${f.y} ${t.x - dx},${t.y} ${t.x},${t.y}`);

    p.appendChild(am);
    svg.appendChild(p);
}

export function triggerAttack(type) {
    const S = getState();
    if (!S.simRunning) toggleSim();

    setSimState(undefined, undefined, undefined, S.trig + 1);
    document.getElementById('trigCnt').textContent = S.trig;
    document.getElementById('simLbl').textContent = '⚠️ ATTACK DETECTED: ' + type.toUpperCase();
    document.getElementById('simLbl').style.color = 'var(--crit)';
    document.getElementById('simDot').style.background = 'var(--crit)';

    const ext = Object.values(S.nodes).find(n => n.type === 'attacker') || Object.values(S.nodes).filter(n => ['internet', 'user'].includes(n.type))[0];
    const targets = {
        sqli: ['database', 'api', 'webserver'],
        ddos: ['webserver', 'api', 'loadbalancer'],
        lateral: ['database', 'internal', 'microservice'],
        exfil: ['database', 'storage', 'cache']
    }[type] || ['webserver'];

    const tgt = Object.values(S.nodes).find(n => targets.includes(n.type)) || Object.values(S.nodes)[0];
    if (!ext || !tgt) return;

    import('../engine/threatEngine.js').then(module => {
        const { RULES } = module;
        // The attack path will be visual by creating a red line via SVG, or highlighting if path exists
        const path = []; // Find a path from ext to tgt if possible
        const edges = S.edges;

        clearAnalysisHighlights();

        import('../engine/blastRadius.js').then(b => {
            const found = b.findPath(ext.id, tgt.id, b.buildAdjacency(S.nodes, S.edges));
            if (found) {
                highlightPath(found, type === 'ddos' ? 'high' : 'critical');
            }
        });

        setTimeout(() => {
            if (S.simRunning) {
                document.getElementById('simLbl').textContent = 'SIMULATING NORMAL TRAFFIC';
                document.getElementById('simLbl').style.color = 'var(--text)';
                document.getElementById('simDot').style.background = '#34d399';
                clearAnalysisHighlights();
            }
        }, 3500);
    });
}
