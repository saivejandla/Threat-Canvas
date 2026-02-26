/**
 * SIMULATION UI — Traffic simulation and attack visualization
 */
import { S } from '../state/state.js';
import { redraw, pp, ec } from './renderSVG.js';
import { sleep } from '../utils/helpers.js';

export function toggleSim() { S.simRunning ? stopSim() : startSim(); }

export function startSim() {
    if (!S.edges.length) { alert('Add data flows first.'); return; }
    S.simRunning = true; S.pkt = 0;
    document.getElementById('simDot').classList.add('run');
    document.getElementById('simLbl').textContent = 'RUNNING'; document.getElementById('simLbl').style.color = 'var(--accent)';
    document.getElementById('simToggleBtn').textContent = '⏹ Stop Traffic Sim';
    S.simInt = setInterval(() => {
        S.pkt += Math.floor(Math.random() * 50 + 10);
        document.getElementById('pktCnt').textContent = S.pkt.toLocaleString();
        if (S.edges.length) spawnP(S.edges[Math.floor(Math.random() * S.edges.length)]);
    }, 200);
}

export function stopSim() {
    clearInterval(S.simInt); S.simRunning = false;
    S.edges.forEach(e => { e._atk = false; e._atkColor = null; });
    document.getElementById('simDot').classList.remove('run');
    document.getElementById('simLbl').textContent = 'IDLE'; document.getElementById('simLbl').style.color = 'var(--text3)';
    document.getElementById('simToggleBtn').textContent = '▶ Start Traffic Sim';
    redraw();
}

export function spawnP(edge) {
    const f = pp(edge.from, 'r'), t = pp(edge.to, 'l'); if (!f || !t) return;
    const p = document.createElement('div'); p.className = 'particle';
    const c = edge._atkColor || ec(edge);
    p.style.cssText = `background:${c};box-shadow:0 0 5px ${c};left:${f.x}px;top:${f.y - 2.5}px`;
    document.getElementById('canvas').appendChild(p);
    let step = 0;
    const a = setInterval(() => {
        step++; const tt = step / 18;
        p.style.left = (f.x + (t.x - f.x) * tt) + 'px';
        p.style.top = ((f.y + (t.y - f.y) * tt) - 2.5) + 'px';
        p.style.opacity = 1 - tt * .3;
        if (step >= 18) { clearInterval(a); p.remove(); }
    }, 700 / 18);
}

export async function runAttack(type) {
    if (!Object.keys(S.nodes).length) { alert('Add components first.'); return; }
    const sc2 = {
        sqli: { name: 'SQL Injection', color: '#ff4444', tgt: ['api', 'webserver', 'database'], steps: ['Scanning endpoints...', 'Sending malformed SQL payloads...', 'Attempting auth bypass...', 'Checking blind SQLi...', 'Exploiting error-based injection...'] },
        ddos: { name: 'DDoS Flood', color: '#ff8c00', tgt: ['webserver', 'loadbalancer', 'cdn'], steps: ['Spawning botnet nodes...', 'Initiating SYN flood...', 'Saturating bandwidth...', 'Testing rate limiting...', 'Volumetric amplification...'] },
        lateral: { name: 'Lateral Movement', color: '#ffd700', tgt: ['microservice', 'api', 'database', 'cache'], steps: ['Foothold established...', 'Enumerating internal network...', 'Scanning weak credentials...', 'Privilege escalation...', 'Pivoting toward data stores...'] },
        exfil: { name: 'Data Exfiltration', color: '#ff4444', tgt: ['database', 'storage', 'cache'], steps: ['Locating data stores...', 'Staging covert channel...', 'Encoding data...', 'DNS tunneling attempt...', 'Evading DLP controls...'] },
    };
    const s = sc2[type]; if (!s) return;
    for (const step of s.steps) {
        await sleep(500);
        S.edges.forEach(e => {
            const to = S.nodes[e.to];
            if (to && s.tgt.includes(to.type)) {
                e._atk = true; e._atkColor = s.color; spawnP(e);
                const nel = document.getElementById(e.to);
                if (nel) { nel.classList.add('threatened'); setTimeout(() => nel.classList.remove('threatened'), 1800); }
            }
        });
        redraw();
    }
    S.trig++; document.getElementById('trigCnt').textContent = S.trig;
    await sleep(2000);
    S.edges.forEach(e => { e._atk = false; e._atkColor = null; }); redraw();
}
