/**
 * SCOPE UI — Step navigation, section toggling, table row CRUD
 */
import { S, ROW_COUNTS } from '../state/state.js';
import { renderCM } from './assessUI.js';
import { refreshAssess } from './assessUI.js';
import { vpZ, vpX, vpY, _applyViewport } from './zoomPan.js';

export function goStep(n) {
    document.querySelectorAll('.step-panel').forEach((p, i) => p.classList.toggle('active', i === n - 1));
    document.querySelectorAll('.step-tab').forEach((t, i) => t.classList.toggle('active', i === n - 1));
    const isC = n === 2;
    document.getElementById('simBar').style.display = isC ? 'flex' : 'none';
    document.getElementById('mainToolbar').style.display = isC ? 'none' : 'flex';
    if (isC && !Object.keys(S.nodes).length) {
        // Directly set viewport variables via zoomReset-like logic
        // We can't reassign let imports, so use _applyViewport after direct DOM update
        const vp = document.getElementById('viewport');
        if (vp) vp.style.transform = `translate(16px,16px) scale(1)`;
        document.getElementById('zoomPct').textContent = '100%';
    }
    if (n === 3) renderCM();
    if (n === 4) refreshAssess();
}

export function showSec(id, el) {
    document.querySelectorAll('.scope-section').forEach(s => s.classList.remove('asec'));
    document.querySelectorAll('.scope-nav-item').forEach(n => n.classList.remove('anav'));
    document.getElementById('sec-' + id).classList.add('asec');
    el.classList.add('anav');
}

export const ROW_TEMPLATES = {
    deps: (i) => `<tr><td>DEP-${i}</td><td contenteditable="true" style="outline:none;color:var(--text2)" placeholder="Describe...">Click to edit</td><td><button class="del-btn" onclick="this.closest('tr').remove()">✕</button></td></tr>`,
    entry: (i) => `<tr><td>EP-${i}</td><td contenteditable="true" style="outline:none;color:var(--text)">Name</td><td contenteditable="true" style="outline:none;color:var(--text2)">Description</td><td contenteditable="true" style="outline:none;color:var(--text2)">TL-1</td><td><button class="del-btn" onclick="this.closest('tr').remove()">✕</button></td></tr>`,
    exit: (i) => `<tr><td>XP-${i}</td><td contenteditable="true" style="outline:none;color:var(--text)">Name</td><td contenteditable="true" style="outline:none;color:var(--text2)">Description</td><td><select style="background:var(--s2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;padding:2px"><option>High</option><option>Medium</option><option>Low</option></select></td><td><button class="del-btn" onclick="this.closest('tr').remove()">✕</button></td></tr>`,
    assets: (i) => `<tr><td>A-${i}</td><td contenteditable="true" style="outline:none;color:var(--text)">Name</td><td contenteditable="true" style="outline:none;color:var(--text2)">What and why protect</td><td contenteditable="true" style="outline:none;color:var(--text2)">TL-1</td><td><button class="del-btn" onclick="this.closest('tr').remove()">✕</button></td></tr>`,
    trust: (i) => `<tr><td>TL-${i}</td><td contenteditable="true" style="outline:none;color:var(--text)">Name</td><td contenteditable="true" style="outline:none;color:var(--text2)">Description</td><td><button class="del-btn" onclick="this.closest('tr').remove()">✕</button></td></tr>`,
};

export function addRow(type) {
    ROW_COUNTS[type]++;
    document.getElementById(type + 'Tbody').insertAdjacentHTML('beforeend', ROW_TEMPLATES[type](ROW_COUNTS[type]));
}
