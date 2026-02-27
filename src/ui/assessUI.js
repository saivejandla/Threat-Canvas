/**
 * ASSESS UI — Countermeasures, STRIDE filter, Assessment checklist, Threat display
 */
import { S, strideFilter, setStrideFilter, setHoveredThreatId } from '../state/state.js';
import { sc, sn, scolor, rr } from '../utils/helpers.js';
import { clearAttackPathHighlights } from '../engine/attackPaths.js';
import { injectGlossaryTooltips } from '../utils/glossary.js';

export function renderDetected() {
    const con = document.getElementById('detectedThreats');
    if (!S.threats.length) { con.innerHTML = '<div style="text-align:center;color:var(--low);padding:20px 0;font-size:12px">✅ No threats detected</div>'; return; }
    const ord = { critical: 0, high: 1, medium: 2, low: 3 };
    const sorted = [...S.threats].sort((a, b) => ord[a.sev] - ord[b.sev]);
    con.innerHTML = sorted.map(t => {
        const isEnhanced = t.id && t.id.startsWith('R-');
        const owaspBadge = t.owasp ? `<div style="font-size:9px;font-family:'JetBrains Mono',monospace;color:var(--info);background:rgba(96,165,250,.12);border:1px solid rgba(96,165,250,.3);border-radius:3px;padding:2px 5px;margin-bottom:5px;display:inline-block">🔗 ${t.owasp}</div>` : '';
        const typeBadge = isEnhanced ? `<span style="font-size:8px;background:rgba(245,158,11,.15);color:var(--accent);border:1px solid rgba(245,158,11,.3);border-radius:2px;padding:1px 4px;margin-left:4px;font-family:'JetBrains Mono',monospace">RULE ENGINE</span>` : '';
        const locNames = (t.locationNames || []).join(', ');
        const locationBadge = locNames ? `<div class="tc-location">📍 ${locNames}</div>` : '';
        const affectedJson = JSON.stringify(t.affected || []).replace(/"/g, '&quot;');
        return `
    <div class="threat-card tc-collapsed" id="tc-${t.id}" data-tc-id="${t.id}" data-affected="${affectedJson}">
      <div class="tc-head" style="cursor:pointer;margin-bottom:0">
        <div class="sev-dot" style="background:${sc(t.sev)}"></div>
        <div style="flex:1;min-width:0">
          <div class="tc-name" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${t.name}</div>
          <div class="tc-id">${t.id}${typeBadge} · <span style="color:${sc(t.sev)}">${t.sev.toUpperCase()}</span></div>
          ${locationBadge}
        </div>
        <span style="font-size:10px;color:var(--text3);flex-shrink:0;padding-left:4px" id="tc-chevron-${t.id}">▸</span>
      </div>
      <div class="tc-body" id="tc-body-${t.id}" style="display:none;margin-top:8px">
        <span class="tc-stride" style="color:${scolor(t.stride)};border-color:${scolor(t.stride)}44">${sn(t.stride)}</span>
        ${owaspBadge}
        <div class="tc-desc">${injectGlossaryTooltips(t.desc)}</div>
        ${t.mits.map(m => `<div class="tc-mit">${injectGlossaryTooltips(m)}</div>`).join('')}
      </div>
    </div>`;
    }).join('');

    // Attach click listeners for threat cards
    con.querySelectorAll('[data-tc-id]').forEach(card => {
        card.addEventListener('click', () => toggleThreatCard(card.dataset.tcId));

        // Hover: highlight affected nodes on canvas
        card.addEventListener('mouseenter', () => {
            const affected = JSON.parse(card.dataset.affected || '[]');
            setHoveredThreatId(card.dataset.tcId);
            // Clear previous highlights
            document.querySelectorAll('.node.threat-hover-highlight').forEach(el => el.classList.remove('threat-hover-highlight'));
            // Apply highlight to affected nodes
            affected.forEach(nid => {
                const el = document.getElementById(nid);
                if (el) el.classList.add('threat-hover-highlight');
            });
            // Also highlight related edges in SVG
            document.querySelectorAll('.edge-threat-highlight').forEach(el => el.classList.remove('edge-threat-highlight'));
            const svg = document.getElementById('svgLayer');
            if (svg) {
                svg.querySelectorAll('.edge-hit').forEach(hit => {
                    const eid = hit.dataset.eid;
                    if (!eid) return;
                    const edge = S.edges.find(e => e.id === eid);
                    if (edge && (affected.includes(edge.from) || affected.includes(edge.to))) {
                        hit.classList.add('edge-threat-highlight');
                    }
                });
            }
        });

        card.addEventListener('mouseleave', () => {
            setHoveredThreatId(null);
            document.querySelectorAll('.node.threat-hover-highlight').forEach(el => el.classList.remove('threat-hover-highlight'));
            document.querySelectorAll('.edge-threat-highlight').forEach(el => el.classList.remove('edge-threat-highlight'));
        });
    });
}

export function toggleThreatCard(id) {
    const body = document.getElementById('tc-body-' + id);
    const chevron = document.getElementById('tc-chevron-' + id);
    const card = document.getElementById('tc-' + id);
    const open = body.style.display === 'none';
    body.style.display = open ? 'block' : 'none';
    chevron.textContent = open ? '▾' : '▸';
    card.classList.toggle('tc-collapsed', !open);
}

export function switchRpTab(tab) {
    ['threats', 'paths'].forEach(t => {
        document.getElementById('rpTab-' + t).classList.toggle('active', t === tab);
        document.getElementById('rpPanel-' + t).style.display = t === tab ? 'block' : 'none';
    });
    if (tab === 'threats') clearAttackPathHighlights();
}

export function filterSTRIDE(s) {
    setStrideFilter(strideFilter === s ? null : s);
    const newFilter = strideFilter === s ? null : s; // re-read after set
    document.querySelectorAll('.stride-card').forEach((c, i) => c.classList.toggle('af', ['S', 'T', 'R', 'I', 'D', 'E'][i] === newFilter));
    renderCM();
    document.querySelectorAll('.node').forEach(n => n.classList.remove('stride-highlight'));
    if (newFilter) {
        const affNodes = new Set();
        S.threats.filter(t => t.stride === newFilter).forEach(t => (t.affected || []).forEach(id => affNodes.add(id)));
        affNodes.forEach(id => { const el = document.getElementById(id); if (el) el.classList.add('stride-highlight'); });
    }
}

export function renderCM() {
    const tbody = document.getElementById('cmTbody');
    const th = strideFilter ? S.threats.filter(t => t.stride === strideFilter) : S.threats;
    if (!th.length) { tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text3);padding:28px">Run analysis in Step 2 first</td></tr>'; return; }
    const ord = { critical: 0, high: 1, medium: 2, low: 3 };
    tbody.innerHTML = [...th].sort((a, b) => ord[a.sev] - ord[b.sev]).map(t => {
        const row = S.cmRows[t.id] || { response: 'Mitigate', status: 'Non-Mitigated' };
        const risk = rr(t.like, t.imp);
        return `<tr><td>${t.id}${t.owasp ? '<br><span style="font-size:8px;color:var(--info);font-family:\'JetBrains Mono\',monospace">' + t.owasp + '</span>' : ''}</td><td style="color:var(--text);font-weight:600;font-size:12px">${t.name}</td><td><span style="font-size:10px;padding:2px 5px;border-radius:3px;background:${scolor(t.stride)}22;color:${scolor(t.stride)};border:1px solid ${scolor(t.stride)}44;font-family:'JetBrains Mono',monospace">${t.stride}</span></td><td style="font-size:11px;font-weight:700;color:${sc(t.sev)}">${t.sev.toUpperCase()}</td><td style="font-size:11px">${t.like}</td><td style="font-size:11px">${t.imp}</td><td style="font-size:11px;font-weight:700;color:${sc(risk.toLowerCase())}">${risk}</td><td><select class="cm-select" data-cm-id="${t.id}" data-cm-field="response"><option ${row.response === 'Mitigate' ? 'selected' : ''}>Mitigate</option><option ${row.response === 'Accept' ? 'selected' : ''}>Accept</option><option ${row.response === 'Eliminate' ? 'selected' : ''}>Eliminate</option><option ${row.response === 'Transfer' ? 'selected' : ''}>Transfer</option></select></td><td><select class="cm-select" data-cm-id="${t.id}" data-cm-field="status"><option ${row.status === 'Non-Mitigated' ? 'selected' : ''}>Non-Mitigated</option><option ${row.status === 'Partial' ? 'selected' : ''}>Partial</option><option ${row.status === 'Mitigated' ? 'selected' : ''}>Mitigated</option></select></td></tr>`;
    }).join('');

    // Attach listeners to CM selects
    tbody.querySelectorAll('.cm-select').forEach(sel => {
        sel.addEventListener('change', () => updCM(sel.dataset.cmId, sel.dataset.cmField, sel.value));
    });
}

export function updCM(id, field, val) {
    if (!S.cmRows[id]) S.cmRows[id] = { response: 'Mitigate', status: 'Non-Mitigated' };
    S.cmRows[id][field] = val;
}

export function refreshAssess() {
    const nc = Object.keys(S.nodes).length, ec2 = S.edges.length, th = S.threats.length;
    const crit = S.threats.filter(t => t.sev === 'critical').length;
    const high = S.threats.filter(t => t.sev === 'high').length;
    const med = S.threats.filter(t => t.sev === 'medium').length;
    const mit = Object.values(S.cmRows).filter(r => r.status === 'Mitigated').length;
    const par = Object.values(S.cmRows).filter(r => r.status === 'Partial').length;
    document.getElementById('aN').textContent = nc; document.getElementById('aE').textContent = ec2; document.getElementById('aT').textContent = th;
    document.getElementById('aC').textContent = crit; document.getElementById('aH').textContent = high; document.getElementById('aM').textContent = med;
    document.getElementById('aMit').textContent = mit; document.getElementById('aPar').textContent = par; document.getElementById('aUnm').textContent = Math.max(0, th - mit - par);
    const name = document.getElementById('appName').value.trim();
    const desc = document.getElementById('appDesc').value.trim();
    const owner = document.getElementById('docOwner').value.trim();
    const entryR = document.getElementById('entryTbody').querySelectorAll('tr').length;
    const exitR = document.getElementById('exitTbody').querySelectorAll('tr').length;
    const trustR = document.getElementById('trustTbody').querySelectorAll('tr').length;
    const assetR = document.getElementById('assetsTbody').querySelectorAll('tr').length;
    setChk('kDfd', nc > 0 && ec2 > 0);
    setChk('kScope', !!(name && desc && owner));
    setChk('kEntry', entryR > 0 && exitR > 0);
    setChk('kTrust', trustR > 0);
    setChk('kAssets', assetR > 0);
    setChk('kThreats', th > 0);
    setChk('kControls', th > 0 && Object.keys(S.cmRows).length >= th);
    setChk('kRisk', th > 0);
}

export function setChk(id, ok) {
    const el = document.getElementById(id); if (!el) return;
    el.textContent = ok ? '✓ Done' : '✗ Missing';
    el.className = 'chk-status ' + (ok ? 'chk-ok' : 'chk-fail');
}
