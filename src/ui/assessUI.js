/**
 * ASSESS UI — Countermeasures, STRIDE filter, Assessment checklist, Threat display
 */
import { S, S_attackPaths, S_boundaryFindings, strideFilter, setStrideFilter, setHoveredThreatId, selectedElementId, setSelectedElementId } from '../state/state.js';
import { sc, sn, scolor, rr, escHtml } from '../utils/helpers.js';
import { clearAttackPathHighlights } from '../engine/attackPaths.js';
import { injectGlossaryTooltips } from '../utils/glossary.js';
import { cvssColor } from '../engine/cvss.js';

export function renderDetected() {
    const con = document.getElementById('detectedThreats');
    // Use deduplicated findings for display; fall back to raw threats if findings not ready
    const source = (S.findings && S.findings.length) ? S.findings
        : (S.threats && S.threats.length) ? S.threats
            : [];
    if (!source.length) { con.innerHTML = '<div style="text-align:center;color:var(--low);padding:20px 0;font-size:12px">✅ No threats detected</div>'; return; }
    const ord = { critical: 0, high: 1, medium: 2, low: 3 };

    // Click-to-filter: if a node is selected, only show threats affecting it
    let threats = [...source];
    let filterHeader = '';
    if (selectedElementId) {
        threats = threats.filter(t => (t.affected || []).includes(selectedElementId));
        const nodeName = S.nodes[selectedElementId]?.label || selectedElementId;
        const totalCount = source.length;
        filterHeader = `<div class="threat-filter-header">
            <div class="filter-label">🔍 Showing threats for: <strong>${escHtml(nodeName)}</strong></div>
            <div class="filter-counts">${threats.length} of ${totalCount} findings</div>
            <button class="filter-clear-btn" id="clearNodeFilter">✕ Show All</button>
        </div>`;
    }

    const sorted = [...threats].sort((a, b) => ord[a.sev] - ord[b.sev]);
    con.innerHTML = sorted.map(t => {
        const isEnhanced = t.id && t.id.startsWith('R-');
        const owaspBadge = t.owasp ? `<div style="font-size:9px;font-family:'JetBrains Mono',monospace;color:var(--info);background:rgba(96,165,250,.12);border:1px solid rgba(96,165,250,.3);border-radius:3px;padding:2px 5px;margin-bottom:5px;display:inline-block">🔗 ${t.owasp}</div>` : '';
        const typeBadge = isEnhanced ? `<span style="font-size:8px;background:rgba(245,158,11,.15);color:var(--accent);border:1px solid rgba(245,158,11,.3);border-radius:2px;padding:1px 4px;margin-left:4px;font-family:'JetBrains Mono',monospace">RULE ENGINE</span>` : '';
        const locNames = (t.locationNames || []).map(escHtml).join(', ');
        const locationBadge = locNames ? `<div class="tc-location">📍 ${locNames}</div>` : '';
        const affectedJson = JSON.stringify(t.affected || []).replace(/"/g, '&quot;');

        // Evidence badge — shows corroborating rules collapsed under this primary finding
        const evidenceList = t.evidence || [];
        const evidenceBadge = evidenceList.length > 0
            ? `<span title="Also covers: ${evidenceList.map(e => escHtml(e.id)).join(', ')}" style="font-size:8px;background:rgba(148,163,184,.12);color:var(--text3);border:1px solid rgba(148,163,184,.25);border-radius:2px;padding:1px 5px;margin-left:4px;font-family:'JetBrains Mono',monospace;cursor:default">+${evidenceList.length} related</span>`
            : '';

        // Severity boost badge — shown when data classification elevated the severity
        const boostBadge = t._boosted
            ? `<span title="Severity boosted from ${t._origSev} because this threat affects a node holding sensitive data (PII/PHI/PCI)" style="font-size:8px;background:rgba(251,146,60,.15);color:#fb923c;border:1px solid rgba(251,146,60,.4);border-radius:2px;padding:1px 5px;margin-left:4px;font-family:'JetBrains Mono',monospace;cursor:help">⬆ boosted</span>`
            : '';

        // CVSS badge
        const cvss = t.cvss;
        const cvssBadge = cvss
            ? `<span title="CVSSv3.1 Vector: ${cvss.vector}" style="font-size:9px;font-family:'JetBrains Mono',monospace;font-weight:800;background:${cvssColor(cvss.score)}1a;color:${cvssColor(cvss.score)};border:1px solid ${cvssColor(cvss.score)}44;border-radius:3px;padding:2px 6px;margin-left:4px;cursor:default;letter-spacing:.3px">CVSS ${cvss.score}</span>`
            : '';

        return `
    <div class="threat-card tc-collapsed" id="tc-${t.id}" data-tc-id="${t.id}" data-affected="${affectedJson}">
      <div class="tc-head" style="cursor:pointer;margin-bottom:0">
        <div class="sev-dot" style="background:${sc(t.sev)}"></div>
        <div style="flex:1;min-width:0">
          <div class="tc-name" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escHtml(t.name)}</div>
          <div class="tc-id">${escHtml(t.id)}${typeBadge}${evidenceBadge}${boostBadge}${cvssBadge} · <span style="color:${sc(t.sev)}">${t.sev.toUpperCase()}</span></div>
          ${locationBadge}
        </div>
        <span style="font-size:10px;color:var(--text3);flex-shrink:0;padding-left:4px" id="tc-chevron-${t.id}">▸</span>
      </div>
      <div class="tc-body" id="tc-body-${t.id}" style="display:none;margin-top:8px">
        <span class="tc-stride" style="color:${scolor(t.stride)};border-color:${scolor(t.stride)}44">${sn(t.stride)}</span>
        ${owaspBadge}
        ${cvss ? `<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;flex-wrap:wrap">
          <span style="font-size:9px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.8px">CVSSv3.1</span>
          <span style="font-size:11px;font-weight:800;color:${cvssColor(cvss.score)}">${cvss.score} — ${cvss.rating}</span>
          <span style="font-size:8px;font-family:'JetBrains Mono',monospace;color:var(--text3);word-break:break-all">${cvss.vector !== 'N/A' ? cvss.vector : ''}</span>
        </div>` : ''}
        <div class="tc-desc">${injectGlossaryTooltips(t.desc)}</div>
        ${t.mits.map(m => `<div class="tc-mit">${injectGlossaryTooltips(m)}</div>`).join('')}
        ${evidenceList.length > 0 ? `<div style="margin-top:8px;padding-top:6px;border-top:1px solid var(--border)"><div style="font-size:9px;font-weight:700;color:var(--text3);letter-spacing:.8px;text-transform:uppercase;margin-bottom:4px">Also covers</div>${evidenceList.map(e => `<div style="font-size:9px;font-family:'JetBrains Mono',monospace;color:var(--text3);padding:1px 0">${escHtml(e.id)} — ${escHtml(e.name)}</div>`).join('')}</div>` : ''}
      </div>
    </div>`;
    }).join('');

    // Prepend filter header if filtering
    con.innerHTML = filterHeader + con.innerHTML;

    // Attach clear-filter button
    const clearBtn = document.getElementById('clearNodeFilter');
    if (clearBtn) {
        clearBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            setSelectedElementId(null);
            // Deselect node on canvas
            if (S.sel) {
                const prev = document.getElementById(S.sel);
                if (prev) prev.classList.remove('selected');
                S.sel = null;
            }
            renderDetected();
        });
    }

    // Attach click listeners for threat cards
    con.querySelectorAll('[data-tc-id]').forEach(card => {
        card.addEventListener('click', () => toggleThreatCard(card.dataset.tcId));

        // Hover: highlight affected nodes on canvas
        card.addEventListener('mouseenter', () => {
            const affected = JSON.parse(card.dataset.affected || '[]');
            setHoveredThreatId(card.dataset.tcId);
            document.querySelectorAll('.node.threat-hover-highlight').forEach(el => el.classList.remove('threat-hover-highlight'));
            affected.forEach(nid => {
                const el = document.getElementById(nid);
                if (el) el.classList.add('threat-hover-highlight');
            });
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
    // Use findings for CM table if available; raw threats as fallback
    const source = (S.findings && S.findings.length) ? S.findings : S.threats;
    const th = strideFilter ? source.filter(t => t.stride === strideFilter) : source;
    if (!th.length) { tbody.innerHTML = '<tr><td colspan="11" style="text-align:center;color:var(--text3);padding:28px">Run analysis in Step 2 first</td></tr>'; return; }
    const ord = { critical: 0, high: 1, medium: 2, low: 3 };
    tbody.innerHTML = [...th].sort((a, b) => ord[a.sev] - ord[b.sev]).map(t => {
        const row = S.cmRows[t.id] || { response: 'Mitigate', status: 'Non-Mitigated' };
        const risk = rr(t.like, t.imp);
        const cvss = t.cvss;
        const cvssCell = cvss
            ? `<span style="font-size:10px;font-weight:800;font-family:'JetBrains Mono',monospace;color:${cvssColor(cvss.score)}">${cvss.score}</span>`
            : `<span style="color:var(--text3);font-size:10px">—</span>`;
        // Build affected node pills
        const locNames = (t.locationNames || []);
        const nodePills = locNames.length
            ? locNames.map(n => `<span style="display:inline-block;font-size:9px;font-family:'JetBrains Mono',monospace;background:${sc(t.sev)}18;color:${sc(t.sev)};border:1px solid ${sc(t.sev)}44;border-radius:3px;padding:1px 5px;margin:1px 2px 1px 0;white-space:nowrap">${escHtml(n)}</span>`).join('')
            : `<span style="color:var(--text3);font-size:10px">—</span>`;

        // Escape description for use as attribute (strip HTML tags)
        const escapedDesc = (t.desc || '').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

        return `<tr>
          <td style="white-space:nowrap">${t.id}${t.owasp ? '<br><span style="font-size:8px;color:var(--info);font-family:\'JetBrains Mono\',monospace">' + t.owasp + '</span>' : ''}</td>
          <td style="color:var(--text);font-weight:600;font-size:12px;max-width:200px">
            <span title="${escapedDesc}" style="cursor:help">${escHtml(t.name)}</span>
          </td>
          <td style="min-width:120px">${nodePills}</td>
          <td><span style="font-size:10px;padding:2px 5px;border-radius:3px;background:${scolor(t.stride)}22;color:${scolor(t.stride)};border:1px solid ${scolor(t.stride)}44;font-family:'JetBrains Mono',monospace">${t.stride}</span></td>
          <td style="font-size:11px;font-weight:700;color:${sc(t.sev)}">${t.sev.toUpperCase()}</td>
          <td>${cvssCell}</td>
          <td style="font-size:11px">${t.like}</td>
          <td style="font-size:11px">${t.imp}</td>
          <td style="font-size:11px;font-weight:700;color:${sc(risk.toLowerCase())}">${risk}</td>
          <td><select class="cm-select" data-cm-id="${t.id}" data-cm-field="response"><option ${row.response === 'Mitigate' ? 'selected' : ''}>Mitigate</option><option ${row.response === 'Accept' ? 'selected' : ''}>Accept</option><option ${row.response === 'Eliminate' ? 'selected' : ''}>Eliminate</option><option ${row.response === 'Transfer' ? 'selected' : ''}>Transfer</option></select></td>
          <td><select class="cm-select" data-cm-id="${t.id}" data-cm-field="status"><option ${row.status === 'Non-Mitigated' ? 'selected' : ''}>Non-Mitigated</option><option ${row.status === 'Partial' ? 'selected' : ''}>Partial</option><option ${row.status === 'Mitigated' ? 'selected' : ''}>Mitigated</option></select></td>
        </tr>`;
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
    const nc = Object.keys(S.nodes).length;
    const ec2 = S.edges.length;
    const th = S.threats.length;
    const crit = S.threats.filter(t => t.sev === 'critical').length;
    const high = S.threats.filter(t => t.sev === 'high').length;
    const med = S.threats.filter(t => t.sev === 'medium').length;
    const mit = Object.values(S.cmRows).filter(r => r.status === 'Mitigated').length;
    const par = Object.values(S.cmRows).filter(r => r.status === 'Partial').length;

    // Stat counters
    document.getElementById('aN').textContent = nc;
    document.getElementById('aE').textContent = ec2;
    document.getElementById('aT').textContent = th;
    document.getElementById('aC').textContent = crit;
    document.getElementById('aH').textContent = high;
    document.getElementById('aM').textContent = med;
    document.getElementById('aMit').textContent = mit;
    document.getElementById('aPar').textContent = par;
    document.getElementById('aUnm').textContent = Math.max(0, th - mit - par);

    // ── Shostack 4-Question Completeness Checks ──────────────────────────────
    const name = document.getElementById('appName')?.value.trim() || '';
    const desc = document.getElementById('appDesc')?.value.trim() || '';
    const owner = document.getElementById('docOwner')?.value.trim() || '';
    const entryR = document.getElementById('entryTbody')?.querySelectorAll('tr').length || 0;
    const exitR = document.getElementById('exitTbody')?.querySelectorAll('tr').length || 0;
    const trustR = document.getElementById('trustTbody')?.querySelectorAll('tr').length || 0;
    const assetR = document.getElementById('assetsTbody')?.querySelectorAll('tr').length || 0;

    // Q1 — What are we working on?
    const q1_scope   = !!(name && desc && owner);
    const q1_dfd     = nc > 1 && ec2 > 0;
    const q1_entry   = entryR > 0 && exitR > 0;
    const q1_trust   = trustR > 0;
    const q1_assets  = assetR > 0;

    // Q2 — What can go wrong? (STRIDE coverage)
    const strideHits = { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 };
    S.threats.forEach(t => { if (t.stride in strideHits) strideHits[t.stride]++; });
    const q2_analyzed = th > 0;
    const q2_spoofing = strideHits.S > 0;
    const q2_tamper   = strideHits.T > 0;
    const q2_repud    = strideHits.R > 0;
    const q2_info     = strideHits.I > 0;
    const q2_dos      = strideHits.D > 0;
    const q2_elev     = strideHits.E > 0;
    const q2_paths    = (S_attackPaths || []).length > 0 || th > 0;
    const q2_boundary = (S_boundaryFindings || []).length > 0 || th > 0;

    // Q3 — What are we doing about it?
    const totalThreats = th;
    const responsedThreats = Object.keys(S.cmRows).length;
    const q3_mitigations = th > 0 && th <= responsedThreats;
    const q3_allResponded = th > 0 && Object.values(S.cmRows).every(r => r.response !== 'Mitigate' || r.status !== 'Non-Mitigated');
    const q3_noUnmitigatedCrit = crit === 0 || S.threats.filter(t => t.sev === 'critical' && S.cmRows[t.id]?.status === 'Non-Mitigated').length === 0;

    // Q4 — Did we do a good job?
    const q4_allNodesHaveThreats = nc > 0 && th > 0;
    const q4_sensitiveClassified = S.edges.some(e => e.dataClass && e.dataClass !== 'Public') || S.edges.some(e => e.dataClassification && e.dataClassification !== 'Public');
    const q4_strideComplete = Object.values(strideHits).every(v => v > 0);

    // ── Compute score (count of passing checks) ──────────────────────────────
    const checks = [
        q1_scope, q1_dfd, q1_entry, q1_trust, q1_assets,
        q2_analyzed, q2_spoofing, q2_tamper, q2_repud, q2_info, q2_dos, q2_elev,
        q2_paths, q2_boundary,
        q3_mitigations, q3_allResponded, q3_noUnmitigatedCrit,
        q4_allNodesHaveThreats, q4_sensitiveClassified, q4_strideComplete
    ];
    const passing = checks.filter(Boolean).length;
    const total = checks.length;
    const pct = Math.round((passing / total) * 100);

    // Update score badge
    const scoreEl = document.getElementById('completenessScore');
    if (scoreEl) {
        scoreEl.textContent = `${pct}%`;
        scoreEl.style.color = pct >= 80 ? 'var(--low)' : pct >= 50 ? 'var(--accent)' : 'var(--crit)';
    }
    const scoreLabelEl = document.getElementById('completenessLabel');
    if (scoreLabelEl) {
        scoreLabelEl.textContent = pct >= 80 ? 'Good coverage' : pct >= 50 ? 'Partial coverage' : 'Incomplete';
        scoreLabelEl.style.color = pct >= 80 ? 'var(--low)' : pct >= 50 ? 'var(--accent)' : 'var(--crit)';
    }

    // Update individual check items
    setChk('kScope',   q1_scope,   'Scope: app name, description & owner filled in');
    setChk('kDfd',     q1_dfd,     'DFD: >1 node and at least one edge drawn');
    setChk('kEntry',   q1_entry,   'Entry & exit points documented');
    setChk('kTrust',   q1_trust,   'Trust levels defined');
    setChk('kAssets',  q1_assets,  'Assets identified');
    setChk('kThreats', q2_analyzed,'Analysis run — threats found');
    setChk('kSTRIDE_S', q2_spoofing, 'Spoofing threats checked');
    setChk('kSTRIDE_T', q2_tamper,   'Tampering threats checked');
    setChk('kSTRIDE_R', q2_repud,    'Repudiation threats checked');
    setChk('kSTRIDE_I', q2_info,     'Information Disclosure threats checked');
    setChk('kSTRIDE_D', q2_dos,      'Denial of Service threats checked');
    setChk('kSTRIDE_E', q2_elev,     'Elevation of Privilege threats checked');
    setChk('kPaths',   q2_paths,   'Attack paths analyzed');
    setChk('kControls', q3_mitigations, 'All threats have a countermeasure response');
    setChk('kRisk',    q3_noUnmitigatedCrit, 'No unmitigated CRITICAL findings');
    setChk('kDataClass', q4_sensitiveClassified, 'Data flows are classified (not all "Public")');
    setChk('kStrideAll', q4_strideComplete, 'All 6 STRIDE categories have at least one finding');

    // Legacy checks (backwards compat)
    setChk('kBoundary', q1_trust, 'Trust boundaries documented');
}

export function setChk(id, ok, tooltip) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = ok ? '✓ Done' : '✗ Missing';
    el.className = 'chk-status ' + (ok ? 'chk-ok' : 'chk-fail');
    if (tooltip) el.title = tooltip;
}

