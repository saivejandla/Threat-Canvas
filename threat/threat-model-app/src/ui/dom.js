import { getState, updateNodeProp, updateNode, removeEdge } from '../state/state.js';
import { RuleManager } from '../engine/threatEngine.js';
import { DEFS } from './defs.js';
import { setCanvasAppMode, redrawWithBlast, redraw, pp, ec } from './canvas.js';
import { clearBlast } from './events.js'; // Requires circular or careful imports
import { scolor, sc, sn } from '../utils/helpers.js';

// DOM MODAL & UI HELPERS

export function showComponentThreats(nodeId) {
  const S = getState();
  const nd = S.nodes[nodeId]; if (!nd) return;
  const def = DEFS[nd.type]; if (!def) return;
  const threats = RuleManager.getComponentThreats(nd.type);
  const section = document.getElementById('ctpSection');

  const strideColors = { S: '#9b59b6', T: '#e67e22', R: '#3498db', I: '#e74c3c', D: '#2ecc71', E: '#ff6b6b' };
  const strideNames = { S: 'Spoofing', T: 'Tampering', R: 'Repudiation', I: 'Info Disclosure', D: 'Denial of Service', E: 'Elev. of Privilege' };
  const sevColor = { critical: '#ef4444', high: '#f97316', medium: '#facc15', low: '#34d399' };
  const strides = [...new Set(threats.map(t => t.stride))];

  const opt = (opts, cur) => opts.map(([v, l]) => `<option value="${v}"${v === cur ? ' selected' : ''}>${l}</option>`).join('');

  const tzColorMap = { internet: '#ff6b6b', dmz: '#ff8c00', internal: '#60a5fa', secure: '#34d399' };
  const ndTZ = nd.trustZone || 'internal';
  const tzC = tzColorMap[ndTZ] || '#60a5fa';

  section.innerHTML = `<div class="ctp-panel">
    <div class="ctp-header">
      <span class="ctp-icon">${def.icon}</span>
      <span class="ctp-name">${nd.label}</span>
      <button class="ctp-close" onclick="document.getElementById('ctpSection').style.display='none'">✕</button>
    </div>
    <div style="display:flex;align-items:center;gap:6px;padding:6px 12px;background:var(--s3);border-bottom:1px solid var(--border)">
      <span style="font-size:9px;font-weight:800;letter-spacing:.8px;text-transform:uppercase;color:var(--text3)">TRUST ZONE</span>
      <span style="font-size:10px;font-weight:800;font-family:'JetBrains Mono',monospace;padding:2px 8px;border-radius:3px;background:${tzC}18;color:${tzC};border:1px solid ${tzC}33">${ndTZ.toUpperCase()}</span>
    </div>

    <!-- Node blast properties -->
    <div class="np-panel" style="margin-bottom:8px">
      <div class="np-title">⚙️ Blast Radius Properties</div>
      <div class="np-row">
        <div class="np-fg">
          <span class="np-lbl">Network Zone</span>
          <select class="np-sel" data-npid="${nodeId}" data-npprop="zone">
            ${opt([['public', '🌐 Public'], ['dmz', '🔶 DMZ'], ['private', '🔵 Private'], ['isolated', '🟢 Isolated']], nd.zone || 'private')}
          </select>
        </div>
        <div class="np-fg">
          <span class="np-lbl">IAM Privilege</span>
          <select class="np-sel" data-npid="${nodeId}" data-npprop="iamPriv">
            ${opt([['none', 'None'], ['read-only', 'Read-Only'], ['standard', 'Standard'], ['write', 'Write'], ['assumerole', 'AssumeRole'], ['network-bypass', 'Network Bypass'], ['admin', 'Admin']], nd.iamPriv || 'standard')}
          </select>
        </div>
      </div>
      <div class="np-row">
        <div class="np-fg">
          <span class="np-lbl">Trust Zone</span>
          <select class="np-sel" data-npid="${nodeId}" data-nptz="true">
            ${opt([['internet', '🌐 Internet'], ['dmz', '🔶 DMZ'], ['internal', '🔵 Internal'], ['restricted', '🔒 Restricted']], nd.trustZone || 'internal')}
          </select>
        </div>
        <div class="np-fg">
          <span class="np-lbl">Data Class</span>
          <select class="np-sel" data-npid="${nodeId}" data-npprop="props.dataClassification">
            ${opt([['public', 'Public'], ['internal', 'Internal'], ['pii', 'PII'], ['secret', 'Secret']], nd.props?.dataClassification || 'internal')}
          </select>
        </div>
      </div>
      <div class="np-fg">
        <span class="np-lbl">Compromise Impact</span>
        <select class="np-sel" data-npid="${nodeId}" data-npprop="compromiseImpact">
          ${opt([['low', 'Low — limited blast, scoped credentials'], ['medium', 'Medium — typical internal service'], ['high', 'High — admin/deploy pipeline, bypasses scoping']], nd.compromiseImpact || 'medium')}
        </select>
      </div>
    </div>

    ${threats.length ? `<div class="ctp-stride-row">${strides.map(s => `<span class="ctp-badge" style="color:${strideColors[s]};border-color:${strideColors[s]}44;background:${strideColors[s]}18">${strideNames[s]}</span>`).join('')}</div>
    ${threats.map(t => `
      <div class="ctp-threat" style="border-left-color:${sevColor[t.sev]}">
        <div class="ctp-tname"><span style="color:${sevColor[t.sev]};font-size:9px;font-family:'JetBrains Mono',monospace;margin-right:5px">${t.sev.toUpperCase()}</span>${t.name}</div>
        ${t.mits.map(m => `<div class="ctp-mit">${m}</div>`).join('')}
      </div>`).join('')}` : ''}
  </div>`;
  section.style.display = 'block';
}

export function openEdgeEditor(edgeId) {
  const S = getState();
  const edge = S.edges.find(e => e.id === edgeId); if (!edge) return;
  const from = S.nodes[edge.from], to = S.nodes[edge.to];
  const section = document.getElementById('edgeEditorSection');

  const opt = (vals, cur) => vals.map(v => `<option${v === cur ? ' selected' : ''}>${v}</option>`).join('');

  section.innerHTML = `<div class="edge-editor">
    <div class="edge-editor-title">
      <span>✏️ Edit: ${from?.label || '?'} → ${to?.label || '?'}</span>
      <button style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:13px" id="btnCloseEdgeEditor">✕</button>
    </div>
    <div class="ee-row">
      <div class="ee-fg"><span class="ee-lbl">Protocol</span>
        <select class="ee-sel" data-eeid="${edgeId}" data-eeval="protocol">
          ${opt(['HTTPS', 'HTTP', 'TCP', 'UDP', 'gRPC', 'WebSocket', 'AMQP', 'SQL', 'Redis', 'S3'], edge.protocol)}</select></div>
      <div class="ee-fg"><span class="ee-lbl">Data Class</span>
        <select class="ee-sel" data-eeid="${edgeId}" data-eeval="dataClass">
          ${opt(['Public', 'Internal', 'Confidential', 'Restricted', 'PII', 'PHI', 'PCI'], edge.dataClass)}</select></div>
    </div>
    <div class="ee-row">
      <div class="ee-fg"><span class="ee-lbl">Auth</span>
        <select class="ee-sel" data-eeid="${edgeId}" data-eeval="auth">
          ${opt(['None', 'API Key', 'JWT', 'OAuth2', 'mTLS', 'IAM Role', 'Basic Auth'], edge.auth)}</select></div>
      <div class="ee-fg"><span class="ee-lbl">Encryption</span>
        <select class="ee-sel" data-eeid="${edgeId}" data-eeval="encryption">
          ${opt(['TLS 1.3', 'TLS 1.2 (strong)', 'TLS 1.2 (weak ciphers)', 'TLS 1.0/1.1', 'None'], edge.encryption)}</select></div>
    </div>
    <div class="ee-row">
      <div class="ee-fg"><span class="ee-lbl">Credential Scope</span>
        <select class="ee-sel" data-eeid="${edgeId}" data-eeval="credScope">
          ${opt(['shared', 'service-bound', 'vault'], edge.credScope || 'shared')}</select></div>
      <div class="ee-fg"><span class="ee-lbl">Network Route</span>
        <select class="ee-sel" data-eeid="${edgeId}" data-eeval="networkRoute">
          ${opt(['direct', 'vpc-peering', 'none'], edge.networkRoute || 'direct')}</select></div>
    </div>
    <div class="ee-fg" style="margin-bottom:6px"><span class="ee-lbl">Trust Boundary</span>
      <select class="ee-sel" data-eeid="${edgeId}" data-eeval="trustBoundary">
        ${opt(['No', 'Yes — Internet to DMZ', 'Yes — DMZ to Internal', 'Yes — Internal to Restricted'], edge.trustBoundary)}</select></div>
    <button class="ee-del" data-eedel="${edgeId}">🗑 Delete This Connection</button>
  </div>`;
  section.style.display = 'block';

  // We need to tell the system to flip to analyze mode if it is in blast
  document.dispatchEvent(new CustomEvent('appModeChangeRequest', { detail: 'analyze' }));
}

export function renderCM() {
  const S = getState();
  const tb = document.getElementById('cmTbody');
  if (!S.threats.length) {
    tb.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--text3);padding:28px">Run analysis in Step 2 first</td></tr>';
    return;
  }
  let h = '';
  S.threats.sort((a, b) => {
    const s = { critical: 4, high: 3, medium: 2, low: 1 };
    return s[b.sev] - s[a.sev];
  }).forEach(t => {
    const r = S.cmRows[t.id];
    // Needs global updater but for pure component HTML we only need data-attributes
    const rs = ['Accept', 'Eliminate', 'Mitigate', 'Transfer'].map(x => `<option${r.response === x ? ' selected' : ''}>${x}</option>`).join('');
    const st = ['Mitigated', 'Partial', 'Non-Mitigated'].map(x => `<option${r.status === x ? ' selected' : ''}>${x}</option>`).join('');

    // RR calculation is in helpers
    const m = { critical: 4, high: 3, medium: 2, low: 1 };
    const score = m[t.like.toLowerCase() || 'medium'] * m[t.imp.toLowerCase() || 'medium'];
    const risk = score >= 12 ? 'Critical' : score >= 6 ? 'High' : score >= 4 ? 'Medium' : 'Low';

    h += `<tr data-stride="${t.stride}">
      <td>${t.id}</td>
      <td><strong>${t.name}</strong><br><span style="font-size:10px;color:var(--text2)">${t.desc}</span></td>
      <td><span style="color:${scolor(t.stride)};font-weight:700">${sn(t.stride)}</span></td>
      <td><span style="color:${sc(t.sev)};font-weight:700">${t.sev.toUpperCase()}</span></td>
      <td>${t.like}</td><td>${t.imp}</td>
      <td><span style="color:${sc(risk.toLowerCase())};font-weight:700">${risk.toUpperCase()}</span></td>
      <td><select style="background:var(--s2);border:1px solid var(--border);color:var(--text);border-radius:4px;padding:3px" data-cmid="${t.id}" data-cmprop="response">${rs}</select></td>
      <td><select style="background:var(--s2);border:1px solid var(--border);color:var(--text);border-radius:4px;padding:3px" data-cmid="${t.id}" data-cmprop="status">${st}</select></td>
    </tr>`;
  });
  tb.innerHTML = h;
}

export function renderDetected(S) {
  const dt = document.getElementById('detectedThreats');
  if (!S.threats.length) {
    dt.innerHTML = '<div style="text-align:center;color:var(--text3);padding:24px 0;font-size:12px">No threats detected!</div>';
    return;
  }
  let h = '';
  S.threats.forEach(t => {
    h += `<div class="det-item">
      <div class="det-hdr" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
        <span class="det-sev" style="background:${sc(t.sev)}22;color:${sc(t.sev)}">${t.sev.toUpperCase()}</span>
        <span class="det-id">${t.id}</span>
        <span class="det-title">${t.name}</span>
      </div>
      <div class="det-body" style="display:none">
        <div style="font-size:11px;color:var(--text2);margin-bottom:8px">${t.desc}</div>
        <div style="font-size:10px;font-weight:800;letter-spacing:.5px;color:var(--text);margin-bottom:4px">AFFECTED NODES:</div>
        <div style="margin-bottom:8px">
          ${t.affected.map(nid => {
      const nd = S.nodes[nid];
      return `<span class="rp-node-pill" style="cursor:pointer" data-hlnode="${nid}">${nd?.label || nid}</span>`;
    }).join('')}
        </div>
        <div style="font-size:10px;font-weight:800;letter-spacing:.5px;color:var(--text);margin-bottom:4px">MITIGATIONS:</div>
        <ul style="margin:0;padding-left:14px">${t.mits.map(m => `<li>${m}</li>`).join('')}</ul>
      </div>
    </div>`;
  });
  dt.innerHTML = h;
}

export function setAnalysisModePanel(tabId) {
  document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
  document.getElementById(`rpTab-${tabId}`).classList.add('active');
  document.getElementById('rpPanel-threats').style.display = tabId === 'threats' ? 'block' : 'none';
  document.getElementById('rpPanel-paths').style.display = tabId === 'paths' ? 'block' : 'none';
}

export function drawAttackPathsList(attackPaths, boundaryFindings, S) {
  const apc = document.getElementById('attackPathsContainer');
  let apHtml = '';
  if (!attackPaths.length && !boundaryFindings.length) {
    apc.innerHTML = '<div style="text-align:center;color:var(--text3);padding:24px 0;font-size:12px">No attack paths detected.</div>';
    return;
  }

  if (attackPaths.length) {
    apHtml += `<div style="font-size:10px;font-weight:800;letter-spacing:1px;color:var(--text3);margin-bottom:8px;text-transform:uppercase">Full Compromise Paths</div>`;
    attackPaths.forEach((ap, i) => {
      const isCrit = ap.severity === 'critical';
      const color = isCrit ? '#ef4444' : '#f97316';

      const pNodeList = ap.path.map((nid, idx) => {
        const nd = S.nodes[nid];
        return `<span style="color:${idx === 0 ? '#ff4444' : idx === ap.path.length - 1 ? color : 'var(--text)'}">${nd?.label || nid}</span>`;
      }).join(' <span style="color:var(--border);margin:0 4px">→</span> ');

      apHtml += `<div class="ap-item" style="border-left-color:${color}">
        <div class="ap-hdr">
          <span style="background:${color}22;color:${color};padding:2px 6px;border-radius:4px;font-size:9px;font-weight:800">${ap.severity.toUpperCase()}</span>
          <span style="font-size:11px;font-weight:700;margin-left:6px">${ap.name}</span>
        </div>
        <div style="font-size:11px;color:var(--text2);margin-bottom:6px;line-height:1.6">${ap.desc}</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:10px;background:var(--s2);padding:6px 8px;border-radius:4px;border:1px solid var(--border)">${pNodeList}</div>
        <div style="margin-top:8px;display:flex;justify-content:flex-end">
          <button class="btn btn-ghost" style="font-size:10px;padding:4px 8px" data-hlpath="${i}">🔍 Highlight Path</button>
        </div>
      </div>`;
    });
  }

  if (boundaryFindings.length) {
    apHtml += `<div style="font-size:10px;font-weight:800;letter-spacing:1px;color:var(--text3);margin:16px 0 8px 0;text-transform:uppercase">Trust Boundary Violations</div>`;
    boundaryFindings.forEach((bf, i) => {
      const color = '#facc15';
      apHtml += `<div class="ap-item" style="border-left-color:${color}">
        <div class="ap-hdr">
          <span style="background:${color}22;color:${color};padding:2px 6px;border-radius:4px;font-size:9px;font-weight:800">WARNING</span>
          <span style="font-size:11px;font-weight:700;margin-left:6px">${bf.name}</span>
        </div>
        <div style="font-size:11px;color:var(--text2);margin-bottom:6px;line-height:1.6">${bf.desc}</div>
        <div style="margin-top:8px;display:flex;justify-content:flex-end">
          <button class="btn btn-ghost" style="font-size:10px;padding:4px 8px" data-hledges='${JSON.stringify(bf.edges)}'>🔍 Highlight Edges</button>
        </div>
      </div>`;
    });
  }
  apc.innerHTML = apHtml;
}

export function highlightNodes(nid) {
  Object.keys(getState().nodes).forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.classList.remove('stride-highlight'); if (id === nid) el.classList.add('stride-highlight'); }
  });
}

export function highlightPath(pathArray, severity) {
  const S = getState();
  // Clear existing
  Object.keys(S.nodes).forEach(id => { const el = document.getElementById(id); if (el) el.classList.remove('atk-path-critical', 'atk-path-high', 'atk-path-entry', 'boundary-violation', 'stride-highlight'); });
  S.edges.forEach(e => { e._atk = false; e._atkColor = null; });

  const hColor = severity === 'critical' ? '#ef4444' : '#f97316';
  const hClass = severity === 'critical' ? 'atk-path-critical' : 'atk-path-high';

  // Tag nodes
  pathArray.forEach((nid, idx) => {
    const el = document.getElementById(nid);
    if (!el) return;
    el.classList.add(hClass);
    if (idx === 0) el.classList.add('atk-path-entry');
  });

  // Tag edges 
  for (let i = 0; i < pathArray.length - 1; i++) {
    const e = S.edges.find(ed => ed.from === pathArray[i] && ed.to === pathArray[i + 1]);
    if (e) { e._atk = true; e._atkColor = hColor; }
  }
  redraw();
}

export function highlightEdges(edgesArray) {
  const S = getState();
  Object.keys(S.nodes).forEach(id => { const el = document.getElementById(id); if (el) el.classList.remove('atk-path-critical', 'atk-path-high', 'atk-path-entry', 'boundary-violation', 'stride-highlight'); });
  S.edges.forEach(e => { e._atk = false; e._atkColor = null; });

  edgesArray.forEach(eid => {
    const e = S.edges.find(ed => ed.id === eid);
    if (e) {
      e._atk = true;
      e._atkColor = '#facc15';
      const fEl = document.getElementById(e.from);
      const tEl = document.getElementById(e.to);
      if (fEl) fEl.classList.add('boundary-violation');
      if (tEl) tEl.classList.add('boundary-violation');
    }
  });
  redraw();
}

export function clearAnalysisHighlights() {
  const S = getState();
  Object.keys(S.nodes).forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('atk-path-critical', 'atk-path-high', 'atk-path-entry', 'boundary-violation', 'stride-highlight');
  });
  S.edges.forEach(e => { e._atk = false; e._atkColor = null; });
  redraw();
}
