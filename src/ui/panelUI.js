/**
 * PANEL UI — Mode toggle, Component Threat Profile, Edge Editor
 */
import { S, appMode, setAppMode, blastSourceId, setBlastSourceId } from '../state/state.js';
import { DEFS, COMPONENT_THREATS } from '../engine/componentDefs.js';
import { runBlast, clearBlast } from '../engine/blastRadius.js';
import { redraw } from './renderSVG.js';
import { renderTrustZoneOverlays } from './trustZones.js';
import { injectGlossaryTooltips } from '../utils/glossary.js';

export function setMode(mode) {
  setAppMode(mode);
  document.getElementById('modeAnalyze').classList.toggle('active', mode === 'analyze');
  document.getElementById('modeBlast').classList.toggle('active', mode === 'blast');
  document.getElementById('analyzeContent').style.display = mode === 'analyze' ? 'block' : 'none';
  document.getElementById('blastContent').style.display = mode === 'blast' ? 'block' : 'none';
  document.getElementById('blastInfo').style.display = mode === 'blast' ? 'block' : 'none';
  document.getElementById('ctpSection').style.display = 'none';
  document.getElementById('edgeEditorSection').style.display = 'none';
  if (mode === 'analyze') clearBlast();
  document.getElementById('canvas').style.cursor = mode === 'blast' ? 'crosshair' : '';
}

export function showComponentThreats(nodeId) {
  const nd = S.nodes[nodeId]; if (!nd) return;
  const def = DEFS[nd.type]; if (!def) return;
  const threats = COMPONENT_THREATS[nd.type] || [];
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
      <button class="ctp-close" id="ctpCloseBtn">✕</button>
    </div>
    <div style="display:flex;align-items:center;gap:6px;padding:6px 12px;background:var(--s3);border-bottom:1px solid var(--border)">
      <span style="font-size:9px;font-weight:800;letter-spacing:.8px;text-transform:uppercase;color:var(--text3)">TRUST ZONE</span>
      <span style="font-size:10px;font-weight:800;font-family:'JetBrains Mono',monospace;padding:2px 8px;border-radius:3px;background:${tzC}18;color:${tzC};border:1px solid ${tzC}33">${ndTZ.toUpperCase()}</span>
    </div>

    <div class="np-panel" style="margin-bottom:8px">
      <div class="np-title">⚙️ Blast Radius Properties</div>
      <div class="np-row">
        <div class="np-fg">
          <span class="np-lbl">Network Zone</span>
          <select class="np-sel" data-action="updateNodeProp" data-node="${nodeId}" data-prop="zone">
            ${opt([['public', '🌐 Public'], ['dmz', '🔶 DMZ'], ['private', '🔵 Private'], ['isolated', '🟢 Isolated']], nd.zone || 'private')}
          </select>
        </div>
        <div class="np-fg">
          <span class="np-lbl">IAM Privilege</span>
          <select class="np-sel" data-action="updateNodeProp" data-node="${nodeId}" data-prop="iamPriv">
            ${opt([['none', 'None'], ['standard', 'Standard'], ['assumerole', 'AssumeRole'], ['admin', 'Admin']], nd.iamPriv || 'standard')}
          </select>
        </div>
      </div>
      <div class="np-row">
        <div class="np-fg">
          <span class="np-lbl">Trust Zone</span>
          <select class="np-sel" data-action="updateNodeTrustZone" data-node="${nodeId}">
            ${opt([['internet', '🌐 Internet'], ['dmz', '🔶 DMZ'], ['internal', '🔵 Internal'], ['restricted', '🔒 Restricted']], nd.trustZone || 'internal')}
          </select>
        </div>
        <div class="np-fg">
          <span class="np-lbl">Data Class</span>
          <select class="np-sel" data-action="updateNodeProp" data-node="${nodeId}" data-prop="props.dataClassification">
            ${opt([['public', 'Public'], ['internal', 'Internal'], ['pii', 'PII'], ['secret', 'Secret']], nd.props?.dataClassification || 'internal')}
          </select>
        </div>
      </div>
      <div class="np-fg">
        <span class="np-lbl">Compromise Impact</span>
        <select class="np-sel" data-action="updateNodeProp" data-node="${nodeId}" data-prop="compromiseImpact">
          ${opt([['low', 'Low — limited blast, scoped credentials'], ['medium', 'Medium — typical internal service'], ['high', 'High — admin/deploy pipeline, bypasses scoping']], nd.compromiseImpact || 'medium')}
        </select>
      </div>
    </div>

    ${threats.length ? `<div class="ctp-stride-row">${strides.map(s => `<span class="ctp-badge" style="color:${strideColors[s]};border-color:${strideColors[s]}44;background:${strideColors[s]}18">${strideNames[s]}</span>`).join('')}</div>
    ${threats.map(t => `
      <div class="ctp-threat" style="border-left-color:${sevColor[t.sev]}">
        <div class="ctp-tname"><span style="color:${sevColor[t.sev]};font-size:9px;font-family:'JetBrains Mono',monospace;margin-right:5px">${t.sev.toUpperCase()}</span>${t.name}</div>
        ${t.mits.map(m => `<div class="ctp-mit">${injectGlossaryTooltips(m)}</div>`).join('')}
      </div>`).join('')}` : ''}
  </div>`;
  section.style.display = 'block';

  // Attach event listeners
  section.querySelector('#ctpCloseBtn')?.addEventListener('click', () => { section.style.display = 'none'; });
  section.querySelectorAll('[data-action="updateNodeProp"]').forEach(sel => {
    sel.addEventListener('change', () => updateNodeProp(sel.dataset.node, sel.dataset.prop, sel.value));
  });
  section.querySelectorAll('[data-action="updateNodeTrustZone"]').forEach(sel => {
    sel.addEventListener('change', () => updateNodeTrustZone(sel.dataset.node, sel.value));
  });
}

export function updateNodeTrustZone(nodeId, tz) {
  if (!S.nodes[nodeId]) return;
  S.nodes[nodeId].trustZone = tz;
  const el = document.getElementById(nodeId);
  if (el) {
    el.classList.remove('tz-internet-node', 'tz-dmz-node', 'tz-internal-node', 'tz-secure-node');
    el.classList.add('tz-' + tz + '-node');
  }
  renderTrustZoneOverlays();
  if (blastSourceId) runBlast(blastSourceId);
}

export function updateNodeProp(nodeId, prop, val) {
  if (!S.nodes[nodeId]) return;
  if (prop.startsWith('props.')) {
    const key = prop.slice(6);
    if (!S.nodes[nodeId].props) S.nodes[nodeId].props = {};
    S.nodes[nodeId].props[key] = val;
  } else {
    S.nodes[nodeId][prop] = val;
  }
  if (blastSourceId) runBlast(blastSourceId);
}

export function openEdgeEditor(edgeId) {
  const edge = S.edges.find(e => e.id === edgeId); if (!edge) return;
  const from = S.nodes[edge.from], to = S.nodes[edge.to];
  const section = document.getElementById('edgeEditorSection');

  const opt = (vals, cur) => vals.map(v => `<option${v === cur ? ' selected' : ''}>${v}</option>`).join('');

  section.innerHTML = `<div class="edge-editor">
    <div class="edge-editor-title">
      <span>✏️ Edit: ${from?.label || '?'} → ${to?.label || '?'}</span>
      <button style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:13px" id="eeCloseBtn">✕</button>
    </div>
    <div class="ee-row">
      <div class="ee-fg"><span class="ee-lbl">Protocol</span>
        <select class="ee-sel" data-field="protocol">
          ${opt(['HTTPS', 'HTTP', 'TCP', 'UDP', 'gRPC', 'WebSocket', 'AMQP', 'SQL', 'Redis', 'S3'], edge.protocol)}</select></div>
      <div class="ee-fg"><span class="ee-lbl">Data Class</span>
        <select class="ee-sel" data-field="dataClass">
          ${opt(['Public', 'Internal', 'Confidential', 'Restricted', 'PII', 'PHI', 'PCI'], edge.dataClass)}</select></div>
    </div>
    <div class="ee-row">
      <div class="ee-fg"><span class="ee-lbl">Auth</span>
        <select class="ee-sel" data-field="auth">
          ${opt(['None', 'API Key', 'JWT', 'OAuth2', 'mTLS', 'IAM Role', 'Basic Auth'], edge.auth)}</select></div>
      <div class="ee-fg"><span class="ee-lbl">Encryption</span>
        <select class="ee-sel" data-field="encryption">
          ${opt(['TLS 1.3', 'TLS 1.2 (strong)', 'TLS 1.2 (weak ciphers)', 'TLS 1.0/1.1', 'None'], edge.encryption)}</select></div>
    </div>
    <div class="ee-row">
      <div class="ee-fg"><span class="ee-lbl">Credential Scope</span>
        <select class="ee-sel" data-field="credScope">
          ${opt(['shared', 'service-bound', 'vault'], edge.credScope || 'shared')}</select></div>
      <div class="ee-fg"><span class="ee-lbl">Network Route</span>
        <select class="ee-sel" data-field="networkRoute">
          ${opt(['direct', 'vpc-peering', 'none'], edge.networkRoute || 'direct')}</select></div>
    </div>
    <div class="ee-fg" style="margin-bottom:6px"><span class="ee-lbl">Trust Boundary</span>
      <select class="ee-sel" data-field="trustBoundary">
        ${opt(['No', 'Yes — Internet to DMZ', 'Yes — DMZ to Internal', 'Yes — Internal to Restricted'], edge.trustBoundary)}</select></div>
    <button class="ee-del" id="eeDelBtn">🗑 Delete This Connection</button>
  </div>`;
  section.style.display = 'block';

  // Event listeners
  section.querySelector('#eeCloseBtn')?.addEventListener('click', () => { section.style.display = 'none'; });
  section.querySelector('#eeDelBtn')?.addEventListener('click', () => deleteEdge(edgeId));
  section.querySelectorAll('.ee-sel').forEach(sel => {
    sel.addEventListener('change', () => updateEdge(edgeId, sel.dataset.field, sel.value));
  });

  if (appMode === 'blast') { setMode('analyze'); }
}

export function updateEdge(edgeId, field, val) {
  const edge = S.edges.find(e => e.id === edgeId);
  if (edge) {
    edge[field] = val;
    if (blastSourceId) runBlast(blastSourceId);
    else redraw();
  }
}

export function deleteEdge(edgeId) {
  S.edges = S.edges.filter(e => e.id !== edgeId);
  document.getElementById('edgeEditorSection').style.display = 'none';
  redraw();
}
