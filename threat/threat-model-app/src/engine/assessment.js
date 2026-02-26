import { getState } from '../state/state.js';
import { sc, sn, scolor } from '../utils/helpers.js';

export function refreshAssess() {
  const S = getState();
  if (!S.threats) return; // Not analyzed yet

  const chk = (id, cond) => {
    const el = document.getElementById(id); if (!el) return;
    el.className = 'chk-status ' + (cond ? 'chk-pass' : 'chk-fail');
    el.innerHTML = cond ? '✓ Complete' : '✗ Missing';
  };

  chk('kDfd', Object.keys(S.nodes).length > 0);
  chk('kScope', document.getElementById('appName')?.value.length > 0);
  chk('kEntry', document.getElementById('entryTbody')?.children.length > 0);
  chk('kTrust', document.getElementById('trustTbody')?.children.length > 0);
  chk('kAssets', document.getElementById('assetsTbody')?.children.length > 0);
  chk('kThreats', S.threats.length > 0);

  const cmRowsArr = Object.values(S.cmRows);
  chk('kControls', S.threats.length > 0 && cmRowsArr.length === S.threats.length && cmRowsArr.every(r => r.status === 'Mitigated'));
  chk('kRisk', S.threats.length > 0 && S.threats.every(t => t.sev));

  const sv = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  sv('aN', Object.keys(S.nodes).length);
  sv('aE', S.edges.length);
  sv('aT', S.threats.length);
  sv('aC', S.threats.filter(t => t.sev === 'critical').length);
  sv('aH', S.threats.filter(t => t.sev === 'high').length);
  sv('aM', S.threats.filter(t => t.sev === 'medium').length);

  sv('aMit', cmRowsArr.filter(r => r.status === 'Mitigated').length);
  sv('aPar', cmRowsArr.filter(r => r.status === 'Partial').length);
  sv('aUnm', cmRowsArr.filter(r => r.status === 'Non-Mitigated').length);
}

export function calculateMaturityMetrics() {
  const S = getState();
  const total = S.threats.length;
  const criticals = S.threats.filter(t => t.sev === 'critical').length;
  const highs = S.threats.filter(t => t.sev === 'high').length;
  const cmRowsArr = Object.values(S.cmRows);
  const mitigated = cmRowsArr.filter(r => r.status === 'Mitigated').length;
  const partial = cmRowsArr.filter(r => r.status === 'Partial').length;
  const mitigPct = total > 0 ? mitigated / total : 0;

  const sevDread = { critical: 9, high: 7, medium: 5, low: 3 };
  const totalDread = S.threats.reduce((acc, t) => acc + (sevDread[t.sev] || 5), 0);
  const avgDread = total > 0 ? (totalDread / total).toFixed(1) : '—';

  const nodeTypes = Object.values(S.nodes).map(n => n.type);
  const detectors = ['siem', 'waf', 'firewall'].filter(t => nodeTypes.includes(t));
  const detProbs = { siem: 0.85, waf: 0.60, firewall: 0.45 };
  const detectConf = detectors.length
    ? Math.round((1 - detectors.reduce((p, t) => p * (1 - detProbs[t]), 1)) * 100)
    : 0;
  const detectorNodes = detectors.map(t => Object.values(S.nodes).find(n => n.type === t)).filter(Boolean);

  let level, statusColor, levelDesc;
  if (total === 0) {
    level = 'Not Assessed'; statusColor = 'var(--text3)';
    levelDesc = 'No analysis has been run. Build a DFD and run analysis first.';
  } else if (criticals > 0) {
    level = 'Initial'; statusColor = 'var(--crit)';
    levelDesc = 'Critical vulnerabilities require immediate remediation before deployment.';
  } else if (mitigPct > 0.8) {
    level = 'Proactive'; statusColor = 'var(--low)';
    levelDesc = 'Security posture exceeds baseline. Architecture demonstrates secure-by-design principles.';
  } else if (mitigPct > 0.7 && criticals === 0) {
    level = 'Managed'; statusColor = 'var(--low)';
    levelDesc = 'Risk is well-understood and largely under control. Continue mitigation progress.';
  } else if (criticals < 3) {
    level = 'Defined'; statusColor = 'var(--med)';
    levelDesc = 'Threats are identified but mitigation coverage needs improvement.';
  } else {
    level = 'Initial'; statusColor = 'var(--crit)';
    levelDesc = 'High number of unresolved critical risks. Prioritize remediation immediately.';
  }

  const STRIDE_NARRATIVES = {
    S: 'Potential for unauthorized identity assumption, credential theft, and fraudulent transactions.',
    T: 'Risk of data integrity violations, undetected modification of records, and audit log tampering.',
    R: 'Inability to attribute actions to users, undermining audit trails and regulatory accountability.',
    I: 'Risk of regulatory non-compliance (GDPR / PCI-DSS / HIPAA) and loss of customer trust through data exposure.',
    D: 'Operational risk involving service downtime, SLA breaches, and direct revenue loss.',
    E: 'Attackers may gain administrative control, enabling lateral movement across the entire system.',
  };
  const activeNarratives = [...new Set(S.threats.map(t => t.stride))]
    .filter(s => STRIDE_NARRATIVES[s])
    .map(s => ({ stride: s, name: sn(s), text: STRIDE_NARRATIVES[s] }));

  const actions = [];
  if (criticals > 0)
    actions.push({ tag: 'IMMEDIATE', color: 'var(--crit)', bg: 'rgba(239,68,68,.1)', text: `Remediate ${criticals} critical vulnerabilit${criticals === 1 ? 'y' : 'ies'}. Secure unencrypted data paths and implement missing WAF/Firewall controls.` });
  if (!detectors.includes('waf') && !detectors.includes('firewall'))
    actions.push({ tag: 'HIGH PRIORITY', color: 'var(--high)', bg: 'rgba(249,115,22,.1)', text: 'No WAF or Firewall detected in the architecture. Add perimeter controls to reduce attack surface.' });
  if (mitigated < total)
    actions.push({ tag: 'SHORT-TERM', color: 'var(--accent)', bg: 'rgba(245,158,11,.1)', text: `Complete countermeasure register for ${total - mitigated} pending threat${total - mitigated === 1 ? '' : 's'}.` });
  if (!detectors.includes('siem'))
    actions.push({ tag: 'ONGOING', color: 'var(--info)', bg: 'rgba(96,165,250,.1)', text: 'No SIEM detected. Implement centralized log aggregation and anomaly alerting for operational visibility.' });
  if (actions.length === 0)
    actions.push({ tag: 'MAINTAIN', color: 'var(--low)', bg: 'rgba(52,211,153,.1)', text: 'Security posture is strong. Schedule periodic threat model reviews as architecture evolves.' });

  return { total, criticals, highs, mitigated, partial, mitigPct, avgDread, detectConf, detectors, detectorNodes, level, statusColor, levelDesc, activeNarratives, actions };
}

export function buildExecSummaryHTML(m, forExport = false) {
  const appName = document.getElementById('appName')?.value || 'Unnamed Application';
  const appVer = document.getElementById('appVersion')?.value || '1.0';
  const docOwner = document.getElementById('docOwner')?.value || '—';
  const docDate = document.getElementById('docDate')?.value || new Date().toISOString().split('T')[0];

  const mitigPct = m.total > 0 ? Math.round(m.mitigPct * 100) : 0;
  const colorMap = { 'var(--crit)': '#ef4444', 'var(--high)': '#f97316', 'var(--med)': '#facc15', 'var(--low)': '#34d399', 'var(--accent)': '#f59e0b', 'var(--info)': '#60a5fa', 'var(--text3)': '#3d5275' };
  const col = c => forExport ? (colorMap[c] || c) : c;

  if (forExport) {
    const narrativeRows = m.activeNarratives.map(n => `<tr><td style="font-weight:700;white-space:nowrap;color:${col(scolor(n.stride))}">${n.name}</td><td style="color:#444">${n.text}</td></tr>`).join('');
    const actionRows = m.actions.map(a => `<tr><td style="font-weight:700;white-space:nowrap;color:${col(a.color)}">${a.tag}</td><td style="color:#444">${a.text}</td></tr>`).join('');
    return `
<div style="page-break-after:always;border:1px solid #ddd;border-radius:10px;padding:28px 32px;margin-bottom:32px;font-family:Arial,sans-serif">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px">
    <div>
      <div style="font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#888;margin-bottom:4px">MANAGEMENT OVERVIEW</div>
      <div style="font-size:22px;font-weight:800;color:#111">${appName} <span style="font-weight:400;font-size:16px;color:#666">v${appVer}</span></div>
      <div style="font-size:12px;color:#666;margin-top:2px">Prepared by ${docOwner} · ${docDate}</div>
    </div>
    <div style="background:${col(m.statusColor)}18;border:1px solid ${col(m.statusColor)}44;border-radius:8px;padding:10px 16px;text-align:center">
      <div style="font-size:18px;font-weight:800;color:${col(m.statusColor)};font-family:monospace">${m.level}</div>
      <div style="font-size:10px;color:#666;font-weight:700;letter-spacing:.5px;text-transform:uppercase">Security Maturity</div>
    </div>
  </div>
  <div style="background:#f8f9fa;border-left:4px solid ${col(m.statusColor)};padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;color:#333;margin-bottom:20px">
    ${m.levelDesc} This architecture contains <strong>${m.criticals} critical</strong> and <strong>${m.highs} high</strong> severity threats.
    The average DREAD risk score is <strong>${m.avgDread}/10</strong>.
  </div>
  <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
    <tr>
      <td style="width:25%;padding:12px;background:#f1f5f9;border-radius:8px;text-align:center">
        <div style="font-size:28px;font-weight:800;color:#ef4444;font-family:monospace">${m.total}</div>
        <div style="font-size:11px;color:#666;text-transform:uppercase;font-weight:700">Total Threats</div>
      </td>
      <td style="width:4%"></td>
      <td style="width:25%;padding:12px;background:#f1f5f9;border-radius:8px;text-align:center">
        <div style="font-size:28px;font-weight:800;color:#ef4444;font-family:monospace">${m.criticals}</div>
        <div style="font-size:11px;color:#666;text-transform:uppercase;font-weight:700">Critical</div>
      </td>
      <td style="width:4%"></td>
      <td style="width:25%;padding:12px;background:#f1f5f9;border-radius:8px;text-align:center">
        <div style="font-size:28px;font-weight:800;color:#f59e0b;font-family:monospace">${m.avgDread}/10</div>
        <div style="font-size:11px;color:#666;text-transform:uppercase;font-weight:700">Avg DREAD Score</div>
      </td>
      <td style="width:4%"></td>
      <td style="width:25%;padding:12px;background:#f1f5f9;border-radius:8px;text-align:center">
        <div style="font-size:28px;font-weight:800;color:#16a34a;font-family:monospace">${m.detectConf}%</div>
        <div style="font-size:11px;color:#666;text-transform:uppercase;font-weight:700">Detection Confidence</div>
      </td>
    </tr>
  </table>
  <div style="margin-bottom:18px">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#888;margin-bottom:6px">Mitigation Progress — ${mitigPct}% of threats mitigated (${m.mitigated}/${m.total})</div>
    <div style="background:#e5e7eb;border-radius:6px;height:10px;overflow:hidden">
      <div style="height:100%;width:${mitigPct}%;background:${mitigPct > 80 ? '#16a34a' : mitigPct > 50 ? '#f59e0b' : '#ef4444'};border-radius:6px"></div>
    </div>
  </div>
  ${m.activeNarratives.length ? `
  <div style="margin-bottom:18px">
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#888;margin-bottom:8px">Business Risk by Threat Category</div>
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <thead><tr><th style="text-align:left;padding:6px 10px;background:#f1f5f9;border-radius:4px;font-size:10px;letter-spacing:.5px">CATEGORY</th><th style="text-align:left;padding:6px 10px;background:#f1f5f9;font-size:10px;letter-spacing:.5px">BUSINESS IMPACT</th></tr></thead>
      <tbody>${narrativeRows}</tbody>
    </table>
  </div>` : ''}
  <div>
    <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#888;margin-bottom:8px">Recommended Actions</div>
    <table style="width:100%;border-collapse:collapse;font-size:12px">
      <tbody>${actionRows}</tbody>
    </table>
  </div>
  <div style="margin-top:16px;font-size:10px;color:#999;border-top:1px solid #eee;padding-top:10px">
    ⚠ This summary is generated from a design-time threat model. Detection confidence is a theoretical estimate based on architecture configuration, not measured against live infrastructure. Validate findings with penetration testing before production deployment.
  </div>
</div>`;
  }

  const narrativeItems = m.activeNarratives.map(n => `
    <div class="exec-risk-item" style="border-left-color:${scolor(n.stride)}">
      <div class="exec-risk-cat" style="color:${scolor(n.stride)}">${n.name}</div>
      <div class="exec-risk-text">${n.text}</div>
    </div>`).join('');

  const actionItems = m.actions.map(a => `
    <div class="exec-action">
      <div class="exec-action-tag" style="background:${a.bg};color:${a.color}">${a.tag}</div>
      <div class="exec-action-text">${a.text}</div>
    </div>`).join('');

  const detectorChips = m.detectorNodes.length
    ? m.detectorNodes.map(n => `<span class="detect-node-chip" style="background:rgba(52,211,153,.12);color:var(--low);border:1px solid rgba(52,211,153,.3)">${n.label}</span>`).join('')
    : `<span class="detect-node-chip" style="background:rgba(239,68,68,.12);color:var(--crit);border:1px solid rgba(239,68,68,.3)">None detected</span>`;

  const barColor = mitigPct > 80 ? 'var(--low)' : mitigPct > 50 ? 'var(--accent)' : 'var(--crit)';

  return `
    <div class="exec-header">
      <div>
        <div class="exec-title">📋 Executive Security Summary</div>
        <div class="exec-subtitle">${appName} v${appVer} · ${docOwner} · ${docDate}</div>
      </div>
      <button class="exec-close" id="btnCloseExecSummary" title="Close">✕</button>
    </div>

    <!-- Maturity Band -->
    <div class="maturity-band" style="background:${m.statusColor}10;border-color:${m.statusColor}40">
      <div>
        <div class="maturity-level" style="color:${m.statusColor}">${m.level}</div>
        <div class="maturity-label" style="color:${m.statusColor}">Security Maturity</div>
      </div>
      <div class="maturity-desc">${m.levelDesc}</div>
    </div>

    <!-- KPI row -->
    <div class="exec-kpis">
      <div class="exec-kpi">
        <div class="exec-kpi-val" style="color:var(--crit)">${m.total}</div>
        <div class="exec-kpi-lbl">Total Threats</div>
      </div>
      <div class="exec-kpi">
        <div class="exec-kpi-val" style="color:var(--crit)">${m.criticals}</div>
        <div class="exec-kpi-lbl">Critical</div>
      </div>
      <div class="exec-kpi">
        <div class="exec-kpi-val" style="color:var(--accent)">${m.avgDread}/10</div>
        <div class="exec-kpi-lbl">Avg DREAD Score</div>
      </div>
      <div class="exec-kpi">
        <div class="exec-kpi-val" style="color:${m.detectConf > 60 ? 'var(--low)' : m.detectConf > 30 ? 'var(--med)' : 'var(--crit)'}">${m.detectConf}%</div>
        <div class="exec-kpi-lbl">Detection Confidence</div>
      </div>
    </div>

    <!-- Risk vs Mitigation progress -->
    <div class="exec-section">
      <div class="exec-section-title">Mitigation Progress — ${mitigPct}%</div>
      <div class="exec-progress-bar">
        <div class="exec-progress-fill" style="width:${mitigPct}%;background:${barColor}"></div>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text2);margin-top:6px;font-weight:700">
        <span>${m.mitigated} Mitigated</span>
        <span>${m.total - m.mitigated} Pending Response</span>
      </div>
    </div>

    <div style="display:flex;gap:16px">
      <!-- Left col: Business Risk -->
      <div style="flex:1">
        ${m.activeNarratives.length ? `
        <div class="exec-section">
          <div class="exec-section-title">Business Risk Profile</div>
          ${narrativeItems}
        </div>` : ''}
        <div class="exec-section">
          <div class="exec-section-title" style="display:flex;justify-content:space-between">
            <span>Security Controls Detected</span>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">
            ${detectorChips}
          </div>
        </div>
      </div>

      <!-- Right col: Actions -->
      <div style="flex:1">
        <div class="exec-section">
          <div class="exec-section-title">Recommended Actions</div>
          <div style="display:flex;flex-direction:column;gap:8px">
            ${actionItems}
          </div>
        </div>
      </div>
    </div>

    <div class="exec-ftr">
      <button class="btn btn-primary" id="btnExportExecReport">⬇ Export Report</button>
    </div>
  `;
}

export function generateMarkdownReport(metrics) {
  const S = getState();
  const appName = document.getElementById('appName')?.value || 'Unnamed Application';
  const appVer = document.getElementById('appVersion')?.value || '1.0';
  const docOwner = document.getElementById('docOwner')?.value || '—';
  const docDate = document.getElementById('docDate')?.value || new Date().toISOString().split('T')[0];

  let md = `# Threat Model Assessment: ${appName} (v${appVer})\n\n`;
  md += `**Owner:** ${docOwner} | **Date:** ${docDate} | **Maturity:** ${metrics.level}\n\n`;

  md += `## Executive Summary\n\n`;
  md += `${metrics.levelDesc} This architecture contains **${metrics.criticals} critical** and **${metrics.highs} high** severity threats. `;
  md += `The average DREAD risk score is **${metrics.avgDread}/10**.\n\n`;

  md += `## Identified Threats\n\n`;

  if (S.threats.length === 0) {
    md += `*No threats identified.*\n\n`;
  } else {
    md += `| ID | Threat | Severity | Status | Response |\n`;
    md += `|---|---|---|---|---|\n`;
    S.threats.forEach(t => {
      const cmRow = S.cmRows[t.id] || { status: 'Non-Mitigated', response: 'Mitigate' };
      md += `| **${t.id}** | ${t.name} | ${t.sev.toUpperCase()} | ${cmRow.status} | ${cmRow.response} |\n`;
    });
    md += `\n`;

    md += `## Threat Details & Mitigations\n\n`;
    S.threats.forEach(t => {
      const cmRow = S.cmRows[t.id] || { status: 'Non-Mitigated', response: 'Mitigate' };
      md += `### ${t.id}: ${t.name}\n`;
      md += `- **Severity**: ${t.sev.toUpperCase()}\n`;
      md += `- **Category**: ${t.cat} (${t.stride})\n`;
      md += `- **Status**: ${cmRow.status} (Response: ${cmRow.response})\n`;
      md += `- **Affected Components**: ${t.affected.join(', ')}\n\n`;
      md += `**Description**\n${t.desc}\n\n`;
      md += `**Recommended Mitigations**\n`;
      t.mits.forEach(m => md += `- [ ] ${m}\n`);
      md += `\n---\n\n`;
    });
  }

  return md;
}
