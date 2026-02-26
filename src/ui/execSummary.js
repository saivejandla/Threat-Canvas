/**
 * EXECUTIVE SUMMARY — Modal and metrics
 */
import { S } from '../state/state.js';
import { sc, sn, scolor, rr } from '../utils/helpers.js';

export function calculateMaturityMetrics() {
    const total = S.threats.length;
    const criticals = S.threats.filter(t => t.sev === 'critical').length;
    const highs = S.threats.filter(t => t.sev === 'high').length;
    const mitigated = Object.values(S.cmRows).filter(r => r.status === 'Mitigated').length;
    const partial = Object.values(S.cmRows).filter(r => r.status === 'Partial').length;
    const mitigPct = total > 0 ? mitigated / total : 0;
    const sevDread = { critical: 9, high: 7, medium: 5, low: 3 };
    const totalDread = S.threats.reduce((acc, t) => acc + (sevDread[t.sev] || 5), 0);
    const avgDread = total > 0 ? (totalDread / total).toFixed(1) : '—';
    const nodeTypes = Object.values(S.nodes).map(n => n.type);
    const detectors = ['siem', 'waf', 'firewall'].filter(t => nodeTypes.includes(t));
    const detProbs = { siem: 0.85, waf: 0.60, firewall: 0.45 };
    const detectConf = detectors.length ? Math.round((1 - detectors.reduce((p, t) => p * (1 - detProbs[t]), 1)) * 100) : 0;
    const detectorNodes = detectors.map(t => Object.values(S.nodes).find(n => n.type === t)).filter(Boolean);

    let level, statusColor, levelDesc;
    if (total === 0) { level = 'Not Assessed'; statusColor = 'var(--text3)'; levelDesc = 'No analysis has been run.'; }
    else if (criticals > 0) { level = 'Initial'; statusColor = 'var(--crit)'; levelDesc = 'Critical vulnerabilities require immediate remediation.'; }
    else if (mitigPct > 0.8) { level = 'Proactive'; statusColor = 'var(--low)'; levelDesc = 'Security posture exceeds baseline.'; }
    else if (mitigPct > 0.7) { level = 'Managed'; statusColor = 'var(--low)'; levelDesc = 'Risk well-understood and largely under control.'; }
    else if (criticals < 3) { level = 'Defined'; statusColor = 'var(--med)'; levelDesc = 'Threats identified but mitigation coverage needs improvement.'; }
    else { level = 'Initial'; statusColor = 'var(--crit)'; levelDesc = 'High number of unresolved critical risks.'; }

    const SN = { S: 'Potential identity assumption and credential theft.', T: 'Risk of data integrity violations.', R: 'Inability to attribute actions to users.', I: 'Risk of regulatory non-compliance and data exposure.', D: 'Service downtime, SLA breaches, revenue loss.', E: 'Attackers may gain admin control, enabling lateral movement.' };
    const activeNarratives = [...new Set(S.threats.map(t => t.stride))].filter(s => SN[s]).map(s => ({ stride: s, name: sn(s), text: SN[s] }));

    const actions = [];
    if (criticals > 0) actions.push({ tag: 'IMMEDIATE', color: 'var(--crit)', bg: 'rgba(239,68,68,.1)', text: `Remediate ${criticals} critical vulnerabilit${criticals === 1 ? 'y' : 'ies'}.` });
    if (!detectors.includes('waf') && !detectors.includes('firewall')) actions.push({ tag: 'HIGH PRIORITY', color: 'var(--high)', bg: 'rgba(249,115,22,.1)', text: 'No WAF or Firewall detected. Add perimeter controls.' });
    if (mitigated < total) actions.push({ tag: 'SHORT-TERM', color: 'var(--accent)', bg: 'rgba(245,158,11,.1)', text: `Complete countermeasure register for ${total - mitigated} pending threats.` });
    if (!detectors.includes('siem')) actions.push({ tag: 'ONGOING', color: 'var(--info)', bg: 'rgba(96,165,250,.1)', text: 'No SIEM detected. Implement centralized log aggregation.' });
    if (actions.length === 0) actions.push({ tag: 'MAINTAIN', color: 'var(--low)', bg: 'rgba(52,211,153,.1)', text: 'Security posture is strong. Schedule periodic reviews.' });

    return { total, criticals, highs, mitigated, partial, mitigPct, avgDread, detectConf, detectors, detectorNodes, level, statusColor, levelDesc, activeNarratives, actions };
}

function _exportHTML(m, appName, appVer, docOwner, docDate, mitigPct) {
    const colorMap = { 'var(--crit)': '#ef4444', 'var(--high)': '#f97316', 'var(--med)': '#facc15', 'var(--low)': '#34d399', 'var(--accent)': '#f59e0b', 'var(--info)': '#60a5fa', 'var(--text3)': '#3d5275' };
    const col = c => colorMap[c] || c;
    const nRows = m.activeNarratives.map(n => `<tr><td style="font-weight:700;color:${col(scolor(n.stride))}">${n.name}</td><td style="color:#444">${n.text}</td></tr>`).join('');
    const aRows = m.actions.map(a => `<tr><td style="font-weight:700;color:${col(a.color)}">${a.tag}</td><td style="color:#444">${a.text}</td></tr>`).join('');
    return `<div style="page-break-after:always;border:1px solid #ddd;border-radius:10px;padding:28px 32px;margin-bottom:32px;font-family:Arial,sans-serif">
  <div style="display:flex;justify-content:space-between;margin-bottom:20px"><div><div style="font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#888;margin-bottom:4px">MANAGEMENT OVERVIEW</div><div style="font-size:22px;font-weight:800;color:#111">${appName} <span style="font-weight:400;font-size:16px;color:#666">v${appVer}</span></div><div style="font-size:12px;color:#666;margin-top:2px">Prepared by ${docOwner} · ${docDate}</div></div>
  <div style="background:${col(m.statusColor)}18;border:1px solid ${col(m.statusColor)}44;border-radius:8px;padding:10px 16px;text-align:center"><div style="font-size:18px;font-weight:800;color:${col(m.statusColor)};font-family:monospace">${m.level}</div><div style="font-size:10px;color:#666;font-weight:700;letter-spacing:.5px;text-transform:uppercase">Security Maturity</div></div></div>
  <div style="background:#f8f9fa;border-left:4px solid ${col(m.statusColor)};padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;color:#333;margin-bottom:20px">${m.levelDesc} <strong>${m.criticals} critical</strong> and <strong>${m.highs} high</strong> severity threats. Avg DREAD: <strong>${m.avgDread}/10</strong>.</div>
  <div style="margin-bottom:18px"><div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#888;margin-bottom:6px">Mitigation — ${mitigPct}% (${m.mitigated}/${m.total})</div><div style="background:#e5e7eb;border-radius:6px;height:10px;overflow:hidden"><div style="height:100%;width:${mitigPct}%;background:${mitigPct > 80 ? '#16a34a' : mitigPct > 50 ? '#f59e0b' : '#ef4444'};border-radius:6px"></div></div></div>
  ${m.activeNarratives.length ? `<div style="margin-bottom:18px"><div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#888;margin-bottom:8px">Business Risk</div><table style="width:100%;border-collapse:collapse;font-size:12px"><tbody>${nRows}</tbody></table></div>` : ''}
  <div><div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#888;margin-bottom:8px">Recommended Actions</div><table style="width:100%;border-collapse:collapse;font-size:12px"><tbody>${aRows}</tbody></table></div>
  <div style="margin-top:16px;font-size:10px;color:#999;border-top:1px solid #eee;padding-top:10px">⚠ Design-time estimate. Validate with penetration testing.</div></div>`;
}

function _modalHTML(m, appName, appVer, docOwner, docDate, mitigPct) {
    const barColor = mitigPct > 80 ? 'var(--low)' : mitigPct > 50 ? 'var(--accent)' : 'var(--crit)';
    const ni = m.activeNarratives.map(n => `<div class="exec-risk-item" style="border-left-color:${scolor(n.stride)}"><div class="exec-risk-cat" style="color:${scolor(n.stride)}">${n.name}</div><div class="exec-risk-text">${n.text}</div></div>`).join('');
    const ai = m.actions.map(a => `<div class="exec-action"><div class="exec-action-tag" style="background:${a.bg};color:${a.color}">${a.tag}</div><div class="exec-action-text">${a.text}</div></div>`).join('');
    const dc = m.detectorNodes.length ? m.detectorNodes.map(n => `<span class="detect-node-chip" style="background:rgba(52,211,153,.12);color:var(--low);border:1px solid rgba(52,211,153,.3)">${n.label}</span>`).join('') : `<span class="detect-node-chip" style="background:rgba(239,68,68,.12);color:var(--crit);border:1px solid rgba(239,68,68,.3)">None detected</span>`;
    return `<div class="exec-header"><div><div class="exec-title">📋 Executive Security Summary</div><div class="exec-subtitle">${appName} v${appVer} · ${docOwner} · ${docDate}</div></div><button class="exec-close" id="execCloseBtn" title="Close">✕</button></div>
  <div class="maturity-band" style="background:${m.statusColor}10;border-color:${m.statusColor}40"><div><div class="maturity-level" style="color:${m.statusColor}">${m.level}</div><div class="maturity-label" style="color:${m.statusColor}">Security Maturity</div></div><div class="maturity-desc">${m.levelDesc}</div></div>
  <div class="exec-kpis"><div class="exec-kpi"><div class="exec-kpi-val" style="color:var(--crit)">${m.total}</div><div class="exec-kpi-lbl">Total Threats</div></div><div class="exec-kpi"><div class="exec-kpi-val" style="color:var(--crit)">${m.criticals}</div><div class="exec-kpi-lbl">Critical</div></div><div class="exec-kpi"><div class="exec-kpi-val" style="color:var(--accent)">${m.avgDread}/10</div><div class="exec-kpi-lbl">Avg DREAD</div></div><div class="exec-kpi"><div class="exec-kpi-val" style="color:${m.detectConf > 60 ? 'var(--low)' : 'var(--crit)'}">${m.detectConf}%</div><div class="exec-kpi-lbl">Detection</div></div></div>
  <div class="exec-section"><div class="exec-section-title">Risk vs. Mitigation</div><div class="exec-progress-label"><span>${m.mitigated} of ${m.total} mitigated</span><span style="color:${barColor}">${mitigPct}%</span></div><div class="exec-progress-wrap"><div class="exec-progress-bar" style="width:${mitigPct}%;background:${barColor}"></div></div></div>
  <div class="exec-section"><div class="exec-section-title">Risk Impact</div><div class="exec-narrative">This architecture contains <strong style="color:${m.statusColor}">${m.criticals} critical</strong> and <strong style="color:var(--high)">${m.highs} high</strong> severity vulnerabilities. Avg DREAD: <strong>${m.avgDread}/10</strong>. ${m.criticals > 0 ? 'Immediate remediation required.' : m.mitigPct > 0.8 ? 'Security posture is strong.' : 'Increase mitigation coverage.'}</div></div>
  ${m.activeNarratives.length ? `<div class="exec-section"><div class="exec-section-title">Business Risk</div>${ni}</div>` : ''}
  <div class="exec-section"><div class="exec-section-title">Detection Coverage</div><div class="exec-narrative"><div style="margin-bottom:6px">Detection confidence: <strong style="color:${m.detectConf > 60 ? 'var(--low)' : 'var(--crit)'}">${m.detectConf}%</strong> based on ${m.detectors.length ? m.detectors.join(', ').toUpperCase() : 'no detection'} nodes. ${m.detectConf < 60 ? 'Add SIEM/WAF/Firewall.' : ''}</div><div class="detect-nodes">${dc}</div></div></div>
  <div class="exec-section"><div class="exec-section-title">Action Plan</div>${ai}</div>
  <div class="exec-footer"><button class="btn btn-primary" style="flex:1" id="execExportBtn">⬇ Export Full Report</button><button class="btn btn-ghost" id="execCloseBtn2">Close</button></div>`;
}

export function buildExecSummaryHTML(m, forExport = false) {
    const appName = document.getElementById('appName').value || 'Unnamed Application';
    const appVer = document.getElementById('appVersion').value || '1.0';
    const docOwner = document.getElementById('docOwner').value || '—';
    const docDate = document.getElementById('docDate').value || new Date().toISOString().split('T')[0];
    const mitigPct = m.total > 0 ? Math.round(m.mitigPct * 100) : 0;
    return forExport ? _exportHTML(m, appName, appVer, docOwner, docDate, mitigPct) : _modalHTML(m, appName, appVer, docOwner, docDate, mitigPct);
}

export function openExecSummary() {
    if (!S.threats.length) { alert('Run analysis in Step 2 first.'); return; }
    const m = calculateMaturityMetrics();
    document.getElementById('execModalContent').innerHTML = buildExecSummaryHTML(m, false);
    document.getElementById('execModal').style.display = 'flex';
    document.getElementById('execCloseBtn')?.addEventListener('click', closeExecSummary);
    document.getElementById('execCloseBtn2')?.addEventListener('click', closeExecSummary);
}

export function closeExecSummary() { document.getElementById('execModal').style.display = 'none'; }
