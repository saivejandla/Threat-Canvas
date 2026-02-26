/**
 * RULE EDITOR UI
 * Modal-based editor for creating, managing, importing/exporting custom rules.
 */
import {
    getCustomRules, addCustomRule, updateCustomRule, deleteCustomRule,
    toggleCustomRule, exportRulePack, importRulePack,
    RULE_PACKS, installRulePack, uninstallRulePack,
    loadCustomRulesFromStorage
} from '../engine/customRules.js';

const NODE_TYPES = [
    'internet', 'user', 'attacker', 'firewall', 'loadbalancer', 'vpn', 'cdn',
    'webserver', 'api', 'microservice', 'lambda', 'database', 'cache',
    'storage', 'messagequeue', 'waf', 'idp', 'siem'
];

const CONDITION_TYPES = [
    { value: 'missing-component', label: 'Missing Component — no node of type X exists' },
    { value: 'component-count-below', label: 'Component Count Below — fewer than N nodes of type X' },
    { value: 'node-missing-property', label: 'Node Missing Property — nodes of type X lack property Y' },
    { value: 'node-has-property', label: 'Node Has Bad Property — nodes of type X have property Y = bad value' },
    { value: 'edge-missing-property', label: 'Edge Missing Property — edges missing/bad property' },
    { value: 'edge-to-node-type', label: 'Edge to Node Type — edges to node type X with bad property' },
    { value: 'all-edges-check', label: 'All Edges Check — all edges matching criteria' },
    { value: 'path-unguarded', label: 'Unguarded Path — path from A to B without guard C' },
    { value: 'node-zone-mismatch', label: 'Zone Mismatch — node type in wrong zone' },
];

const STRIDE_OPTIONS = [
    { value: 'S', label: 'Spoofing' }, { value: 'T', label: 'Tampering' },
    { value: 'R', label: 'Repudiation' }, { value: 'I', label: 'Information Disclosure' },
    { value: 'D', label: 'Denial of Service' }, { value: 'E', label: 'Elevation of Privilege' },
];

const SEV_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'];
const LIKE_OPTIONS = ['High', 'Medium', 'Low'];

// ─── Open / Close Modal ───
export function openRuleEditor() {
    const modal = document.getElementById('ruleEditorModal');
    if (!modal) return;
    modal.style.display = 'flex';
    renderRuleList();
}

export function closeRuleEditor() {
    const modal = document.getElementById('ruleEditorModal');
    if (modal) modal.style.display = 'none';
}

// ─── Render Rule List ───
function renderRuleList() {
    const container = document.getElementById('ruleEditorContent');
    if (!container) return;

    const rules = getCustomRules();
    const installedPacks = new Set(rules.map(r => r.pack));

    let html = '';

    // ── Rule Packs section ──
    html += `<div class="re-section">
        <div class="re-section-title">📦 Rule Packs <span style="font-weight:400;color:var(--text2)">— pre-built domain-specific rules</span></div>
        <div class="re-pack-grid">`;

    for (const [key, pack] of Object.entries(RULE_PACKS)) {
        const installed = pack.rules.some(r => rules.find(cr => cr.id === r.id));
        html += `<div class="re-pack-card ${installed ? 're-pack-installed' : ''}">
            <div class="re-pack-label">${pack.label}</div>
            <div class="re-pack-count">${pack.rules.length} rules</div>
            <button class="btn btn-sm ${installed ? 're-pack-remove' : 'btn-primary'}"
                    data-pack="${key}" data-action="${installed ? 'uninstall' : 'install'}">
                ${installed ? '✕ Remove' : '+ Install'}
            </button>
        </div>`;
    }

    html += `</div></div>`;

    // ── Import / Export ──
    html += `<div class="re-section">
        <div class="re-section-title">📂 Import / Export</div>
        <div style="display:flex;gap:8px;margin-bottom:12px">
            <button class="btn btn-ghost btn-sm" id="reImportBtn">⬆ Import Rule Pack (.json)</button>
            <input type="file" id="reImportFile" accept=".json" style="display:none">
            <button class="btn btn-ghost btn-sm" id="reExportAllBtn">⬇ Export All Rules</button>
        </div>
    </div>`;

    // ── Custom Rules List ──
    html += `<div class="re-section">
        <div class="re-section-title">📝 Custom Rules <span style="font-weight:400;color:var(--text2)">— ${rules.length} total</span></div>
        <button class="btn btn-primary btn-sm" id="reAddRuleBtn" style="margin-bottom:10px">+ Create New Rule</button>`;

    if (rules.length === 0) {
        html += `<div style="text-align:center;color:var(--text3);padding:20px;font-size:12px">
            No custom rules yet. Create one or install a rule pack above.
        </div>`;
    } else {
        html += `<div class="re-rule-list">`;
        for (const rule of rules) {
            const sevColor = { critical: '#ef4444', high: '#f97316', medium: '#facc15', low: '#34d399', info: '#60a5fa' }[rule.sev] || '#60a5fa';
            html += `<div class="re-rule-item ${rule.enabled ? '' : 're-rule-disabled'}">
                <div class="re-rule-header">
                    <div class="re-rule-toggle" data-id="${rule.id}" title="${rule.enabled ? 'Disable' : 'Enable'}">
                        ${rule.enabled ? '🟢' : '🔴'}
                    </div>
                    <div style="flex:1">
                        <div class="re-rule-name">${_esc(rule.name)}</div>
                        <div class="re-rule-meta">
                            <span class="re-rule-id">${_esc(rule.id)}</span>
                            <span class="re-rule-stride" style="border-color:${sevColor};color:${sevColor}">${rule.stride}</span>
                            <span class="re-rule-sev" style="color:${sevColor}">${rule.sev}</span>
                            ${rule.pack ? `<span class="re-rule-pack">${_esc(rule.pack)}</span>` : ''}
                        </div>
                    </div>
                    <div style="display:flex;gap:4px">
                        <button class="re-action-btn" data-id="${rule.id}" data-action="edit" title="Edit">✏️</button>
                        <button class="re-action-btn" data-id="${rule.id}" data-action="duplicate" title="Duplicate">📋</button>
                        <button class="re-action-btn re-action-del" data-id="${rule.id}" data-action="delete" title="Delete">🗑</button>
                    </div>
                </div>
                <div class="re-rule-desc">${_esc(rule.desc || '')}</div>
            </div>`;
        }
        html += `</div>`;
    }

    html += `</div>`;
    container.innerHTML = html;

    // ── Wire up events ──
    container.querySelectorAll('[data-action="install"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const res = installRulePack(btn.dataset.pack);
            if (res.success) renderRuleList();
        });
    });
    container.querySelectorAll('[data-action="uninstall"]').forEach(btn => {
        btn.addEventListener('click', () => {
            uninstallRulePack(btn.dataset.pack);
            renderRuleList();
        });
    });
    container.querySelectorAll('.re-rule-toggle').forEach(el => {
        el.addEventListener('click', () => { toggleCustomRule(el.dataset.id); renderRuleList(); });
    });
    container.querySelectorAll('[data-action="edit"]').forEach(btn => {
        btn.addEventListener('click', () => openRuleForm(btn.dataset.id));
    });
    container.querySelectorAll('[data-action="duplicate"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const rule = getCustomRules().find(r => r.id === btn.dataset.id);
            if (rule) {
                const dup = { ...rule, id: '', name: rule.name + ' (copy)', pack: 'custom' };
                addCustomRule(dup);
                renderRuleList();
            }
        });
    });
    container.querySelectorAll('[data-action="delete"]').forEach(btn => {
        btn.addEventListener('click', () => {
            if (confirm(`Delete rule "${btn.dataset.id}"?`)) {
                deleteCustomRule(btn.dataset.id);
                renderRuleList();
            }
        });
    });
    document.getElementById('reAddRuleBtn')?.addEventListener('click', () => openRuleForm(null));
    document.getElementById('reImportBtn')?.addEventListener('click', () => document.getElementById('reImportFile')?.click());
    document.getElementById('reImportFile')?.addEventListener('change', function () {
        const file = this.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            const res = importRulePack(reader.result);
            if (res.success) {
                alert(`Imported ${res.count} rules from pack "${res.packName}"`);
                renderRuleList();
            } else {
                alert('Import failed: ' + res.error);
            }
        };
        reader.readAsText(file);
        this.value = '';
    });
    document.getElementById('reExportAllBtn')?.addEventListener('click', () => exportRulePack(null));
}

// ─── Rule Form (create / edit) ───
function openRuleForm(ruleId) {
    const existing = ruleId ? getCustomRules().find(r => r.id === ruleId) : null;
    const container = document.getElementById('ruleEditorContent');
    if (!container) return;

    const r = existing || {
        id: '', name: '', stride: 'S', sev: 'high', like: 'Medium', imp: 'Medium',
        cat: 'Spoofing', ctrl: 'Authentication', desc: '', mits: [''],
        pack: 'custom', enabled: true,
        condition: { type: 'missing-component', nodeType: 'waf' }
    };

    let html = `<div class="re-form">
        <div class="re-form-title">${existing ? 'Edit Rule' : 'Create New Rule'}</div>

        <div class="re-form-row">
            <div class="re-form-fg"><label class="re-lbl">Rule Name *</label>
                <input class="inp" id="rf-name" value="${_esc(r.name)}" placeholder="e.g. Lambda must use VPC"></div>
            <div class="re-form-fg"><label class="re-lbl">Pack / Category</label>
                <input class="inp" id="rf-pack" value="${_esc(r.pack || 'custom')}" placeholder="e.g. healthcare"></div>
        </div>

        <div class="re-form-row">
            <div class="re-form-fg"><label class="re-lbl">STRIDE *</label>
                <select class="inp" id="rf-stride">${STRIDE_OPTIONS.map(o => `<option value="${o.value}" ${r.stride === o.value ? 'selected' : ''}>${o.value} — ${o.label}</option>`).join('')}</select></div>
            <div class="re-form-fg"><label class="re-lbl">Severity *</label>
                <select class="inp" id="rf-sev">${SEV_OPTIONS.map(s => `<option ${r.sev === s ? 'selected' : ''}>${s}</option>`).join('')}</select></div>
        </div>

        <div class="re-form-row">
            <div class="re-form-fg"><label class="re-lbl">Likelihood</label>
                <select class="inp" id="rf-like">${LIKE_OPTIONS.map(l => `<option ${r.like === l ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
            <div class="re-form-fg"><label class="re-lbl">Impact</label>
                <select class="inp" id="rf-imp">${LIKE_OPTIONS.map(l => `<option ${r.imp === l ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
        </div>

        <div class="re-form-fg"><label class="re-lbl">Description</label>
            <textarea class="inp" id="rf-desc" rows="2" placeholder="Detailed description of the threat...">${_esc(r.desc)}</textarea></div>

        <div class="re-form-fg"><label class="re-lbl">Mitigations (one per line)</label>
            <textarea class="inp" id="rf-mits" rows="3" placeholder="One mitigation per line...">${(r.mits || []).join('\n')}</textarea></div>

        <hr style="border:none;border-top:1px solid var(--border);margin:14px 0">
        <div class="re-form-title" style="font-size:12px;margin-bottom:10px">⚙ Condition (when should this rule fire?)</div>

        <div class="re-form-fg"><label class="re-lbl">Condition Type *</label>
            <select class="inp" id="rf-condType">
                ${CONDITION_TYPES.map(ct => `<option value="${ct.value}" ${r.condition?.type === ct.value ? 'selected' : ''}>${ct.label}</option>`).join('')}
            </select></div>

        <div id="rf-condParams">${_renderConditionParams(r.condition)}</div>

        <div class="re-form-actions">
            <button class="btn btn-ghost" id="rf-cancel">Cancel</button>
            <button class="btn btn-primary" id="rf-save">${existing ? 'Save Changes' : 'Create Rule'}</button>
        </div>
    </div>`;

    container.innerHTML = html;

    // Dynamic condition params
    document.getElementById('rf-condType')?.addEventListener('change', function () {
        const params = document.getElementById('rf-condParams');
        if (params) params.innerHTML = _renderConditionParams({ type: this.value });
    });

    // Cancel
    document.getElementById('rf-cancel')?.addEventListener('click', () => renderRuleList());

    // Save
    document.getElementById('rf-save')?.addEventListener('click', () => {
        const name = document.getElementById('rf-name')?.value?.trim();
        if (!name) { alert('Rule name is required'); return; }

        const stride = document.getElementById('rf-stride')?.value;
        const condType = document.getElementById('rf-condType')?.value;
        const condition = _buildConditionFromForm(condType);

        const catMap = { S: 'Spoofing', T: 'Tampering', R: 'Repudiation', I: 'Information Disclosure', D: 'Denial of Service', E: 'Elevation of Privilege' };
        const ctrlMap = { S: 'Authentication', T: 'Integrity', R: 'Non-Repudiation', I: 'Confidentiality', D: 'Availability', E: 'Authorization' };

        const rule = {
            name,
            stride,
            sev: document.getElementById('rf-sev')?.value || 'high',
            like: document.getElementById('rf-like')?.value || 'Medium',
            imp: document.getElementById('rf-imp')?.value || 'Medium',
            cat: catMap[stride] || 'Spoofing',
            ctrl: ctrlMap[stride] || 'Authentication',
            desc: document.getElementById('rf-desc')?.value?.trim() || '',
            mits: (document.getElementById('rf-mits')?.value || '').split('\n').map(s => s.trim()).filter(Boolean),
            pack: document.getElementById('rf-pack')?.value?.trim() || 'custom',
            condition
        };

        if (existing) {
            updateCustomRule(existing.id, rule);
        } else {
            addCustomRule(rule);
        }
        renderRuleList();
    });
}

// ─── Render condition-specific parameter fields ───
function _renderConditionParams(cond) {
    const c = cond || {};
    const typeOpts = NODE_TYPES.map(t => `<option value="${t}" ${c.nodeType === t ? 'selected' : ''}>${t}</option>`).join('');

    switch (c.type) {
        case 'missing-component':
            return `<div class="re-form-fg"><label class="re-lbl">Node Type that must exist</label>
                <select class="inp" id="rf-cp-nodeType">${typeOpts}</select></div>`;

        case 'component-count-below':
            return `<div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">Node Type</label>
                    <select class="inp" id="rf-cp-nodeType">${typeOpts}</select></div>
                <div class="re-form-fg"><label class="re-lbl">Minimum Count</label>
                    <input class="inp" type="number" id="rf-cp-threshold" value="${c.threshold || 1}" min="1"></div>
            </div>`;

        case 'node-missing-property':
        case 'node-has-property':
            return `<div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">Node Type(s)</label>
                    <select class="inp" id="rf-cp-nodeType" multiple style="height:60px">${typeOpts}</select></div>
                <div class="re-form-fg"><label class="re-lbl">Property Key</label>
                    <input class="inp" id="rf-cp-propKey" value="${_esc(c.propKey || '')}" placeholder="e.g. vpc, encryption, auth"></div>
            </div>
            <div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">Expected Value</label>
                    <input class="inp" id="rf-cp-propValue" value="${c.propValue !== undefined ? c.propValue : ''}" placeholder="e.g. true, admin"></div>
                <div class="re-form-fg"><label class="re-lbl">Default if Missing</label>
                    <input class="inp" id="rf-cp-propDefault" value="${c.propDefault !== undefined ? c.propDefault : ''}" placeholder="e.g. false"></div>
            </div>`;

        case 'edge-missing-property':
            return `<div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">Edge Property Key</label>
                    <input class="inp" id="rf-cp-propKey" value="${_esc(c.propKey || '')}" placeholder="e.g. encryption, auth"></div>
                <div class="re-form-fg"><label class="re-lbl">Bad Values (comma-separated)</label>
                    <input class="inp" id="rf-cp-badValues" value="${(c.badValues || ['None']).join(', ')}" placeholder="e.g. None, HTTP"></div>
            </div>
            <div class="re-form-fg"><label class="re-lbl">Only for Data Classes (comma-separated, leave empty for all)</label>
                <input class="inp" id="rf-cp-dataClassFilter" value="${(c.dataClassFilter || []).join(', ')}" placeholder="e.g. PHI, PCI, PII"></div>`;

        case 'edge-to-node-type':
            return `<div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">Target Node Type</label>
                    <select class="inp" id="rf-cp-targetNodeType">${typeOpts.replace(`value="${c.targetNodeType}"`, `value="${c.targetNodeType}" selected`)}</select></div>
                <div class="re-form-fg"><label class="re-lbl">Edge Property Key</label>
                    <input class="inp" id="rf-cp-propKey" value="${_esc(c.propKey || '')}" placeholder="e.g. auth"></div>
            </div>
            <div class="re-form-fg"><label class="re-lbl">Bad Values (comma-separated)</label>
                <input class="inp" id="rf-cp-badValues" value="${(c.badValues || ['None']).join(', ')}" placeholder="e.g. None"></div>`;

        case 'all-edges-check':
            return `<div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">From Node Type (optional)</label>
                    <select class="inp" id="rf-cp-fromNodeType"><option value="">Any</option>${typeOpts.replace(`value="${c.fromNodeType}"`, `value="${c.fromNodeType}" selected`)}</select></div>
                <div class="re-form-fg"><label class="re-lbl">To Node Type (optional)</label>
                    <select class="inp" id="rf-cp-toNodeType"><option value="">Any</option>${typeOpts.replace(`value="${c.toNodeType}"`, `value="${c.toNodeType}" selected`)}</select></div>
            </div>
            <div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">Edge Property Key</label>
                    <input class="inp" id="rf-cp-propKey" value="${_esc(c.propKey || '')}" placeholder="e.g. auth, encryption"></div>
                <div class="re-form-fg"><label class="re-lbl">Bad Values (comma-separated)</label>
                    <input class="inp" id="rf-cp-badValues" value="${(c.badValues || ['None']).join(', ')}" placeholder="e.g. None"></div>
            </div>`;

        case 'path-unguarded':
            return `<div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">Source Types (comma-separated)</label>
                    <input class="inp" id="rf-cp-srcType" value="${(Array.isArray(c.srcType) ? c.srcType : [c.srcType]).filter(Boolean).join(', ')}" placeholder="e.g. internet, user, attacker"></div>
                <div class="re-form-fg"><label class="re-lbl">Destination Types (comma-separated)</label>
                    <input class="inp" id="rf-cp-dstType" value="${(Array.isArray(c.dstType) ? c.dstType : [c.dstType]).filter(Boolean).join(', ')}" placeholder="e.g. database, storage"></div>
            </div>
            <div class="re-form-fg"><label class="re-lbl">Guard Types (comma-separated, must be on path)</label>
                <input class="inp" id="rf-cp-guardType" value="${(Array.isArray(c.guardType) ? c.guardType : [c.guardType]).filter(Boolean).join(', ')}" placeholder="e.g. waf, firewall"></div>`;

        case 'node-zone-mismatch':
            return `<div class="re-form-row">
                <div class="re-form-fg"><label class="re-lbl">Node Type</label>
                    <select class="inp" id="rf-cp-nodeType">${typeOpts}</select></div>
                <div class="re-form-fg"><label class="re-lbl">Expected Zones (comma-separated)</label>
                    <input class="inp" id="rf-cp-expectedZones" value="${(c.expectedZones || []).join(', ')}" placeholder="e.g. isolated, restricted"></div>
            </div>`;

        default:
            return `<div class="re-form-fg"><label class="re-lbl">Node Type</label>
                <select class="inp" id="rf-cp-nodeType">${typeOpts}</select></div>`;
    }
}

// ─── Build condition object from form ───
function _buildConditionFromForm(type) {
    const getVal = id => document.getElementById(id)?.value?.trim() || '';
    const splitCSV = id => getVal(id).split(',').map(s => s.trim()).filter(Boolean);
    const parseBool = v => v === 'true' ? true : v === 'false' ? false : v;

    const cond = { type };

    switch (type) {
        case 'missing-component':
            cond.nodeType = getVal('rf-cp-nodeType');
            break;
        case 'component-count-below':
            cond.nodeType = getVal('rf-cp-nodeType');
            cond.threshold = parseInt(getVal('rf-cp-threshold')) || 1;
            break;
        case 'node-missing-property': {
            const sel = document.getElementById('rf-cp-nodeType');
            const selected = sel ? [...sel.selectedOptions].map(o => o.value) : [];
            cond.nodeType = selected.length === 1 ? selected[0] : selected[0];
            cond.propKey = getVal('rf-cp-propKey');
            cond.propValue = parseBool(getVal('rf-cp-propValue'));
            cond.propDefault = parseBool(getVal('rf-cp-propDefault'));
            break;
        }
        case 'node-has-property': {
            const sel = document.getElementById('rf-cp-nodeType');
            const selected = sel ? [...sel.selectedOptions].map(o => o.value) : [];
            cond.nodeTypes = selected;
            cond.propKey = getVal('rf-cp-propKey');
            cond.propValue = parseBool(getVal('rf-cp-propValue'));
            break;
        }
        case 'edge-missing-property':
            cond.propKey = getVal('rf-cp-propKey');
            cond.badValues = splitCSV('rf-cp-badValues');
            cond.dataClassFilter = splitCSV('rf-cp-dataClassFilter');
            if (!cond.dataClassFilter.length) delete cond.dataClassFilter;
            break;
        case 'edge-to-node-type':
            cond.targetNodeType = getVal('rf-cp-targetNodeType');
            cond.propKey = getVal('rf-cp-propKey');
            cond.badValues = splitCSV('rf-cp-badValues');
            break;
        case 'all-edges-check':
            cond.propKey = getVal('rf-cp-propKey');
            cond.badValues = splitCSV('rf-cp-badValues');
            cond.fromNodeType = getVal('rf-cp-fromNodeType') || undefined;
            cond.toNodeType = getVal('rf-cp-toNodeType') || undefined;
            break;
        case 'path-unguarded':
            cond.srcType = splitCSV('rf-cp-srcType');
            cond.dstType = splitCSV('rf-cp-dstType');
            cond.guardType = splitCSV('rf-cp-guardType');
            break;
        case 'node-zone-mismatch':
            cond.nodeType = getVal('rf-cp-nodeType');
            cond.expectedZones = splitCSV('rf-cp-expectedZones');
            break;
    }
    return cond;
}

function _esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

// ─── Init ───
export function initRuleEditor() {
    loadCustomRulesFromStorage();

    // Close on overlay click
    const modal = document.getElementById('ruleEditorModal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeRuleEditor();
        });
    }
}
