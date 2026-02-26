/**
 * MAIN.JS — Application entry point
 * Imports all modules and wires up event listeners on DOMContentLoaded.
 */
import { S } from './state/state.js';
import { goStep, showSec, addRow } from './ui/scopeUI.js';
import { createNode, clearCanvas, confirmConn, cancelConn, initCanvas } from './ui/canvasUI.js';
import { setMode } from './ui/panelUI.js';
import { runAnalysis } from './engine/threatEngine.js';
import { zoomStep, zoomFit, zoomReset, initZoomPan } from './ui/zoomPan.js';
import { toggleSim, runAttack } from './ui/simulationUI.js';
import { filterSTRIDE, switchRpTab } from './ui/assessUI.js';
import { exportReport, saveProject, loadProject, loadExample } from './ui/exportUI.js';
import { openExecSummary, closeExecSummary } from './ui/execSummary.js';
import { renderTrustZoneOverlays } from './ui/trustZones.js';
import { upHint } from './utils/helpers.js';
import { openRuleEditor, closeRuleEditor, initRuleEditor } from './ui/ruleEditorUI.js';

document.addEventListener('DOMContentLoaded', () => {
    // Init
    document.getElementById('docDate').value = new Date().toISOString().split('T')[0];
    setMode('analyze');
    initZoomPan();
    initCanvas();
    initRuleEditor();

    // ── Step Tabs ──
    document.querySelectorAll('.step-tab').forEach((tab, i) => {
        tab.addEventListener('click', () => goStep(i + 1));
    });

    // ── Scope navigation ──
    document.querySelectorAll('.scope-nav-item').forEach(el => {
        el.addEventListener('click', () => {
            const secId = el.dataset.sec;
            if (secId) showSec(secId, el);
        });
    });

    // ── Add Row buttons ──
    document.querySelectorAll('[data-add-row]').forEach(btn => {
        btn.addEventListener('click', () => addRow(btn.dataset.addRow));
    });

    // ── Mode toggle ──
    document.getElementById('modeAnalyze').addEventListener('click', () => setMode('analyze'));
    document.getElementById('modeBlast').addEventListener('click', () => setMode('blast'));

    // ── Run Analysis ──
    document.getElementById('analyzeBtn').addEventListener('click', runAnalysis);

    // ── Zoom controls ──
    document.getElementById('zoomInBtn').addEventListener('click', () => zoomStep(+1));
    document.getElementById('zoomOutBtn').addEventListener('click', () => zoomStep(-1));
    document.getElementById('zoomFitBtn').addEventListener('click', zoomFit);
    document.getElementById('zoomResetBtn').addEventListener('click', zoomReset);

    // ── Simulation ──
    document.getElementById('simToggleBtn').addEventListener('click', toggleSim);
    document.querySelectorAll('[data-attack]').forEach(btn => {
        btn.addEventListener('click', () => runAttack(btn.dataset.attack));
    });

    // ── Connection modal ──
    document.getElementById('connOk').addEventListener('click', confirmConn);
    document.getElementById('connCancel').addEventListener('click', cancelConn);

    // ── Right panel tabs ──
    document.getElementById('rpTab-threats').addEventListener('click', () => switchRpTab('threats'));
    document.getElementById('rpTab-paths').addEventListener('click', () => switchRpTab('paths'));

    // ── STRIDE filter ──
    document.querySelectorAll('.stride-card').forEach((card, i) => {
        const letters = ['S', 'T', 'R', 'I', 'D', 'E'];
        card.addEventListener('click', () => filterSTRIDE(letters[i]));
    });

    // ── Save / Load / Export ──
    document.querySelector('.btn-save')?.addEventListener('click', saveProject);
    document.getElementById('loadInput')?.addEventListener('change', function () { loadProject(this); });
    document.getElementById('loadBtn')?.addEventListener('click', () => document.getElementById('loadInput').click());
    document.getElementById('exportBtn')?.addEventListener('click', exportReport);
    document.getElementById('clearBtn')?.addEventListener('click', clearCanvas);
    document.getElementById('exampleBtn')?.addEventListener('click', loadExample);
    document.getElementById('exampleBtnHint')?.addEventListener('click', loadExample);

    // ── Rules Engine ──
    document.getElementById('openRulesBtn')?.addEventListener('click', openRuleEditor);
    document.getElementById('closeRulesBtn')?.addEventListener('click', closeRuleEditor);

    // ── Next: Build DFD ──
    document.getElementById('nextDfdBtn')?.addEventListener('click', () => goStep(2));

    // ── Clear highlights / blast ──
    document.getElementById('clearHighlightsBtn')?.addEventListener('click', () => {
        import('./engine/attackPaths.js').then(m => m.clearAttackPathHighlights());
    });
    document.getElementById('clearBlastBtn')?.addEventListener('click', () => {
        import('./engine/blastRadius.js').then(m => m.clearBlast());
    });

    // ── Assess page ──
    document.getElementById('refreshAssessBtn')?.addEventListener('click', () => {
        import('./ui/assessUI.js').then(m => m.refreshAssess());
    });
    document.getElementById('exportBtn2')?.addEventListener('click', exportReport);

    // ── Executive Summary ──
    document.getElementById('openExecBtn')?.addEventListener('click', openExecSummary);

    // ── Exec Modal ── delegate for dynamically created export button
    document.getElementById('execModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'execExportBtn') exportReport();
        if (e.target.id === 'execCloseBtn' || e.target.id === 'execCloseBtn2') closeExecSummary();
        if (e.target === document.getElementById('execModal')) closeExecSummary();
    });

    // ── Cloud Sync panel buttons (Step 5) ──
    document.querySelector('#panel5 .btn-primary.btn-sm')?.addEventListener('click', saveProject);
    document.querySelector('#panel5 input[type="file"]')?.addEventListener('change', function () { loadProject(this); });
    document.querySelector('#panel5 .btn-ghost.btn-sm[style]')?.addEventListener('click', exportReport);
});
