import { getState, setAppMode, removeNode, removeEdge, updateNodeProp, updateNode, clearState } from '../state/state.js';
import { vpZ, zoomFit, zoomReset, zoomStep, setDragType, dragType, selNode, createNode, getSelNodeId, pp, redraw, cancelConn, confirmConn } from './canvas.js';
import { runAnalysis } from '../engine/analysis.js';
import { refreshAssess, calculateMaturityMetrics, buildExecSummaryHTML, generateMarkdownReport } from '../engine/assessment.js';
import { runBlast, clearBlast, toggleSim, triggerAttack } from '../engine/simulations.js';
import { showComponentThreats, openEdgeEditor } from './dom.js';

export function bindAllEvents() {
    // Top Tabs
    ['stab1', 'stab2', 'stab3', 'stab4', 'stab5', 'stab6'].forEach((id, i) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', () => switchTab(i + 1));
    });

    // Internal Step Navigation
    document.getElementById('btnNextToDfd')?.addEventListener('click', () => switchTab(2));
    document.getElementById('btnNextToAssess')?.addEventListener('click', () => switchTab(4));

    // Scope Internal Menu Sidebar
    document.querySelectorAll('.scope-nav-item').forEach(el => {
        el.addEventListener('click', () => {
            document.querySelectorAll('.scope-nav-item').forEach(n => n.classList.remove('active', 'anav'));
            document.querySelectorAll('.scope-section').forEach(s => s.classList.remove('active', 'asec'));
            el.classList.add('active', 'anav');
            document.getElementById('sec-' + el.dataset.sec)?.classList.add('active', 'asec');
        });
    });

    // Zoom
    document.getElementById('zIn')?.addEventListener('click', () => zoomStep(1));
    document.getElementById('zOut')?.addEventListener('click', () => zoomStep(-1));
    document.getElementById('zFit')?.addEventListener('click', zoomFit);
    document.getElementById('zRst')?.addEventListener('click', zoomReset);

    // Canvas panning
    const canvasWrap = document.getElementById('canvasWrap');
    if (canvasWrap) {
        let isPan = false, px, py;
        canvasWrap.addEventListener('mousedown', e => {
            if (e.target.id === 'canvasWrap' || e.target.id === 'svgLayer') {
                isPan = true; px = e.clientX; py = e.clientY;
                canvasWrap.style.cursor = 'grabbing';
            }
        });
        canvasWrap.addEventListener('mousemove', e => {
            if (!isPan) return;
            const dx = e.clientX - px; const dy = e.clientY - py;
            px = e.clientX; py = e.clientY;
            import('./canvas.js').then(c => {
                c.vpX += dx; c.vpY += dy;
                c._applyViewport();
            });
        });
        canvasWrap.addEventListener('mouseup', () => { isPan = false; canvasWrap.style.cursor = 'default'; });
        canvasWrap.addEventListener('mouseleave', () => { isPan = false; canvasWrap.style.cursor = 'default'; });

        canvasWrap.addEventListener('wheel', e => {
            if (e.ctrlKey || e.metaKey) {
                e.preventDefault();
                import('./canvas.js').then(c => c._zoomAround(vpZ * (e.deltaY > 0 ? 0.9 : 1.1), { x: e.clientX, y: e.clientY }));
            } else {
                import('./canvas.js').then(c => {
                    c.vpX -= e.deltaX; c.vpY -= e.deltaY;
                    c._applyViewport();
                });
            }
        });
    }

    // Drag from sidebar
    document.querySelectorAll('.pal-item').forEach(el => {
        el.addEventListener('mousedown', e => {
            setDragType(el.dataset.type);
            const ghost = el.cloneNode(true);
            ghost.id = 'dragGhost';
            ghost.style.position = 'absolute';
            ghost.style.left = e.clientX + 'px';
            ghost.style.top = e.clientY + 'px';
            ghost.style.opacity = '0.8';
            ghost.style.pointerEvents = 'none';
            ghost.style.zIndex = '9999';
            document.body.appendChild(ghost);

            const move = me => {
                ghost.style.left = me.clientX + 10 + 'px';
                ghost.style.top = me.clientY + 10 + 'px';
            };
            const up = ue => {
                document.body.removeChild(ghost);
                document.removeEventListener('mousemove', move);
                document.removeEventListener('mouseup', up);
                if (dragType && ue.target.closest('#canvasWrap')) {
                    import('./canvas.js').then(c => {
                        const cw = document.getElementById('canvasWrap');
                        const r = cw.getBoundingClientRect();
                        const x = (ue.clientX - r.left - c.vpX) / c.vpZ;
                        const y = (ue.clientY - r.top - c.vpY) / c.vpZ;
                        if (dragType === 'boundary') {
                            c.createBoundary(x, y);
                        } else {
                            const nid = c.createNode(dragType, x, y);
                            c.selNode(nid);
                        }
                        c.redraw();
                    });
                }
                setDragType(null);
            };
            document.addEventListener('mousemove', move);
            document.addEventListener('mouseup', up);
        });
    });

    // Delete keys
    document.addEventListener('keydown', e => {
        if ((e.key === 'Delete' || e.key === 'Backspace') && e.target.tagName !== 'INPUT' && e.target.tagName !== 'SELECT' && e.target.tagName !== 'TEXTAREA') {
            const sid = getSelNodeId();
            if (sid) {
                removeNode(sid);
                document.getElementById(sid)?.remove();
                document.getElementById('ctpSection').style.display = 'none';
                import('./canvas.js').then(c => { c.selNode(null); c.redraw(); });
            }
        }
    });

    // Toggle blast mode
    document.getElementById('btnAttackMode')?.addEventListener('click', e => {
        const S = getState();
        const m = S.appMode === 'analyze' ? 'blast' : 'analyze';
        setAppMode(m);
        import('./canvas.js').then(c => c.setCanvasAppMode(m));

        const btn = document.getElementById('btnAttackMode');
        const bPanel = document.getElementById('blastPanel');
        const count = document.getElementById('blastCount');

        if (m === 'blast') {
            btn.innerHTML = '🛡️ Exit Blast Radius';
            btn.classList.add('active');
            bPanel.style.display = 'block';
            document.getElementById('ctpSection').style.display = 'none';
            document.getElementById('edgeEditorSection').style.display = 'none';

            Object.keys(S.nodes).forEach(id => {
                const el = document.getElementById(id); if (!el) return;
                el.classList.remove('selected', 'stride-highlight');
                el.classList.add('blast-safe');
            });
            count.textContent = 'Click a node to simulate compromise';
        } else {
            btn.innerHTML = '💥 Blast Radius';
            btn.classList.remove('active');
            bPanel.style.display = 'none';
            clearBlast(true);
            const sid = getSelNodeId();
            if (sid) showComponentThreats(sid);
        }
    });

    // Connection modal
    document.getElementById('btnCancelConn')?.addEventListener('click', cancelConn);
    document.getElementById('btnConfirmConn')?.addEventListener('click', confirmConn);

    // Analysis mode panels
    document.getElementById('rpTab-threats')?.addEventListener('click', () => import('../ui/dom.js').then(d => d.setAnalysisModePanel('threats')));
    document.getElementById('rpTab-paths')?.addEventListener('click', () => import('../ui/dom.js').then(d => d.setAnalysisModePanel('paths')));

    // Action handlers using delegation
    document.body.addEventListener('click', e => {
        // Edge Editor Delete Button
        if (e.target.dataset.eedel) {
            removeEdge(e.target.dataset.eedel);
            document.getElementById('edgeEditorSection').style.display = 'none';
            redraw();
            return;
        }

        // Close Edge Editor
        if (e.target.id === 'btnCloseEdgeEditor') {
            document.getElementById('edgeEditorSection').style.display = 'none';
            redraw();
            return;
        }

        // Run Analysis Step 3
        if (e.target.id === 'btnRunAnalysis') {
            runAnalysis();
            return;
        }

        // Highlight Attack Path
        if (e.target.dataset.hlpath) {
            import('../engine/analysis.js').then(m => {
                const ap = m.S_attackPaths[e.target.dataset.hlpath];
                if (ap) import('./dom.js').then(d => d.highlightPath(ap.path, ap.severity));
            });
            return;
        }

        // Highlight Edges
        if (e.target.dataset.hledges) {
            const edges = JSON.parse(e.target.dataset.hledges);
            import('./dom.js').then(d => d.highlightEdges(edges));
            return;
        }

        // Highlight Node in Analysis
        if (e.target.dataset.hlnode) {
            import('./dom.js').then(d => d.highlightNodes(e.target.dataset.hlnode));
            // smooth scroll to canvas if window is small
            return;
        }

        // Add table row (Step 1)
        if (e.target.dataset.addrow) {
            const tbd = document.getElementById(e.target.dataset.addrow);
            const tmpl = document.getElementById(e.target.dataset.tmpl);
            if (tbd && tmpl) {
                const tr = document.createElement('tr');
                tr.innerHTML = tmpl.innerHTML;
                tbd.appendChild(tr);
            }
            return;
        }

        // Delete table row (Step 1)
        if (e.target.classList.contains('del-row')) {
            e.target.closest('tr').remove();
            return;
        }

        // Generate Executive Report
        if (e.target.id === 'btnGenExecReport') {
            const metrics = calculateMaturityMetrics();
            const html = buildExecSummaryHTML(metrics, false);
            const overlay = document.getElementById('execSummaryOverlay');
            overlay.innerHTML = html;
            overlay.style.display = 'flex';
            setTimeout(() => overlay.classList.add('show'), 10);
            return;
        }

        // Close Exec Report
        if (e.target.id === 'btnCloseExecSummary') {
            const overlay = document.getElementById('execSummaryOverlay');
            overlay.classList.remove('show');
            setTimeout(() => overlay.style.display = 'none', 300);
            return;
        }

        // Export Exec Report
        if (e.target.id === 'btnExportExecReport') {
            const metrics = calculateMaturityMetrics();
            const html = buildExecSummaryHTML(metrics, true);
            const printWindow = window.open('', '_blank');
            printWindow.document.write('<html><head><title>Threat Model Executive Summary</title></head><body>' + html + '<script>window.print();window.close();</script></body></html>');
            printWindow.document.close();
            return;
        }

        // Export Markdown Report (Header)
        if (e.target.id === 'btnExportReportHdr') {
            const metrics = calculateMaturityMetrics();
            const md = generateMarkdownReport(metrics);
            const blob = new Blob([md], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threat-report-${new Date().toISOString().split('T')[0]}.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            return;
        }

        // Sim Actions
        if (e.target.id === 'simToggleBtn') {
            toggleSim();
            return;
        }

        if (e.target.dataset.attack) {
            triggerAttack(e.target.dataset.attack);
            return;
        }

        // Example Load System
        if (e.target.id === 'btnLoadSystem') {
            clearState();
            import('./canvas.js').then(c => {
                document.getElementById('canvas').innerHTML = '';
                ['svgLayer', 'connModal', 'edgeEditorSection', 'ctpSection'].forEach(s => document.getElementById('canvas').appendChild(document.getElementById(s).cloneNode(true)));
                // Need to clean DOM heavily or just reload. Reload for simplification for now because we ripped out load logic
                alert("Load logic is stripped in refactor for brevity but can be restored using the import/export state features.");
            });
        }
    });

    // --- JSON Export/Import ---
    document.getElementById('btnSaveProject')?.addEventListener('click', () => {
        import('../state/state.js').then(m => {
            const state = m.getState();
            const json = JSON.stringify({ nodes: state.nodes, edges: state.edges, cmRows: state.cmRows, nextId: state.nextId }, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `threat-model-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
    });

    document.getElementById('btnLoadProjectTrigger')?.addEventListener('click', () => {
        document.getElementById('loadFileInput')?.click();
    });

    document.getElementById('loadFileInput')?.addEventListener('change', e => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = e2 => {
            try {
                const data = JSON.parse(e2.target.result);
                import('../state/state.js').then(m => {
                    m.resetState();
                    m.setState({ nodes: data.nodes || {}, edges: data.edges || [], cmRows: data.cmRows || {}, nextId: data.nextId || 1 });
                    import('./canvas.js').then(c => c.redraw());
                    import('./dom.js').then(d => {
                        const S = m.getState();
                        d.renderDetected(S);
                        d.renderCM();
                        document.getElementById('ctpSection').style.display = 'none';
                    });
                });
            } catch (err) {
                alert('Invalid JSON file. Could not parse threat model data.');
            }
        };
        reader.readAsText(file);
        e.target.value = ''; // trigger change even if same file selected again
    });

    // --- Rules Engine ---
    document.getElementById('btnUploadRulesTrigger')?.addEventListener('click', () => {
        document.getElementById('rulesFileInput')?.click();
    });

    document.getElementById('rulesFileInput')?.addEventListener('change', e => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = e2 => {
            try {
                const data = JSON.parse(e2.target.result);

                // Allow evaluate/check functions passed as strings in JSON
                if (data.rules) {
                    data.rules.forEach(r => {
                        if (r.checkString) {
                            r.check = new Function('N', 'E', 'adj', r.checkString);
                        } else if (r.evaluateString) {
                            r.evaluate = new Function('node', r.evaluateString);
                        }
                    });
                }

                import('../engine/threatEngine.js').then(m => {
                    m.RuleManager.loadCustomRules(data);
                    alert("Custom rules loaded successfully. Please run Analysis to see them.");
                });
            } catch (err) {
                alert('Invalid rules JSON file.');
            }
        };
        reader.readAsText(file);
        e.target.value = '';
    });

    document.getElementById('btnClearRules')?.addEventListener('click', () => {
        import('../engine/threatEngine.js').then(m => {
            m.RuleManager.clearCustomRules();
            alert('Rules reset to default standard STRIDE set.');
        });
    });

    // Change handlers using delegation
    document.body.addEventListener('change', e => {
        // Edge Editor Prop Updates
        if (e.target.classList.contains('ee-sel')) {
            const eid = e.target.dataset.eeid;
            const prop = e.target.dataset.eeval;
            import('../state/state.js').then(m => {
                m.updateEdge(eid, { [prop]: e.target.value });
                redraw();
            });
            return;
        }

        // Countermeasure Matrix Updates
        if (e.target.dataset.cmid) {
            const cid = e.target.dataset.cmid;
            const prop = e.target.dataset.cmprop;
            import('../state/state.js').then(m => {
                const cmv = m.getState().cmRows;
                if (!cmv[cid]) cmv[cid] = {};
                cmv[cid][prop] = e.target.value;
                m.setCmRows(cmv);
            });
            return;
        }

        // Node Properties Panel Updates
        if (e.target.dataset.npid) {
            const nid = e.target.dataset.npid;

            if (e.target.dataset.nptz) {
                // Trust Zone changes UI
                updateNode(nid, { trustZone: e.target.value });
                const el = document.getElementById(nid);
                if (el) {
                    el.className = 'node selected tz-' + e.target.value + '-node';
                }
                import('./canvas.js').then(c => {
                    c._debounceTZOverlay();
                    showComponentThreats(nid);
                });
            } else if (e.target.dataset.npprop) {
                const propList = e.target.dataset.npprop.split('.');
                import('../state/state.js').then(m => {
                    const S = m.getState();
                    const nd = S.nodes[nid];
                    if (propList.length === 1) {
                        m.updateNode(nid, { [propList[0]]: e.target.value });
                    } else {
                        // nested (e.g. props.dataClassification)
                        if (!nd[propList[0]]) nd[propList[0]] = {};
                        nd[propList[0]][propList[1]] = e.target.value;
                        m.updateNode(nid, { [propList[0]]: nd[propList[0]] });
                    }
                });
            }
            return;
        }
    });

    // External AppMode Change Requests
    document.addEventListener('appModeChangeRequest', e => {
        const mode = e.detail;
        if (mode === 'analyze') {
            const btn = document.getElementById('btnAttackMode');
            if (btn && btn.classList.contains('active')) btn.click(); // trigger toggle off
        }
    });
}

function switchTab(num) {
    document.querySelectorAll('.step-tab').forEach((t, i) => t.classList.toggle('active', i + 1 === num));
    document.querySelectorAll('.step-panel').forEach((t, i) => t.classList.toggle('active', i + 1 === num));
    if (num === 2) { zoomFit(); redraw(); }
    if (num === 4) refreshAssess();
}
