import { getState } from './state/state.js';
import { bindAllEvents } from './ui/events.js';
import { renderDetected, renderCM } from './ui/dom.js';
import { RuleManager } from './engine/threatEngine.js';
import { runAnalysis } from './engine/analysis.js';

// Initialize Everything 
document.addEventListener('DOMContentLoaded', () => {
    // Top Tabs Set
    document.querySelectorAll('.tab')[0]?.classList.add('active');
    document.querySelectorAll('.tab-cont')[0]?.classList.add('active');

    // Setup initial DOM pieces based on initial empty state or persisted state
    import('./state/state.js').then(m => {
        if (m.loadFromLocal()) {
            import('./ui/canvas.js').then(c => c.redraw());
        }
        const S = m.getState();
        renderDetected(S);
        renderCM();
    });

    // Bind UI interactions
    bindAllEvents();

    // Temporarily expose to window for testing custom rule injection
    window.RuleManager = RuleManager;
    window.runAnalysis = runAnalysis;
});
