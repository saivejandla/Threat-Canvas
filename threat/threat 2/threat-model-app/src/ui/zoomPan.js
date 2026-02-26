/**
 * ZOOM & PAN ENGINE
 */
import { S } from '../state/state.js';
import { renderTrustZoneOverlays } from './trustZones.js';

export const ZOOM_STEPS = [0.5, 0.67, 0.8, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0];
export let vpZ = 1.0;
export let vpX = 0;
export let vpY = 0;

let _tzTimer = 0;
export function _debounceTZOverlay() { clearTimeout(_tzTimer); _tzTimer = setTimeout(renderTrustZoneOverlays, 60); }

export function _applyViewport() {
    const vp = document.getElementById('viewport');
    if (!vp) return;
    vp.style.transform = `translate(${vpX}px,${vpY}px) scale(${vpZ})`;
    document.getElementById('zoomPct').textContent = Math.round(vpZ * 100) + '%';
}

function _canvasMid() {
    const cw = document.getElementById('canvasWrap');
    if (!cw) return { x: 0, y: 0 };
    const r = cw.getBoundingClientRect();
    return { x: r.width / 2, y: r.height / 2 };
}

function _zoomAround(newZ, pivot) {
    vpX = pivot.x - (pivot.x - vpX) * (newZ / vpZ);
    vpY = pivot.y - (pivot.y - vpY) * (newZ / vpZ);
    vpZ = newZ;
    _applyViewport();
}

export function zoomStep(dir) {
    const idx = ZOOM_STEPS.findIndex(z => Math.abs(z - vpZ) < 0.01);
    const cur = idx < 0 ? 4 : idx;
    const next = Math.max(0, Math.min(ZOOM_STEPS.length - 1, cur + dir));
    _zoomAround(ZOOM_STEPS[next], _canvasMid());
}

export function zoomFit() {
    const nodes = Object.values(S.nodes);
    if (!nodes.length) return;
    const cw = document.getElementById('canvasWrap');
    const r = cw.getBoundingClientRect();
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    nodes.forEach(nd => {
        const el = document.getElementById(nd.id);
        const w = el && el.offsetWidth > 0 ? el.offsetWidth : 160;
        const h = el && el.offsetHeight > 0 ? el.offsetHeight : 75;
        minX = Math.min(minX, nd.x); minY = Math.min(minY, nd.y);
        maxX = Math.max(maxX, nd.x + w); maxY = Math.max(maxY, nd.y + h);
    });
    const PAD = 40;
    const scaleX = (r.width - PAD * 2) / (maxX - minX);
    const scaleY = (r.height - PAD * 2) / (maxY - minY);
    const z = Math.min(scaleX, scaleY, 2.0);
    const snapped = ZOOM_STEPS.reduce((a, b) => Math.abs(b - z) < Math.abs(a - z) ? b : a);
    vpZ = snapped;
    vpX = PAD - minX * vpZ + (r.width - PAD * 2 - (maxX - minX) * vpZ) / 2;
    vpY = PAD - minY * vpZ + (r.height - PAD * 2 - (maxY - minY) * vpZ) / 2;
    _applyViewport();
}

export function zoomReset() {
    vpZ = 1.0; vpX = 16; vpY = 16;
    _applyViewport();
}

/** Initialize wheel/pan/keyboard handlers — call on DOMContentLoaded */
export function initZoomPan() {
    const cw = document.getElementById('canvasWrap');
    if (!cw) return;

    cw.addEventListener('wheel', e => {
        e.preventDefault();
        if (e.ctrlKey || e.metaKey) {
            const delta = e.deltaY > 0 ? -1 : 1;
            const cwr = cw.getBoundingClientRect();
            const pivot = { x: e.clientX - cwr.left, y: e.clientY - cwr.top };
            const idx = ZOOM_STEPS.findIndex(z => Math.abs(z - vpZ) < 0.01);
            const cur = idx < 0 ? 4 : idx;
            const next = Math.max(0, Math.min(ZOOM_STEPS.length - 1, cur + delta));
            _zoomAround(ZOOM_STEPS[next], pivot);
        } else {
            vpX -= e.deltaX; vpY -= e.deltaY;
            _applyViewport();
        }
    }, { passive: false });

    // Middle-mouse pan
    let panActive = false, panSX = 0, panSY = 0, panOX = 0, panOY = 0;
    cw.addEventListener('mousedown', e => {
        if (e.button === 1) { e.preventDefault(); panActive = true; panSX = e.clientX; panSY = e.clientY; panOX = vpX; panOY = vpY; }
    });
    document.addEventListener('mousemove', e => {
        if (!panActive) return;
        vpX = panOX + (e.clientX - panSX); vpY = panOY + (e.clientY - panSY);
        _applyViewport();
    });
    document.addEventListener('mouseup', e => { if (e.button === 1) panActive = false; });

    // Keyboard shortcuts
    document.addEventListener('keydown', e => {
        if (e.ctrlKey || e.metaKey) {
            if (e.key === '=' || e.key === '+') { e.preventDefault(); zoomStep(+1); }
            if (e.key === '-') { e.preventDefault(); zoomStep(-1); }
            if (e.key === '0') { e.preventDefault(); zoomReset(); }
            if (e.key === 'f' || e.key === 'F') { e.preventDefault(); zoomFit(); }
        }
    });
}
