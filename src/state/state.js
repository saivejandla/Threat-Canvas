/**
 * STATE — Central singleton holding all mutable application state.
 * All modules import and mutate this shared object reference.
 */
export const S = {
    nodes: {},   // { [nodeId]: NodeObject }
    edges: [],   // EdgeObject[]
    sel: null, // currently selected node ID
    connecting: null, // port element being dragged
    pendConn: null, // { from: nodeId } — pending connection
    nextId: 1,    // auto-increment ID counter
    simRunning: false,
    simInt: null, // setInterval handle
    pkt: 0,    // packet counter
    trig: 0,    // attack trigger counter
    threats: [],   // ThreatObject[]
    cmRows: {},   // { [threatId]: { response, status } }
};

// ── App mode ──
export let appMode = 'analyze'; // 'analyze' | 'blast'
export function setAppMode(m) { appMode = m; }

export let blastSourceId = null;
export function setBlastSourceId(id) { blastSourceId = id; }

// ── STRIDE filter ──
export let strideFilter = null;
export function setStrideFilter(f) { strideFilter = f; }

// ── Blast state ──
export let _lastBlastDist = null;
export let _lastBlockedEdges = new Set();
export let _lastDetectScores = {};
export let _lastPrivEscNodes = new Set();

export function setBlastState(dist, blocked, detect, privEsc) {
    _lastBlastDist = dist;
    _lastBlockedEdges = blocked;
    _lastDetectScores = detect;
    _lastPrivEscNodes = privEsc;
}

export function resetBlastState() {
    _lastBlastDist = null;
    _lastBlockedEdges = new Set();
    _lastDetectScores = {};
    _lastPrivEscNodes = new Set();
}

// ── Drag type for palette drag-drop ──
export let dragType = null;
export function setDragType(t) { dragType = t; }

// ── Attack path UI state ──
export let S_attackPaths = [];
export let S_boundaryFindings = [];
export let S_pathFindings = [];
export let _highlightedPathIdx = -1;

export function setAttackPathState(paths, boundary, pathFindings) {
    S_attackPaths = paths;
    S_boundaryFindings = boundary;
    S_pathFindings = pathFindings;
}

export function setHighlightedPathIdx(idx) { _highlightedPathIdx = idx; }

// ── Row counts for scope tables ──
export const ROW_COUNTS = { deps: 0, entry: 0, exit: 0, assets: 0, trust: 0 };

// ── Threat-to-canvas hover linking ──
export let hoveredThreatId = null;
export function setHoveredThreatId(id) { hoveredThreatId = id; }
