let S = {
    nodes: {},       // Component dictionary: { id: { x, y, type, label, trust, ... } }
    edges: [],       // Array of connections: { id, from, to, protocol, auth, ... }
    boundaries: [],  // Array of trust boundaries: { id, x, y, w, h, name }
    threats: [],     // Detected threats array
    cmRows: {},      // Countermeasure row state: { threatId: { response, status } }
    nextId: 1,       // Auto-increment edge IDs
    simRunning: false, // Flag for traffic sim animation
    pkt: 0,          // Packet counter
    simInt: null,    // Traffic sim setInterval ID
    trig: 0          // Triggered attack count
};

// --- Getters ---
export const getState = () => S;
export const getNodes = () => S.nodes;
export const getEdges = () => S.edges;
export const getBoundaries = () => S.boundaries;
export const getThreats = () => S.threats;
export const getCmRows = () => S.cmRows;
export const getNextId = () => S.nextId++;
export const isSimRunning = () => S.simRunning;

// --- Persistence ---
export const saveToLocal = () => {
    try {
        const data = { nodes: S.nodes, edges: S.edges, boundaries: S.boundaries, cmRows: S.cmRows, nextId: S.nextId };
        localStorage.setItem('threatModelerState', JSON.stringify(data));
    } catch (e) {
        console.warn("Failed to save state to localStorage", e);
    }
};

export const loadFromLocal = () => {
    try {
        const raw = localStorage.getItem('threatModelerState');
        if (raw) {
            const data = JSON.parse(raw);
            S.nodes = data.nodes || {};
            S.edges = data.edges || [];
            S.boundaries = data.boundaries || [];
            S.cmRows = data.cmRows || {};
            S.nextId = data.nextId || 1;
            return true;
        }
    } catch (e) {
        console.warn("Failed to load state from localStorage", e);
    }
    return false;
};

// --- Setters / Mutators ---
export const setState = (newState) => {
    S = { ...S, ...newState };
    saveToLocal();
};

export const setNodes = (nodes) => { S.nodes = nodes; saveToLocal(); };
export const setEdges = (edges) => { S.edges = edges; saveToLocal(); };
export const setBoundaries = (boundaries) => { S.boundaries = boundaries; saveToLocal(); };
export const setThreats = (threats) => { S.threats = threats; }; // derived state, no save needed
export const setCmRows = (cmRows) => { S.cmRows = cmRows; saveToLocal(); };

export const addNode = (id, nodeData) => {
    S.nodes[id] = nodeData;
    saveToLocal();
};

export const updateNode = (id, updates) => {
    if (S.nodes[id]) {
        S.nodes[id] = { ...S.nodes[id], ...updates };
        saveToLocal();
    }
};

export const removeNode = (id) => {
    delete S.nodes[id];
    // Remove edges connected to this node
    S.edges = S.edges.filter(e => e.from !== id && e.to !== id);
    saveToLocal();
};

export const addEdge = (edgeData) => {
    S.edges.push(edgeData);
    saveToLocal();
};

export const updateEdge = (id, updates) => {
    const edge = S.edges.find(e => e.id === id);
    if (edge) {
        Object.assign(edge, updates);
        saveToLocal();
    }
};

export const removeEdge = (id) => {
    S.edges = S.edges.filter(e => e.id !== id);
    saveToLocal();
};

export const addBoundary = (boundaryData) => {
    S.boundaries.push(boundaryData);
    saveToLocal();
};

export const updateBoundary = (id, updates) => {
    const b = S.boundaries.find(x => x.id === id);
    if (b) {
        Object.assign(b, updates);
        saveToLocal();
    }
};

export const removeBoundary = (id) => {
    S.boundaries = S.boundaries.filter(b => b.id !== id);
    saveToLocal();
};

export const updateCmRow = (id, field, value) => {
    if (!S.cmRows[id]) {
        S.cmRows[id] = { response: 'Mitigate', status: 'Non-Mitigated' };
    }
    S.cmRows[id][field] = value;
    saveToLocal();
};

export const setSimState = (running, packetCount, intervalId, triggerCount) => {
    if (running !== undefined) S.simRunning = running;
    if (packetCount !== undefined) S.pkt = packetCount;
    if (intervalId !== undefined) S.simInt = intervalId;
    if (triggerCount !== undefined) S.trig = triggerCount;
};

export const resetState = () => {
    S.nodes = {};
    S.edges = [];
    S.boundaries = [];
    S.threats = [];
    S.cmRows = {};
    S.nextId = 1;
    saveToLocal();
};
