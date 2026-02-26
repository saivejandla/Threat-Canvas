/**
 * TRUST ZONE OVERLAYS — swim lane rendering on the DFD canvas
 */
import { S } from '../state/state.js';

export function renderTrustZoneOverlays() {
    document.querySelectorAll('.trust-zone-overlay').forEach(el => el.remove());
    const canvas = document.getElementById('canvas');
    if (!canvas || !Object.keys(S.nodes).length) return;

    const TZ = {
        internet: { cls: 'tz-internet', lbl: 'tz-label-internet', name: '🌐 INTERNET' },
        dmz: { cls: 'tz-dmz', lbl: 'tz-label-dmz', name: '🔶 DMZ' },
        internal: { cls: 'tz-internal', lbl: 'tz-label-internal', name: '🔵 INTERNAL' },
        restricted: { cls: 'tz-secure', lbl: 'tz-label-secure', name: '🔒 RESTRICTED' },
    };

    const LANE_PAD_X = 18, LANE_PAD_TOP = 36, LANE_PAD_BOT = 20;

    const groups = { internet: [], dmz: [], internal: [], restricted: [] };
    Object.values(S.nodes).forEach(nd => {
        const tz = nd.trustZone || 'internal';
        if (groups[tz]) groups[tz].push(nd);
    });

    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            document.querySelectorAll('.trust-zone-overlay').forEach(el => el.remove());

            const zoneBox = {};
            let gY0 = Infinity, gY1 = -Infinity;

            Object.entries(groups).forEach(([tz, nds]) => {
                if (!nds.length) return;
                let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
                nds.forEach(nd => {
                    const el = document.getElementById(nd.id);
                    const w = el && el.offsetWidth > 30 ? el.offsetWidth : 180;
                    const h = el && el.offsetHeight > 30 ? el.offsetHeight : 90;
                    x0 = Math.min(x0, nd.x); y0 = Math.min(y0, nd.y);
                    x1 = Math.max(x1, nd.x + w); y1 = Math.max(y1, nd.y + h);
                });
                zoneBox[tz] = { x0, x1, y0, y1 };
                gY0 = Math.min(gY0, y0); gY1 = Math.max(gY1, y1);
            });

            if (gY0 === Infinity) return;

            const laneTop = gY0 - LANE_PAD_TOP;
            const laneHeight = gY1 - gY0 + LANE_PAD_TOP + LANE_PAD_BOT;

            Object.entries(TZ).forEach(([tz, cfg]) => {
                const bx = zoneBox[tz];
                if (!bx) return;

                const div = document.createElement('div');
                div.className = 'trust-zone-overlay ' + cfg.cls;
                div.setAttribute('data-tz', tz);
                div.style.cssText =
                    `left:${bx.x0 - LANE_PAD_X}px;` +
                    `top:${laneTop}px;` +
                    `width:${bx.x1 - bx.x0 + LANE_PAD_X * 2}px;` +
                    `height:${laneHeight}px;`;

                const lbl = document.createElement('div');
                lbl.className = 'tz-label ' + cfg.lbl;
                lbl.textContent = cfg.name;
                div.appendChild(lbl);

                canvas.insertBefore(div, canvas.firstChild);
            });
        });
    });
}
