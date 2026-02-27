# ThreatCanvas v5 — Dev Notes

> Internal development notes covering three planned changes.  
> Date: <!-- auto --> 2026-02-27

---

## Summary

| Item | Priority | Status |
|------|----------|--------|
| Architecture Templates | 🟢 High | Planned |
| Viewport Scroll Zoom Fix | 🔴 High | Bug |
| Remove Attack Simulation | 🟡 Medium | Planned |

---

## 1. Architecture Templates

Replace the **Attack Simulation** section in the right panel with a **Templates** menu offering 5 pre-built architectures. Goal: get users from blank canvas to meaningful threat model in under 10 seconds, with node types, trust zones, edge properties, and trust boundaries already correctly configured.

### Templates to include

| # | Name | Description |
|---|------|-------------|
| 1 | **AWS 3-Tier Web App** | ALB → EC2 web tier → RDS, with WAF, S3, CloudFront. Most common pattern. |
| 2 | **Serverless API** | API Gateway → Lambda → DynamoDB, Cognito for auth, CloudWatch as SIEM. |
| 3 | **Microservices** | Multiple APIs behind service mesh, shared Redis cache, message queue, separate DBs per service. |
| 4 | **E-commerce Checkout** | Internet → CDN → checkout API → payment processor → order DB, PCI data class on sensitive edges. |
| 5 | **Zero Trust Remote Access** | User → IdP → VPN/proxy → internal services. Identity-first perimeter model. |

### Each template should

- Ship with **pre-configured edge properties** — auth method, encryption, protocol, data class, trust boundaries — not just nodes
- Have **trust zones already set** correctly per layer
- **Run analysis automatically** on load so threats appear immediately
- Include a **short description** tooltip of what it represents
- Use **common real-world defaults** (not hardened best-practice) so meaningful threats fire — this teaches users something

### Accuracy note

Templates will be accurate at two levels:

- ✅ **Structural** — correct node types, trust zones, realistic topology
- ✅ **Default-state** — edges reflect what you get deploying without hardening
- ❌ **Cloud-provider-specific** — IAM policies, VPC security groups, S3 bucket-level controls are out of scope; the current rule engine cannot model these

A tooltip on each template should state this clearly rather than implying full accuracy.

### Implementation note

The existing `loadExample()` function is already one template (a library web app). Refactor it into the first template entry so all templates share the same code path. The right panel section currently labelled `⚔️ Attack Simulation` becomes `📐 Templates`.

---

## 2. Viewport Scroll Zoom Fix

Mouse wheel zoom (`Ctrl+wheel`) and trackpad pinch-to-zoom are not working correctly. The viewport transform applies but zoom does not centre on the cursor position, and on some systems the canvas does not respond at all.

### What is broken

**1. Stale bounding rect**  
The zoom pivot calculation calls `canvasWrap.getBoundingClientRect()` at event time, but if the panel has not fully laid out the returned rect can be stale or zero-sized, putting the pivot at the wrong position.

**2. Pan speed not scaled by zoom**  
Plain scroll (pan) and `Ctrl+scroll` (zoom) share the same wheel listener. The `ctrlKey` check is correct but the fallback pan delta is not divided by `vpZ` — so panning feels sluggish when zoomed in and too fast when zoomed out.

**3. Trackpad deltaMode mismatch**  
On trackpad, `wheel` events arrive with `deltaMode = DOM_DELTA_PIXEL` (value `0`) rather than `DOM_DELTA_LINE` (value `1`). Pixel deltas are ~10× larger than line deltas, so a single pinch gesture jumps multiple zoom steps at once.

### Fix approach

- **Normalise delta by `deltaMode`** — divide by `100` for `PIXEL` mode (`deltaMode === 0`), use as-is for `LINE` mode
- **Clamp zoom delta per event** to a maximum of one `ZOOM_STEPS` increment so a fast scroll cannot skip multiple levels
- **Read pivot from `e.clientX / e.clientY`** relative to `canvasWrap` at event time — do not cache `getBoundingClientRect`
- **Scale pan delta by `1 / vpZ`** so panning speed is consistent regardless of zoom level

---

## 3. Remove Attack Simulation

The attack simulation — **Traffic Sim**, **SQL Injection**, **DDoS Flood**, **Lateral Movement**, **Data Exfiltration** — should be removed entirely. It adds no analytical value and could mislead users about how attacks actually traverse an architecture.

### Why it is being removed

- The **traffic sim** picks random edges every 200ms and animates a dot along them. No attack logic whatsoever.
- The **attack buttons** find target edges by node type only — a SQL Injection "attack" lights up any edge touching an `api` or `database` node regardless of whether TLS 1.3, mTLS, a WAF, or any other control is in place.
- The **Blast Radius** already does what the sim pretends to do, but correctly — it runs BFS through the graph and checks 6 real factors: auth strength, TLS version, credential scope, network route, IAM privilege level, and detection probability. The attack sim checks zero of these.
- **Risk of confusion** — a user watching the animation may believe they are seeing something accurate about how an attack traverses their architecture. They are not.

### What to delete

| Code | Location |
|------|----------|
| `startSim()`, `stopSim()`, `toggleSim()` | JS functions |
| `spawnP()` | Particle animation function |
| `runAttack()` | Attack type dispatcher |
| `simBar` element | HTML — the bottom sim status bar |
| Attack buttons HTML | Right panel — SQL Injection, DDoS, Lateral, Exfil |
| `S.simRunning`, `S.simInt`, `S.pkt` | State object fields |

### What to keep

- ✅ **Blast Radius mode** — accurate, useful, keep entirely
- ✅ **Attack path detection** (`runFullAnalysis`, `detectAttackPaths`) — graph-traversal-based, keep entirely
- ✅ `spawnP()` could theoretically be repurposed to animate blast radius traversal in a future feature — but that is separate work, not the current sim

### What replaces it

The right panel space freed by removing the simulation section is taken by the **Templates** section (item 1 above).

---

*ThreatCanvas v5 · Internal Dev Notes · 2026-02-27*
