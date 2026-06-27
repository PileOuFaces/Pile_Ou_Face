/**
 * elk.bundled.js — Pure-JS implementation of ELK (Eclipse Layout Kernel) Sugiyama pipeline.
 *
 * Implements the full ELK graph layout API:
 *   new ELK().layout(graph) → Promise<layoutedGraph>
 *   new ELK({ sync: true }).layout(graph) → layoutedGraph   (sync shortcut)
 *
 * ELK graph format (input):
 *   {
 *     id: string,
 *     layoutOptions?: { ... },
 *     children: [{ id, width, height, layoutOptions? }, ...],
 *     edges: [{ id, sources: [nodeId], targets: [nodeId], layoutOptions? }, ...],
 *   }
 *
 * ELK graph format (output — same object, mutated):
 *   Each child gets { x, y } added.
 *   Each edge gets { sections: [{ startPoint, bendPoints, endPoint }] } added.
 *
 * Supported layoutOptions (ELK standard keys):
 *   'elk.algorithm'                  : 'layered' (default, only supported value)
 *   'elk.direction'                  : 'DOWN' (default) | 'RIGHT'
 *   'elk.layered.spacing.nodeNodeBetweenLayers' : number (vertical gap, default 40)
 *   'elk.spacing.nodeNode'           : number (horizontal gap, default 30)
 *   'elk.edgeRouting'                : 'ORTHOGONAL' (default) | 'POLYLINE'
 *   'elk.padding'                    : '[top=N,left=N,bottom=N,right=N]' (default 20 all sides)
 *
 * Algorithm pipeline (Sugiyama 1981):
 *   1. Cycle removal  — reverse back-edges (DFS)
 *   2. Layer assignment — longest-path layering (topological)
 *   3. Virtual node insertion — dummy nodes for long edges
 *   4. Crossing minimization — barycenter sweeps (4 passes)
 *   5. Node positioning — barycenter X coords + Brandes-Köpf inspired placement
 *   6. Edge routing — orthogonal segments with bend points
 *   7. Coordinate normalization + padding
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ELK = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function () {

  // ─── Utility ─────────────────────────────────────────────────────────────────

  function parseOpt(opts, key, defaultValue) {
    if (!opts) return defaultValue;
    const v = opts[key];
    if (v === undefined || v === null) return defaultValue;
    if (typeof defaultValue === 'number') {
      const n = parseFloat(v);
      return isNaN(n) ? defaultValue : n;
    }
    return String(v);
  }

  function parsePadding(str, def) {
    const r = { top: def, right: def, bottom: def, left: def };
    if (typeof str !== 'string') return r;
    const re = /(top|right|bottom|left)\s*=\s*([0-9.]+)/g;
    let m;
    while ((m = re.exec(str)) !== null) r[m[1]] = parseFloat(m[2]);
    return r;
  }

  // ─── Step 1: Cycle removal (DFS) ─────────────────────────────────────────────

  function removeCycles(nodes, edges) {
    const nodeSet = new Set(nodes.map(n => n.id));
    const adj = {};
    for (const e of edges) {
      const s = e.sources[0];
      if (!adj[s]) adj[s] = [];
      adj[s].push(e);
    }
    const WHITE = 0, GRAY = 1, BLACK = 2;
    const color = {};
    for (const n of nodes) color[n.id] = WHITE;
    const reversed = new Set();

    function dfs(u) {
      color[u] = GRAY;
      for (const e of (adj[u] || [])) {
        const v = e.targets[0];
        if (!nodeSet.has(v)) continue;
        if (color[v] === GRAY) {
          reversed.add(e.id);
        } else if (color[v] === WHITE) {
          dfs(v);
        }
      }
      color[u] = BLACK;
    }
    for (const n of nodes) {
      if (color[n.id] === WHITE) dfs(n.id);
    }
    return reversed;
  }

  // ─── Step 2: Longest-path layer assignment ───────────────────────────────────

  function assignLayers(nodes, edges, reversedEdgeIds) {
    const ids = nodes.map(n => n.id);
    const nodeSet = new Set(ids);
    const succ = {}; const pred = {};
    for (const id of ids) { succ[id] = []; pred[id] = []; }

    for (const e of edges) {
      const s = reversedEdgeIds.has(e.id) ? e.targets[0] : e.sources[0];
      const t = reversedEdgeIds.has(e.id) ? e.sources[0] : e.targets[0];
      if (!nodeSet.has(s) || !nodeSet.has(t) || s === t) continue;
      succ[s].push(t);
      pred[t].push(s);
    }

    // Kahn topological sort
    const inDeg = {};
    for (const id of ids) inDeg[id] = pred[id].length;
    const queue = ids.filter(id => inDeg[id] === 0);
    const topo = [];
    const seen = new Set(queue);
    while (queue.length) {
      const u = queue.shift();
      topo.push(u);
      for (const v of (succ[u] || [])) {
        inDeg[v]--;
        if (inDeg[v] <= 0 && !seen.has(v)) {
          seen.add(v);
          queue.push(v);
        }
      }
    }
    // append any cycle-remaining nodes
    for (const id of ids) {
      if (!seen.has(id)) topo.push(id);
    }

    // Longest path
    const layer = {};
    for (const id of ids) layer[id] = 0;
    for (const u of topo) {
      for (const v of (succ[u] || [])) {
        if ((layer[v] || 0) < layer[u] + 1) layer[v] = layer[u] + 1;
      }
    }
    return { layer, succ, pred };
  }

  // ─── Step 3: Virtual node (dummy) insertion ──────────────────────────────────

  let _dummySeq = 0;
  function insertDummies(nodes, edges, layer, reversedEdgeIds) {
    const extra = []; const extraE = []; const toRemove = new Set();
    for (const e of edges) {
      const s = reversedEdgeIds.has(e.id) ? e.targets[0] : e.sources[0];
      const t = reversedEdgeIds.has(e.id) ? e.sources[0] : e.targets[0];
      const lS = layer[s]; const lT = layer[t];
      if (lT === undefined || lS === undefined) continue;
      const span = lT - lS;
      if (span <= 1) continue;
      toRemove.add(e.id);
      let prev = s;
      for (let l = lS + 1; l < lT; l++) {
        const dId = `__d${_dummySeq++}`;
        extra.push({ id: dId, width: 0, height: 0, _isDummy: true, _origEdge: e.id });
        layer[dId] = l;
        extraE.push({ id: `__de${_dummySeq++}`, sources: [prev], targets: [dId], _isDummy: true, _origEdge: e.id, _type: e._type });
        prev = dId;
      }
      extraE.push({ id: `__de${_dummySeq++}`, sources: [prev], targets: [t], _isDummy: true, _origEdge: e.id, _type: e._type });
    }
    return {
      allNodes: [...nodes, ...extra],
      allEdges: [...edges.filter(e => !toRemove.has(e.id)), ...extraE],
    };
  }

  // ─── Step 4: Crossing minimization (barycenter sweeps) ───────────────────────

  function crossingMin(allNodes, allEdges, layer) {
    // Group by layer
    const byLayer = {};
    for (const n of allNodes) {
      const l = layer[n.id];
      if (l === undefined) continue;
      if (!byLayer[l]) byLayer[l] = [];
      byLayer[l].push(n.id);
    }
    const sortedLayers = Object.keys(byLayer).map(Number).sort((a, b) => a - b);

    // Initial order: sort by id
    for (const l of sortedLayers) {
      byLayer[l].sort((a, b) => String(a).localeCompare(String(b)));
    }
    const pos = {};
    for (const l of sortedLayers) byLayer[l].forEach((id, i) => { pos[id] = i; });

    // Build weighted parent/child adjacency
    const parents = {}; const children = {};
    for (const n of allNodes) { parents[n.id] = []; children[n.id] = []; }
    for (const e of allEdges) {
      const s = e.sources[0]; const t = e.targets[0];
      const lS = layer[s]; const lT = layer[t];
      if (lS === undefined || lT === undefined || lS >= lT) continue;
      const w = e._type === 'fallthrough' ? 5 : e._type === 'call' ? 0.5 : 1;
      if (!children[s]) children[s] = [];
      if (!parents[t]) parents[t] = [];
      children[s].push({ id: t, w });
      parents[t].push({ id: s, w });
    }

    function bary(id, usePar) {
      const list = usePar ? parents[id] : children[id];
      if (!list || !list.length) return pos[id] !== undefined ? pos[id] : 0;
      let sum = 0, tot = 0;
      for (const { id: nb, w } of list) {
        const p = pos[nb];
        sum += (p !== undefined ? p : 0) * w;
        tot += w;
      }
      return tot ? sum / tot : 0;
    }

    for (let pass = 0; pass < 4; pass++) {
      // Top-down
      for (let li = 1; li < sortedLayers.length; li++) {
        const l = sortedLayers[li];
        const ordered = byLayer[l].map(id => ({ id, b: bary(id, true) }));
        ordered.sort((a, b) => a.b - b.b || String(a.id).localeCompare(String(b.id)));
        byLayer[l] = ordered.map(o => o.id);
        byLayer[l].forEach((id, i) => { pos[id] = i; });
      }
      // Bottom-up
      for (let li = sortedLayers.length - 2; li >= 0; li--) {
        const l = sortedLayers[li];
        const ordered = byLayer[l].map(id => ({ id, b: bary(id, false) }));
        ordered.sort((a, b) => a.b - b.b || String(a.id).localeCompare(String(b.id)));
        byLayer[l] = ordered.map(o => o.id);
        byLayer[l].forEach((id, i) => { pos[id] = i; });
      }
    }
    return { byLayer, sortedLayers, pos };
  }

  // ─── Step 5: Node X positioning ──────────────────────────────────────────────
  //
  // Strategy (4 passes + spine alignment):
  //
  //   Pass 1 (top-down):   place each node at the weighted average of its parents' centres.
  //   Pass 2 (bottom-up):  adjust parents to sit centred above their children.
  //   Pass 3 (top-down):   repeat to propagate bottom-up adjustments forward.
  //   Average passes 1+3 for a balanced result.
  //   Gap pass:            enforce minimum hSpacing between every pair of nodes in a layer.
  //   Spine pass:          snap fallthrough chains (single-parent, single-child) to be
  //                        perfectly vertical — only when the target has ONE parent.
  //
  // Key invariant: a node with multiple parents (join node like the exit of an if/else)
  // ALWAYS gets placed at the barycenter of those parents, never snapped to one of them.

  function assignXCoords(byLayer, sortedLayers, allNodes, allEdges, layer, widths, hSpacing) {
    // ── Build weighted parent / child adjacency ──────────────────────────────
    const parentsOf  = {};
    const childrenOf = {};
    for (const n of allNodes) { parentsOf[n.id] = []; childrenOf[n.id] = []; }
    for (const e of allEdges) {
      const s = e.sources[0]; const t = e.targets[0];
      const lS = layer[s]; const lT = layer[t];
      if (lS === undefined || lT === undefined || lS >= lT) continue;
      // Higher weight for structural flow edges so the spine dominates layout
      const w = e._type === 'fallthrough' ? 8 : e._type === 'call' ? 0.5 : 2;
      parentsOf[t].push({ id: s, w });
      childrenOf[s].push({ id: t, w });
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    // Half-width of a node (for centre-based arithmetic)
    const hw = id => (widths[id] || 0) / 2;

    // Weighted centre of parents/children for node `id` given a coordinate map `lx`
    function parentCentre(id, lx) {
      const pars = parentsOf[id];
      if (!pars.length) return null;
      let sum = 0, tot = 0;
      for (const { id: pid, w } of pars) {
        const px = lx[pid];
        if (px === undefined) continue;
        sum += (px + hw(pid)) * w;
        tot += w;
      }
      return tot ? sum / tot - hw(id) : null;
    }

    function childCentre(id, lx) {
      const kids = childrenOf[id];
      if (!kids.length) return null;
      let sum = 0, tot = 0;
      for (const { id: cid, w } of kids) {
        const cx = lx[cid];
        if (cx === undefined) continue;
        sum += (cx + hw(cid)) * w;
        tot += w;
      }
      return tot ? sum / tot - hw(id) : null;
    }

    // Place a layer left-to-right enforcing hSpacing, starting from ideal positions.
    // Returns the placed x-coordinates for that layer in `lx`.
    function placeLayer(l, lx, idealFn) {
      const ids = byLayer[l] || [];
      if (!ids.length) return;

      // Compute ideal x for each node
      const ideals = ids.map(id => ({ id, ix: idealFn(id, lx) }));

      // Forward sweep: enforce minimum gap left-to-right
      let cursor = 0;
      for (const item of ideals) {
        const ix = item.ix !== null && item.ix !== undefined ? item.ix : cursor;
        const x  = Math.max(ix, cursor);
        lx[item.id] = x;
        cursor = x + (widths[item.id] || 0) + hSpacing;
      }

      // Compute how much we had to push nodes right relative to their ideals
      let drift = 0; let driftCount = 0;
      for (const item of ideals) {
        if (item.ix !== null && item.ix !== undefined) {
          drift += lx[item.id] - item.ix;
          driftCount++;
        }
      }
      // Shift everything left by the average drift so the group stays centred
      if (driftCount > 0) {
        const shift = drift / driftCount;
        for (const item of ideals) lx[item.id] -= shift;
        // Re-enforce gap after shift
        let cur2 = 0;
        for (const item of ideals) {
          if (lx[item.id] < cur2) lx[item.id] = cur2;
          cur2 = lx[item.id] + (widths[item.id] || 0) + hSpacing;
        }
      }
    }

    // ── Pass 1: top-down — place children under parents ──────────────────────
    const lx1 = {};
    for (const l of sortedLayers) placeLayer(l, lx1, parentCentre);

    // ── Pass 2: bottom-up — pull parents above children ──────────────────────
    const lx2 = {};
    for (const id of Object.keys(lx1)) lx2[id] = lx1[id];
    for (let li = sortedLayers.length - 1; li >= 0; li--) {
      const l = sortedLayers[li];
      const ids = byLayer[l] || [];
      for (const id of ids) {
        const cc = childCentre(id, lx2);
        if (cc !== null) lx2[id] = cc;
      }
      // Re-enforce gap bottom-to-top
      let cur = 0;
      for (const id of ids) {
        if (lx2[id] < cur) lx2[id] = cur;
        cur = lx2[id] + (widths[id] || 0) + hSpacing;
      }
    }

    // ── Pass 3: top-down again — propagate bottom-up adjustments ─────────────
    const lx3 = {};
    for (const id of Object.keys(lx2)) lx3[id] = lx2[id];
    for (const l of sortedLayers) placeLayer(l, lx3, parentCentre);

    // ── Average passes 1 and 3 ────────────────────────────────────────────────
    const xCoords = {};
    for (const n of allNodes) {
      xCoords[n.id] = ((lx1[n.id] || 0) + (lx3[n.id] || 0)) / 2;
    }

    // ── Shift all x-coords so the minimum is 0 ───────────────────────────────
    const minX = Math.min(...Object.values(xCoords));
    if (isFinite(minX) && minX < 0) {
      for (const id of Object.keys(xCoords)) xCoords[id] -= minX;
    }

    // ── Final gap enforcement ─────────────────────────────────────────────────
    for (const l of sortedLayers) {
      const ids = byLayer[l] || [];
      let cur = 0;
      for (const id of ids) {
        if (xCoords[id] < cur) xCoords[id] = cur;
        cur = xCoords[id] + (widths[id] || 0) + hSpacing;
      }
    }

    // ── Spine alignment pass ──────────────────────────────────────────────────
    // Snap v directly below u when:
    //   - u has exactly one fallthrough child (v)
    //   - v has exactly one parent (u)      ← join nodes are EXCLUDED
    // This guarantees the main fallthrough spine is perfectly vertical
    // without disturbing the barycenter of join nodes (which have multiple parents).
    const fallthroughEdges = allEdges.filter(e => e._type === 'fallthrough');
    for (const e of fallthroughEdges) {
      const u = e.sources[0]; const v = e.targets[0];
      if (layer[u] === undefined || layer[v] === undefined) continue;

      // u must have exactly one fallthrough child
      const uFtKids = fallthroughEdges.filter(fe => fe.sources[0] === u);
      if (uFtKids.length !== 1) continue;

      // v must have exactly one parent total (not a join node)
      if ((parentsOf[v] || []).length !== 1) continue;

      // Snap v.x to u.x
      const delta = xCoords[u] - xCoords[v];
      if (Math.abs(delta) < 0.5) continue;
      xCoords[v] += delta;

      // Re-enforce gap in v's layer after snap
      const layerV = [...(byLayer[layer[v]] || [])].sort((a, b) => xCoords[a] - xCoords[b]);
      let cur = -Infinity;
      for (const id of layerV) {
        if (xCoords[id] < cur) xCoords[id] = cur;
        cur = xCoords[id] + (widths[id] || 0) + hSpacing;
      }
    }

    return xCoords;
  }

  // ─── Step 6: Orthogonal edge routing ─────────────────────────────────────────

  function routeEdges(edges, allNodes, layer, xCoords, yCoords, widths, heights, reversedEdgeIds) {
    // Map dummy chain per original edge
    const chains = {};
    for (const n of allNodes) {
      if (n._isDummy && n._origEdge) {
        if (!chains[n._origEdge]) chains[n._origEdge] = [];
        chains[n._origEdge].push(n.id);
      }
    }
    for (const eid of Object.keys(chains)) {
      chains[eid].sort((a, b) => (layer[a] || 0) - (layer[b] || 0));
    }

    const sections = {};
    for (const e of edges) {
      if (e._isDummy) continue;
      const isRev = reversedEdgeIds.has(e.id);
      const src = isRev ? e.targets[0] : e.sources[0];
      const tgt = isRev ? e.sources[0] : e.targets[0];

      const sx = xCoords[src]; const sy = yCoords[src];
      const tx = xCoords[tgt]; const ty = yCoords[tgt];
      if (sx === undefined || tx === undefined) continue;

      const sw = widths[src] || 0; const sh = heights[src] || 0;
      const tw = widths[tgt] || 0;

      const chain = chains[e.id] || [];

      // Build waypoints through dummy nodes
      const waypoints = [src, ...chain, tgt];
      const segStarts = [];
      for (let i = 0; i < waypoints.length - 1; i++) {
        const a = waypoints[i]; const b = waypoints[i + 1];
        const ax = xCoords[a] || 0; const ay = yCoords[a] || 0;
        const aw = widths[a] || 0; const ah = heights[a] || 0;
        const bx = xCoords[b] || 0; const by2 = yCoords[b] || 0;
        const bw = widths[b] || 0;
        segStarts.push({
          start: { x: ax + aw / 2, y: ay + ah },
          end:   { x: bx + bw / 2, y: by2 },
        });
      }

      // Orthogonal bends: for each segment, add a horizontal bend at midY
      const allBends = [];
      for (let i = 0; i < segStarts.length; i++) {
        const { start, end } = segStarts[i];
        if (i > 0) allBends.push(start); // junction between segments
        const midY = start.y + (end.y - start.y) / 2;
        if (Math.abs(start.x - end.x) > 1) {
          allBends.push({ x: start.x, y: midY });
          allBends.push({ x: end.x,   y: midY });
        }
      }

      sections[e.id] = [{
        id: `${e.id}_s0`,
        startPoint: segStarts[0].start,
        endPoint:   segStarts[segStarts.length - 1].end,
        bendPoints: allBends,
      }];
    }
    return sections;
  }

  // ─── Main layout orchestrator ─────────────────────────────────────────────────

  function doLayout(graph) {
    const opts = graph.layoutOptions || {};
    const direction = parseOpt(opts, 'elk.direction', 'DOWN').toUpperCase();
    const hSpacing = parseOpt(opts, 'elk.spacing.nodeNode', 30);
    const vSpacing = parseOpt(opts, 'elk.layered.spacing.nodeNodeBetweenLayers', 40);
    const pad = parsePadding(opts['elk.padding'], 20);

    const nodes = (graph.children || []).filter(n => n && n.id);
    const edges = (graph.edges || []).filter(e => e && e.sources && e.targets && e.sources[0] && e.targets[0]);

    if (nodes.length === 0) {
      graph.width = pad.left + pad.right;
      graph.height = pad.top + pad.bottom;
      return graph;
    }

    // Annotate edge types
    for (const e of edges) {
      e._type = (e.layoutOptions && e.layoutOptions['elk.edge.type']) || 'jmp';
    }

    // 1. Cycle removal
    const reversedEdgeIds = removeCycles(nodes, edges);

    // 2. Layer assignment
    const { layer } = assignLayers(nodes, edges, reversedEdgeIds);

    // 3. Dummy insertion
    const { allNodes, allEdges } = insertDummies(nodes, edges, layer, reversedEdgeIds);

    // 4. Crossing minimisation
    const { byLayer, sortedLayers } = crossingMin(allNodes, allEdges, layer);

    // Build widths/heights maps
    const widths = {}; const heights = {};
    for (const n of allNodes) {
      widths[n.id] = n.width || 0;
      heights[n.id] = n.height || 0;
    }

    // 5a. X coords
    const xCoords = assignXCoords(byLayer, sortedLayers, allNodes, allEdges, layer, widths, hSpacing);

    // 5b. Y coords: per-layer, cumulative based on max node height in each layer
    const layerMaxH = {};
    for (const l of sortedLayers) {
      layerMaxH[l] = 0;
      for (const id of byLayer[l]) {
        if (heights[id] > layerMaxH[l]) layerMaxH[l] = heights[id];
      }
    }
    const layerTopY = {};
    let curY = pad.top;
    for (const l of sortedLayers) {
      layerTopY[l] = curY;
      curY += layerMaxH[l] + vSpacing;
    }
    const yCoords = {};
    for (const n of allNodes) {
      yCoords[n.id] = layerTopY[layer[n.id]] !== undefined ? layerTopY[layer[n.id]] : 0;
    }

    // Normalize X to start at pad.left
    const xVals = Object.values(xCoords);
    const minX = xVals.length ? Math.min(...xVals) : 0;
    for (const id of Object.keys(xCoords)) xCoords[id] = xCoords[id] - minX + pad.left;

    // 6. Edge routing
    const edgeSections = routeEdges(edges, allNodes, layer, xCoords, yCoords, widths, heights, reversedEdgeIds);

    // Write positions to original nodes
    for (const n of nodes) {
      n.x = Math.round((xCoords[n.id] || 0) * 10) / 10;
      n.y = Math.round((yCoords[n.id] || 0) * 10) / 10;
    }

    // Write sections to original edges
    for (const e of edges) {
      if (e._isDummy) continue;
      e.sections = edgeSections[e.id] || [{
        id: `${e.id}_s0`,
        startPoint: { x: (xCoords[e.sources[0]] || 0) + (widths[e.sources[0]] || 0) / 2, y: (yCoords[e.sources[0]] || 0) + (heights[e.sources[0]] || 0) },
        endPoint:   { x: (xCoords[e.targets[0]] || 0) + (widths[e.targets[0]] || 0) / 2, y: yCoords[e.targets[0]] || 0 },
        bendPoints: [],
      }];
    }

    // Compute total dimensions
    let maxRight = 0;
    for (const n of nodes) {
      const r = (n.x || 0) + (widths[n.id] || 0);
      if (r > maxRight) maxRight = r;
    }
    graph.width  = Math.max(maxRight + pad.right, pad.left + pad.right);
    graph.height = Math.max(curY - vSpacing + pad.bottom, pad.top + pad.bottom);

    // Direction rotation (RIGHT = swap axes)
    if (direction === 'RIGHT') {
      const origW = graph.width; const origH = graph.height;
      for (const n of nodes) {
        const nx = n.y; const ny = n.x;
        n.x = nx; n.y = ny;
      }
      for (const e of edges) {
        const swap = p => ({ x: p.y, y: p.x });
        for (const sec of (e.sections || [])) {
          sec.startPoint = swap(sec.startPoint);
          sec.endPoint   = swap(sec.endPoint);
          sec.bendPoints = (sec.bendPoints || []).map(swap);
        }
      }
      graph.width = origH;
      graph.height = origW;
    }

    return graph;
  }

  // ─── ELK public constructor ───────────────────────────────────────────────────

  function ELK(options) {
    this._sync = !!(options && options.sync);
  }

  ELK.prototype.layout = function (graph, extraOpts) {
    // Deep-clone children/edges so we don't corrupt caller's data before writing back
    const work = Object.assign({}, graph);
    if (extraOpts && extraOpts.layoutOptions) {
      work.layoutOptions = Object.assign({}, graph.layoutOptions || {}, extraOpts.layoutOptions);
    }
    try {
      const result = doLayout(work);
      // Copy x/y back to original graph children
      if (graph.children && work.children) {
        const byId = {};
        for (const c of work.children) byId[c.id] = c;
        for (const c of graph.children) {
          if (byId[c.id]) { c.x = byId[c.id].x; c.y = byId[c.id].y; }
        }
      }
      if (graph.edges && work.edges) {
        const byId = {};
        for (const e of work.edges) byId[e.id] = e;
        for (const e of graph.edges) {
          if (byId[e.id]) { e.sections = byId[e.id].sections; }
        }
      }
      graph.width = result.width;
      graph.height = result.height;
      if (this._sync) return graph;
      return Promise.resolve(graph);
    } catch (err) {
      if (this._sync) throw err;
      return Promise.reject(err);
    }
  };

  ELK.prototype.knownLayoutOptions    = function () { return Promise.resolve([]); };
  ELK.prototype.knownLayoutAlgorithms = function () { return Promise.resolve([{ id: 'layered', name: 'ELK Layered' }]); };
  ELK.prototype.knownLayoutCategories = function () { return Promise.resolve([]); };

  return ELK;
}));
