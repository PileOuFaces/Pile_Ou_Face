/**
 * cfgHelpers.js — Graph layout helpers for CFG and Call Graph SVG rendering.
 *
 * Uses ELK (elk.bundled.js) as the layout engine when available in the browser
 * (window.ELK), with a full synchronous fallback for Node.js environments (tests)
 * and when ELK is not yet loaded.
 *
 * Universal module: works in a VS Code webview (browser) and in Node.js (Mocha tests).
 * No DOM, no vscode, no side-effects.
 *
 * Public API (unchanged):
 *   buildAdjacency(edges)                → adjacency map
 *   buildReverseAdj(edges)               → reverse adjacency map
 *   bfsLevels(adj, entry)                → level map
 *   classifyEdges(edges, levels)         → { forwardEdges, backEdges }
 *   computeLayout(nodes, edges, opts)    → { positions, width, height, levels, lanes? }
 *   computeLayoutAsync(nodes, edges, opts) → Promise<{ positions, width, height, levels, lanes? }>
 *   bfsPath(adj, start, end)             → string[] | null
 *
 * computeLayout opts:
 *   nodeW, nodeH, padX, padY, lanePadX  : dimensions (px)
 *   layoutMode                          : 'elk' (default) | 'lanes' | 'cutter' | 'sugiyama'
 *   maxPerRow                           : max nodes per row in sugiyama fallback
 *
 * ELK layout options passed through:
 *   'elk.spacing.nodeNode'                        : horizontal gap (default = padX or 40)
 *   'elk.layered.spacing.nodeNodeBetweenLayers'   : vertical gap (default = padY or 40)
 */
(function (exports) {

  // ─── Basic graph utilities (unchanged) ──────────────────────────────────────

  /**
   * Build forward adjacency list from an edge array.
   * @param {Array<{from: string, to: string, type?: string}>} edges
   * @returns {Object.<string, Array<{to: string, type: string}>>}
   */
  function buildAdjacency(edges) {
    const adj = {};
    for (const e of edges) {
      if (!adj[e.from]) adj[e.from] = [];
      adj[e.from].push({ to: e.to, type: e.type || 'fallthrough' });
    }
    return adj;
  }

  /**
   * Build reverse adjacency list.
   * @param {Array<{from: string, to: string}>} edges
   * @returns {Object.<string, string[]>}
   */
  function buildReverseAdj(edges) {
    const radj = {};
    for (const e of edges) {
      if (!radj[e.to]) radj[e.to] = [];
      radj[e.to].push(e.from);
    }
    return radj;
  }

  /**
   * BFS level assignment from an entry node.
   * @param {Object.<string, Array<{to: string}>>} adj
   * @param {string} entry
   * @returns {Object.<string, number>}
   */
  function bfsLevels(adj, entry) {
    if (!entry) return {};
    const levels = {};
    const queue = [entry];
    levels[entry] = 0;
    while (queue.length) {
      const addr = queue.shift();
      const l = levels[addr];
      for (const { to } of (adj[addr] || [])) {
        if (levels[to] === undefined) {
          levels[to] = l + 1;
          queue.push(to);
        }
      }
    }
    return levels;
  }

  /**
   * Classify edges into forward and back edges based on BFS levels.
   * A back-edge points to the same level or higher (towards entry), indicating a loop.
   * @param {Array<{from: string, to: string, type?: string}>} edges
   * @param {Object.<string, number>} levels
   * @returns {{forwardEdges: Array, backEdges: Array}}
   */
  function classifyEdges(edges, levels) {
    const forwardEdges = [];
    const backEdges = [];
    for (const e of edges) {
      const lFrom = levels[e.from];
      const lTo   = levels[e.to];
      if (lFrom !== undefined && lTo !== undefined && lFrom >= lTo) {
        backEdges.push(e);
      } else {
        forwardEdges.push(e);
      }
    }
    return { forwardEdges, backEdges };
  }

  /**
   * BFS shortest path between two nodes.
   * @param {Object.<string, Array<{to: string}>>} adj
   * @param {string} start
   * @param {string} end
   * @returns {string[]|null}
   */
  function bfsPath(adj, start, end) {
    if (start === end) return [start];
    const visited = new Set([start]);
    const queue = [[start]];
    while (queue.length) {
      const path = queue.shift();
      const cur = path[path.length - 1];
      for (const { to } of (adj[cur] || [])) {
        if (to === end) return [...path, to];
        if (!visited.has(to)) {
          visited.add(to);
          queue.push([...path, to]);
        }
      }
    }
    return null;
  }

  // ─── Address utilities ───────────────────────────────────────────────────────

  function addrSortValue(addr) {
    const raw = String(addr || '').trim();
    const normalized = raw.toLowerCase().startsWith('0x') ? raw.slice(2) : raw;
    if (/^[0-9a-f]+$/i.test(normalized)) {
      const value = parseInt(normalized, 16);
      if (isFinite(value)) return value;
    }
    return Number.MAX_SAFE_INTEGER;
  }

  function compareAddr(a, b) {
    const av = addrSortValue(a);
    const bv = addrSortValue(b);
    if (av !== bv) return av - bv;
    return String(a).localeCompare(String(b));
  }

  // ─── ELK-based layout (primary) ─────────────────────────────────────────────

  /**
   * Build an ELK graph from CFG nodes/edges, run synchronous layout,
   * and return positions in the cfgHelpers format.
   *
   * @param {Array<{addr: string}>} nodes
   * @param {Array<{from: string, to: string, type?: string}>} edges
   * @param {{nodeW?:number, nodeH?:number, padX?:number, padY?:number, lanePadX?:number}} opts
   * @returns {{ positions, width, height, levels, elkGraph }}
   */
  function computeLayoutELK(nodes, edges, opts, elkInstance) {
    const nodeW = (opts && opts.nodeW)  || 200;
    const nodeH = (opts && opts.nodeH)  || 100;
    const padX  = (opts && opts.padX)   || 40;
    const padY  = (opts && opts.padY)   || 40;
    const hGap  = (opts && opts.lanePadX) || Math.max(28, Math.min(54, padX));

    // Assign levels first (for classifyEdges and back-edge detection)
    const entry = nodes.length > 0 ? nodes[0].addr : null;
    const layoutEdges = edges.filter(e => e.type !== 'call');
    const adj = buildAdjacency(layoutEdges);
    const bfsL = bfsLevels(adj, entry);
    const { backEdges } = classifyEdges(layoutEdges, bfsL);
    const backEdgeKeys = new Set(backEdges.map(e => `${e.from}|${e.to}`));

    // Build ELK graph
    const elkGraph = {
      id: 'root',
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': 'DOWN',
        'elk.spacing.nodeNode': String(hGap),
        'elk.layered.spacing.nodeNodeBetweenLayers': String(padY),
        'elk.edgeRouting': 'ORTHOGONAL',
        'elk.padding': `[top=${padX},left=${padX},bottom=${padX},right=${padX}]`,
      },
      children: nodes.map(n => ({
        id: n.addr,
        width: nodeW,
        height: nodeH,
      })),
      edges: edges
        .filter(e => !backEdgeKeys.has(`${e.from}|${e.to}`))
        .map((e, i) => ({
          id: `e${i}_${e.from}_${e.to}`,
          sources: [e.from],
          targets: [e.to],
          layoutOptions: { 'elk.edge.type': e.type || 'jmp' },
          _fromAddr: e.from,
          _toAddr:   e.to,
          _type:     e.type || 'jmp',
        })),
    };

    // Run ELK (sync mode)
    const laid = elkInstance.layout(elkGraph);
    // laid.children now have { x, y }

    const positions = {};
    const levels = {};
    for (const child of (laid.children || [])) {
      positions[child.id] = { x: child.x || 0, y: child.y || 0 };
    }

    // Derive levels from Y coordinate (tier = row index by y)
    const yValues = [...new Set(Object.values(positions).map(p => p.y))].sort((a, b) => a - b);
    const yToLevel = new Map(yValues.map((y, i) => [y, i]));
    for (const addr of Object.keys(positions)) {
      levels[addr] = yToLevel.get(positions[addr].y) ?? 0;
    }

    // Assign unreachable nodes
    const maxL = Math.max(-1, ...Object.values(levels));
    for (const n of nodes) {
      if (levels[n.addr] === undefined) {
        levels[n.addr] = maxL + 1;
        positions[n.addr] = positions[n.addr] || { x: padX, y: padY + (maxL + 1) * (nodeH + padY) };
      }
    }

    const allX = Object.values(positions).map(p => p.x);
    const allY = Object.values(positions).map(p => p.y);
    const width  = Math.max(600, allX.length ? Math.max(...allX) + nodeW + padX : 600);
    const height = Math.max(400, allY.length ? Math.max(...allY) + nodeH + padY : 400);

    return { positions, width, height, levels, elkGraph: laid };
  }

  // ─── Fallback: legacy synchronous Sugiyama layout ────────────────────────────
  // (kept intact so all existing Mocha tests still pass)

  function edgeWeight(type) {
    if (type === 'fallthrough') return 5;
    if (type === 'jmp') return 3;
    if (type === 'jumptable') return 2;
    if (type === 'call') return 0.35;
    return 1;
  }

  function edgeRank(type) {
    if (type === 'fallthrough') return 0;
    if (type === 'jmp') return 1;
    if (type === 'jumptable') return 2;
    if (type === 'call') return 3;
    return 4;
  }

  function isLayoutEdge(edge) {
    return edge && edge.type !== 'call';
  }

  function sortedEdges(edges) {
    return [...edges].sort((a, b) => {
      const aw = edgeWeight(a.type || 'fallthrough');
      const bw = edgeWeight(b.type || 'fallthrough');
      return bw - aw || compareAddr(a.to, b.to) || compareAddr(a.from, b.from);
    });
  }

  function computeStructuredLevels(nodes, edges, entry) {
    const layoutEdges = sortedEdges(edges.filter(isLayoutEdge));
    const adj = buildAdjacency(layoutEdges);
    const seedLevels = bfsLevels(adj, entry);
    const levels = { ...seedLevels };

    const forwardEdges = layoutEdges.filter((e) => {
      const lFrom = seedLevels[e.from];
      const lTo = seedLevels[e.to];
      return lFrom !== undefined && lTo !== undefined && lFrom < lTo;
    });
    for (let pass = 0; pass < nodes.length; pass++) {
      let changed = false;
      for (const e of forwardEdges) {
        const desired = levels[e.from] + 1;
        if (levels[e.to] < desired) {
          levels[e.to] = desired;
          changed = true;
        }
      }
      if (!changed) break;
    }
    return levels;
  }

  function edgeLaneOffset(edge, siblings, parentCol) {
    const type = edge.type || 'fallthrough';
    const idx = Math.max(0, siblings.findIndex((item) => item.to === edge.to && item.type === edge.type));
    const mid = (siblings.length - 1) / 2;
    if (type === 'fallthrough') return 0;
    if (type === 'call') return 1.75 + idx * 0.75;
    if (type === 'jumptable') return (idx - mid) * 1.05;
    if (type === 'jmp') {
      const hasMainFlow = siblings.some((item) => (item.type || 'fallthrough') === 'fallthrough');
      if (hasMainFlow) return idx <= mid ? -1.15 : 1.15;
      return (idx - mid || 0.6) * 1.15;
    }
    return parentCol >= 0 ? 0.9 : -0.9;
  }

  function assignSugiyamaColumns(byLevel, sortedLevelKeys, edges, levels, colIdx) {
    const columns = {};
    const incoming = {};
    const outgoingByParentLevel = {};

    for (const e of edges) {
      const lFrom = levels[e.from];
      const lTo = levels[e.to];
      if (lFrom === undefined || lTo === undefined || lFrom >= lTo) continue;
      if (!incoming[e.to]) incoming[e.to] = [];
      incoming[e.to].push(e);
      const key = `${e.from}|${lTo}`;
      if (!outgoingByParentLevel[key]) outgoingByParentLevel[key] = [];
      outgoingByParentLevel[key].push(e);
    }

    Object.keys(outgoingByParentLevel).forEach((key) => {
      outgoingByParentLevel[key].sort((a, b) =>
        edgeRank(a.type || 'fallthrough') - edgeRank(b.type || 'fallthrough') || compareAddr(a.to, b.to));
    });

    for (const lk of sortedLevelKeys) {
      const addrs = byLevel[lk];
      const centeredFallback = (addrs.length - 1) / 2;
      const scored = addrs.map((addr, index) => {
        const parents = incoming[addr] || [];
        if (!parents.length) return { addr, ideal: index - centeredFallback, rank: 4 };
        let weighted = 0; let total = 0; let bestRank = 4;
        parents.forEach((edge) => {
          const parentCol = columns[edge.from] ?? 0;
          const siblings = outgoingByParentLevel[`${edge.from}|${lk}`] || [edge];
          const weight = edgeWeight(edge.type || 'fallthrough');
          const rank = edgeRank(edge.type || 'fallthrough');
          weighted += (parentCol + edgeLaneOffset(edge, siblings, parentCol)) * weight;
          total += weight;
          bestRank = Math.min(bestRank, rank);
        });
        return { addr, ideal: total ? weighted / total : index - centeredFallback, rank: bestRank };
      });
      scored.sort((a, b) => a.ideal - b.ideal || a.rank - b.rank || colIdx[a.addr] - colIdx[b.addr] || compareAddr(a.addr, b.addr));
      let previous = -Infinity;
      const minGap = 1.08;
      scored.forEach((item) => {
        const col = Math.max(item.ideal, previous + minGap);
        columns[item.addr] = col;
        previous = col;
      });
      const drift = scored.length
        ? scored.reduce((sum, item) => sum + (columns[item.addr] - item.ideal), 0) / scored.length
        : 0;
      scored.forEach((item) => { columns[item.addr] -= drift; });
    }
    return columns;
  }

  function firstEdge(edges, type) {
    const matches = edges.filter((edge) => (edge.type || 'fallthrough') === type);
    matches.sort((a, b) => compareAddr(a.to, b.to));
    return matches[0] || null;
  }

  function buildMainPath(entry, edges) {
    const byFrom = {};
    for (const edge of edges) {
      if (!byFrom[edge.from]) byFrom[edge.from] = [];
      byFrom[edge.from].push(edge);
    }
    const path = new Set();
    let current = entry;
    while (current && !path.has(current)) {
      path.add(current);
      const outgoing = byFrom[current] || [];
      const next = firstEdge(outgoing, 'fallthrough')
        || firstEdge(outgoing.filter((edge) => edge.type !== 'call'), 'jmp')
        || null;
      current = next ? next.to : null;
    }
    return path;
  }

  function computeLaneLayout(nodes, edges, opts) {
    const nodeW   = (opts && opts.nodeW)     || 200;
    const nodeH   = (opts && opts.nodeH)     || 100;
    const padX    = (opts && opts.padX)      || 40;
    const padY    = (opts && opts.padY)      || 40;
    const laneGap = (opts && opts.lanePadX)  || Math.max(28, Math.min(54, padX));
    const entry = nodes.length > 0 ? nodes[0].addr : null;
    const levels = computeStructuredLevels(nodes, edges, entry);

    for (let pass = 0; pass < nodes.length; pass++) {
      let changed = false;
      for (const e of sortedEdges(edges.filter((edge) => edge.type === 'call'))) {
        if (levels[e.from] === undefined || levels[e.to] !== undefined) continue;
        levels[e.to] = levels[e.from] + 1;
        changed = true;
      }
      if (!changed) break;
    }

    const maxL = nodes.length > 0
      ? Math.max(-1, ...nodes.map(n => (levels[n.addr] !== undefined ? levels[n.addr] : -1)))
      : -1;
    for (const n of nodes) {
      if (levels[n.addr] === undefined) levels[n.addr] = maxL + 1;
    }

    const mainPath = buildMainPath(entry, sortedEdges(edges.filter((edge) => edge.type !== 'call')));
    const incoming = {}; const outgoing = {};
    for (const e of edges) {
      if (!incoming[e.to]) incoming[e.to] = [];
      incoming[e.to].push(e);
      if (!outgoing[e.from]) outgoing[e.from] = [];
      outgoing[e.from].push(e);
    }

    const { backEdges } = classifyEdges(edges.filter((edge) => edge.type !== 'call'), levels);
    const loopLatchNodes = new Set(backEdges.map((edge) => edge.from));

    function laneFor(addr) {
      const ins = incoming[addr] || [];
      const outs = outgoing[addr] || [];
      const hasCallIn = ins.some((edge) => edge.type === 'call');
      const hasNonCallIn = ins.some((edge) => edge.type !== 'call');
      const hasBranchIn = ins.some((edge) => edge.type === 'jmp' || edge.type === 'jumptable');
      const hasLoopOut = outs.some((edge) => {
        const lFrom = levels[edge.from];
        const lTo = levels[edge.to];
        return edge.type !== 'call' && lFrom !== undefined && lTo !== undefined && lFrom >= lTo;
      });
      if (hasCallIn && !hasNonCallIn) return 'side';
      if (loopLatchNodes.has(addr) || hasLoopOut) return 'loop';
      if (mainPath.has(addr) || addr === entry) return 'flow';
      if (hasBranchIn) return 'side';
      return hasCallIn ? 'side' : 'side';
    }

    const lanes = [
      { id: 'side', label: 'Branches / Calls' },
      { id: 'flow', label: 'Flux' },
      { id: 'loop', label: 'Boucles' },
    ];
    const byLevelLane = {};
    for (const n of nodes) {
      const level = levels[n.addr];
      const lane = laneFor(n.addr);
      if (!byLevelLane[level]) byLevelLane[level] = {};
      if (!byLevelLane[level][lane]) byLevelLane[level][lane] = [];
      byLevelLane[level][lane].push(n.addr);
    }

    const sortedLevelKeys = Object.keys(byLevelLane).sort((a, b) => +a - +b);
    const laneMaxCounts = {};
    lanes.forEach((lane) => { laneMaxCounts[lane.id] = 1; });
    for (const level of sortedLevelKeys) {
      for (const lane of lanes) {
        const addrs = byLevelLane[level][lane.id] || [];
        addrs.sort(compareAddr);
        laneMaxCounts[lane.id] = Math.max(laneMaxCounts[lane.id], addrs.length);
      }
    }

    let cursorX = padX;
    const laneMeta = [];
    for (const lane of lanes) {
      const slots = laneMaxCounts[lane.id] || 1;
      const width = slots * nodeW + Math.max(0, slots - 1) * laneGap;
      laneMeta.push({ ...lane, x: cursorX, width });
      cursorX += width + padX;
    }

    const laneById = Object.fromEntries(laneMeta.map((lane) => [lane.id, lane]));
    const positions = {};
    sortedLevelKeys.forEach((level, rowIndex) => {
      const y = padY + rowIndex * (nodeH + padY);
      for (const lane of lanes) {
        const addrs = byLevelLane[level][lane.id] || [];
        addrs.forEach((addr, index) => {
          const meta = laneById[lane.id];
          positions[addr] = { x: meta.x + index * (nodeW + laneGap), y };
        });
      }
    });

    const width  = Math.max(600, cursorX);
    const height = Math.max(400, padY + sortedLevelKeys.length * (nodeH + padY));
    return { positions, width, height, levels, lanes: laneMeta };
  }

  function cutterChildSort(a, b) {
    return edgeRank(a.type || 'fallthrough') - edgeRank(b.type || 'fallthrough') || compareAddr(a.to, b.to);
  }

  function computeCutterLayout(nodes, edges, opts) {
    const nodeW    = (opts && opts.nodeW)    || 200;
    const nodeH    = (opts && opts.nodeH)    || 100;
    const padX     = (opts && opts.padX)     || 40;
    const padY     = (opts && opts.padY)     || 40;
    const lanePadX = (opts && opts.lanePadX) || Math.max(28, Math.min(48, padX));
    const entry = nodes.length > 0 ? nodes[0].addr : null;
    const levels = computeStructuredLevels(nodes, edges, entry);

    const maxL = nodes.length > 0
      ? Math.max(-1, ...nodes.map(n => (levels[n.addr] !== undefined ? levels[n.addr] : -1)))
      : -1;
    for (const n of nodes) {
      if (levels[n.addr] === undefined) levels[n.addr] = maxL + 1;
    }

    const sortedNodes = [...nodes].sort((a, b) => compareAddr(a.addr, b.addr));
    const rowIndex = Object.fromEntries(sortedNodes.map((node, index) => [node.addr, index]));
    const byFrom = {};
    for (const edge of edges) {
      if (!byFrom[edge.from]) byFrom[edge.from] = [];
      byFrom[edge.from].push(edge);
    }
    Object.keys(byFrom).forEach((addr) => byFrom[addr].sort(cutterChildSort));

    const col = {};
    for (const node of sortedNodes) col[node.addr] = 0;
    for (const node of sortedNodes) {
      const children = byFrom[node.addr] || [];
      const forwardStructural = children.filter((edge) =>
        edge.type !== 'call' && rowIndex[edge.to] !== undefined && rowIndex[edge.to] > rowIndex[node.addr]);
      const fallthrough = forwardStructural.find((edge) => (edge.type || 'fallthrough') === 'fallthrough');
      forwardStructural.forEach((edge) => {
        if (fallthrough && edge.to === fallthrough.to) return;
        col[edge.to] = Math.max(col[edge.to] || 0, (col[node.addr] || 0) + 1);
      });
      children.filter((edge) => edge.type === 'call').forEach((edge) => {
        if (rowIndex[edge.to] === undefined) return;
        col[edge.to] = Math.max(col[edge.to] || 0, (col[node.addr] || 0) + 2);
      });
    }

    const maxCol = Math.max(0, ...Object.values(col));
    const laneW = nodeW + lanePadX;
    const positions = {};
    for (const n of sortedNodes) {
      positions[n.addr] = {
        x: padX + (col[n.addr] || 0) * laneW,
        y: padY + rowIndex[n.addr] * (nodeH + padY),
      };
    }

    const width  = Math.max(600, (maxCol + 1) * laneW + padX * 2);
    const height = Math.max(400, sortedNodes.length * (nodeH + padY) + padY);
    return { positions, width, height, levels };
  }

  function computeSugiyamaLayout(nodes, edges, opts) {
    const nodeW    = (opts && opts.nodeW)    || 200;
    const nodeH    = (opts && opts.nodeH)    || 100;
    const padX     = (opts && opts.padX)     || 40;
    const padY     = (opts && opts.padY)     || 40;
    const maxPerRow = (opts && opts.maxPerRow) || 8;

    const entry = nodes.length > 0 ? nodes[0].addr : null;
    const levels = computeStructuredLevels(nodes, edges, entry);

    for (let pass = 0; pass < nodes.length; pass++) {
      let changed = false;
      for (const e of sortedEdges(edges.filter((edge) => edge.type === 'call'))) {
        if (levels[e.from] === undefined || levels[e.to] !== undefined) continue;
        levels[e.to] = levels[e.from] + 1;
        changed = true;
      }
      if (!changed) break;
    }

    const maxL = nodes.length > 0
      ? Math.max(-1, ...nodes.map(n => (levels[n.addr] !== undefined ? levels[n.addr] : -1)))
      : -1;
    for (const n of nodes) {
      if (levels[n.addr] === undefined) levels[n.addr] = maxL + 1;
    }

    const byLevel = {};
    for (const n of nodes) {
      const l = levels[n.addr];
      if (!byLevel[l]) byLevel[l] = [];
      byLevel[l].push(n.addr);
    }

    const sortedLevelKeys = Object.keys(byLevel).sort((a, b) => +a - +b);

    const parentMap = {}; const childMap = {};
    const parentWeightMap = {}; const childWeightMap = {};
    const incomingRankMap = {};
    for (const e of edges) {
      const lFrom = levels[e.from];
      const lTo   = levels[e.to];
      if (lFrom !== undefined && lTo !== undefined && lFrom < lTo) {
        if (!childMap[e.from])  childMap[e.from]  = [];
        if (!childWeightMap[e.from]) childWeightMap[e.from] = [];
        childMap[e.from].push(e.to);
        childWeightMap[e.from].push(edgeWeight(e.type || 'fallthrough'));
        if (!parentMap[e.to])  parentMap[e.to]  = [];
        if (!parentWeightMap[e.to]) parentWeightMap[e.to] = [];
        parentMap[e.to].push(e.from);
        parentWeightMap[e.to].push(edgeWeight(e.type || 'fallthrough'));
        const rank = edgeRank(e.type || 'fallthrough');
        incomingRankMap[e.to] = Math.min(incomingRankMap[e.to] ?? rank, rank);
      }
    }

    const colIdx = {};
    for (const lk of sortedLevelKeys) {
      const addrs = byLevel[lk];
      for (let i = 0; i < addrs.length; i++) colIdx[addrs[i]] = i;
    }

    for (let pass = 0; pass < 4; pass++) {
      // Top-down
      for (let li = 1; li < sortedLevelKeys.length; li++) {
        const lk = sortedLevelKeys[li];
        const addrs = byLevel[lk];
        const scored = addrs.map(addr => {
          const pars = parentMap[addr];
          const weights = parentWeightMap[addr] || [];
          if (pars && pars.length > 0) {
            const total = weights.reduce((s, w) => s + w, 0) || pars.length;
            const avg = pars.reduce((s, p, i) => s + colIdx[p] * (weights[i] || 1), 0) / total;
            return { addr, bary: avg, rank: incomingRankMap[addr] ?? 4 };
          }
          return { addr, bary: colIdx[addr], rank: incomingRankMap[addr] ?? 4 };
        });
        scored.sort((a, b) => a.bary - b.bary || a.rank - b.rank || compareAddr(a.addr, b.addr));
        for (let i = 0; i < scored.length; i++) {
          byLevel[lk][i] = scored[i].addr;
          colIdx[scored[i].addr] = i;
        }
      }
      // Bottom-up
      for (let li = sortedLevelKeys.length - 2; li >= 0; li--) {
        const lk = sortedLevelKeys[li];
        const addrs = byLevel[lk];
        const scored = addrs.map(addr => {
          const childs = childMap[addr];
          const weights = childWeightMap[addr] || [];
          if (childs && childs.length > 0) {
            const total = weights.reduce((s, w) => s + w, 0) || childs.length;
            const avg = childs.reduce((s, c, i) => s + colIdx[c] * (weights[i] || 1), 0) / total;
            return { addr, bary: avg, rank: incomingRankMap[addr] ?? 4 };
          }
          return { addr, bary: colIdx[addr], rank: incomingRankMap[addr] ?? 4 };
        });
        scored.sort((a, b) => a.bary - b.bary || a.rank - b.rank || compareAddr(a.addr, b.addr));
        for (let i = 0; i < scored.length; i++) {
          byLevel[lk][i] = scored[i].addr;
          colIdx[scored[i].addr] = i;
        }
      }
    }

    const columns = assignSugiyamaColumns(byLevel, sortedLevelKeys, edges, levels, colIdx);

    const positions = {};
    const rowSpecs = [];
    let y = padY;
    for (const lk of sortedLevelKeys) {
      const addrs = byLevel[lk];
      if (addrs.length <= maxPerRow) {
        rowSpecs.push({ addrs: [...addrs], y });
        y += nodeH + padY;
      } else {
        let rowY = y;
        for (let i = 0; i < addrs.length; i += maxPerRow) {
          rowSpecs.push({ addrs: addrs.slice(i, i + maxPerRow), y: rowY });
          rowY += nodeH + padY;
        }
        y = rowY;
      }
    }

    const columnValues = Object.values(columns);
    const minCol = columnValues.length ? Math.min(...columnValues) : 0;
    const lanePadX = (opts && opts.lanePadX) || Math.max(24, Math.min(padX, 44));
    const laneW = nodeW + lanePadX;
    rowSpecs.forEach((row) => {
      row.addrs.forEach((addr, i) => {
        const col = columns[addr] ?? i;
        positions[addr] = { x: padX + (col - minCol) * laneW, y: row.y };
      });
    });

    const allX = Object.values(positions).map(p => p.x);
    const width  = allX.length > 0 ? Math.max(600, Math.max(...allX) + nodeW + padX) : 600;
    const height = Math.max(400, y);

    return { positions, width, height, levels };
  }

  // ─── Public computeLayout (synchronous, backward-compatible) ─────────────────

  /**
   * Compute a graph layout. Uses ELK when available (window.ELK or require('elkjs')),
   * falls back to legacy Sugiyama otherwise.
   *
   * Returns the same shape as before:
   *   { positions: {addr: {x,y}}, width, height, levels, lanes? }
   *
   * @param {Array<{addr: string}>} nodes
   * @param {Array<{from: string, to: string, type?: string}>} edges
   * @param {object} [opts]
   * @returns {{ positions, width, height, levels, lanes? }}
   */
  function computeLayout(nodes, edges, opts) {
    if (nodes.length === 0) {
      return { positions: {}, width: 600, height: 400, levels: {} };
    }

    const mode = (opts && opts.layoutMode) || 'elk';

    // Explicit legacy modes
    if (mode === 'cutter')   return computeCutterLayout(nodes, edges, opts);
    if (mode === 'lanes')    return computeLaneLayout(nodes, edges, opts);
    if (mode === 'sugiyama') return computeSugiyamaLayout(nodes, edges, opts);

    // ELK mode: try to find ELK constructor
    let ElkCtor = null;
    if (typeof window !== 'undefined' && typeof window.ELK === 'function') {
      ElkCtor = window.ELK;
    } else if (typeof ELK !== 'undefined' && typeof ELK === 'function') {
      // Global scope (module loaded before this file)
      ElkCtor = ELK;
    } else {
      // Try CommonJS require (Node.js / test environment) — but avoid hard crash
      try {
        // This path is only hit in test environments where elkjs may not be installed
        ElkCtor = null;
      } catch (_) {
        ElkCtor = null;
      }
    }

    if (ElkCtor) {
      try {
        const elk = new ElkCtor({ sync: true });
        return computeLayoutELK(nodes, edges, opts, elk);
      } catch (err) {
        // Fall through to legacy
      }
    }

    // Fallback: legacy Sugiyama
    return computeSugiyamaLayout(nodes, edges, opts);
  }

  /**
   * Async variant — always uses ELK (Promise-based) if available.
   * @returns {Promise<{ positions, width, height, levels, lanes? }>}
   */
  function computeLayoutAsync(nodes, edges, opts) {
    if (nodes.length === 0) {
      return Promise.resolve({ positions: {}, width: 600, height: 400, levels: {} });
    }

    const mode = (opts && opts.layoutMode) || 'elk';
    if (mode === 'cutter')   return Promise.resolve(computeCutterLayout(nodes, edges, opts));
    if (mode === 'lanes')    return Promise.resolve(computeLaneLayout(nodes, edges, opts));
    if (mode === 'sugiyama') return Promise.resolve(computeSugiyamaLayout(nodes, edges, opts));

    let ElkCtor = null;
    if (typeof window !== 'undefined' && typeof window.ELK === 'function') {
      ElkCtor = window.ELK;
    } else if (typeof ELK !== 'undefined' && typeof ELK === 'function') {
      ElkCtor = ELK;
    }

    if (!ElkCtor) {
      return Promise.resolve(computeSugiyamaLayout(nodes, edges, opts));
    }

    const elk = new ElkCtor();
    const nodeW = (opts && opts.nodeW) || 200;
    const nodeH = (opts && opts.nodeH) || 100;
    const padX  = (opts && opts.padX)  || 40;
    const padY  = (opts && opts.padY)  || 40;
    const hGap  = (opts && opts.lanePadX) || Math.max(28, Math.min(54, padX));

    const entry = nodes.length > 0 ? nodes[0].addr : null;
    const layoutEdges = edges.filter(e => e.type !== 'call');
    const adj = buildAdjacency(layoutEdges);
    const bfsL = bfsLevels(adj, entry);
    const { backEdges } = classifyEdges(layoutEdges, bfsL);
    const backEdgeKeys = new Set(backEdges.map(e => `${e.from}|${e.to}`));

    const elkGraph = {
      id: 'root',
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': 'DOWN',
        'elk.spacing.nodeNode': String(hGap),
        'elk.layered.spacing.nodeNodeBetweenLayers': String(padY),
        'elk.edgeRouting': 'ORTHOGONAL',
        'elk.padding': `[top=${padX},left=${padX},bottom=${padX},right=${padX}]`,
      },
      children: nodes.map(n => ({ id: n.addr, width: nodeW, height: nodeH })),
      edges: edges
        .filter(e => !backEdgeKeys.has(`${e.from}|${e.to}`))
        .map((e, i) => ({
          id: `e${i}_${e.from}_${e.to}`,
          sources: [e.from],
          targets: [e.to],
          layoutOptions: { 'elk.edge.type': e.type || 'jmp' },
        })),
    };

    return elk.layout(elkGraph).then(laid => {
      const positions = {};
      const levels = {};
      for (const child of (laid.children || [])) {
        positions[child.id] = { x: child.x || 0, y: child.y || 0 };
      }
      const yValues = [...new Set(Object.values(positions).map(p => p.y))].sort((a, b) => a - b);
      const yToLevel = new Map(yValues.map((y, i) => [y, i]));
      for (const addr of Object.keys(positions)) {
        levels[addr] = yToLevel.get(positions[addr].y) ?? 0;
      }
      const maxL = Math.max(-1, ...Object.values(levels));
      for (const n of nodes) {
        if (levels[n.addr] === undefined) {
          levels[n.addr] = maxL + 1;
          positions[n.addr] = { x: padX, y: padY + (maxL + 1) * (nodeH + padY) };
        }
      }
      const allX = Object.values(positions).map(p => p.x);
      const allY = Object.values(positions).map(p => p.y);
      const width  = Math.max(600, allX.length ? Math.max(...allX) + nodeW + padX : 600);
      const height = Math.max(400, allY.length ? Math.max(...allY) + nodeH + padY : 400);
      return { positions, width, height, levels, elkGraph: laid };
    }).catch(() => computeSugiyamaLayout(nodes, edges, opts));
  }

  // ─── Exports ─────────────────────────────────────────────────────────────────

  exports.buildAdjacency     = buildAdjacency;
  exports.buildReverseAdj    = buildReverseAdj;
  exports.bfsLevels          = bfsLevels;
  exports.classifyEdges      = classifyEdges;
  exports.computeLayout      = computeLayout;
  exports.computeLayoutAsync = computeLayoutAsync;
  exports.bfsPath            = bfsPath;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exports;
  } else {
    window.cfgHelpers = exports;
  }

}(typeof module !== 'undefined' && module.exports ? module.exports : {}));
