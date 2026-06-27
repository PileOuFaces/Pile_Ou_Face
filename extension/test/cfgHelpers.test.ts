/**
 * Tests for extension/webview/shared/cfgHelpers.js
 * Pure graph layout helpers — no DOM, no vscode.
 */
const { expect } = require('chai');
const path = require('path');
const helpers = require(path.resolve(__dirname, '../webview/shared/cfgHelpers.js'));

const { buildAdjacency, buildReverseAdj, bfsLevels, classifyEdges, computeLayout, bfsPath } = helpers;

// ---------------------------------------------------------------------------
// buildAdjacency
// ---------------------------------------------------------------------------
describe('buildAdjacency', () => {
  it('returns empty object for no edges', () => {
    expect(buildAdjacency([])).to.deep.equal({});
  });

  it('groups edges by from node', () => {
    const edges = [
      { from: 'A', to: 'B', type: 'jmp' },
      { from: 'A', to: 'C', type: 'fallthrough' },
      { from: 'B', to: 'C', type: 'call' },
    ];
    const adj = buildAdjacency(edges);
    expect(adj['A']).to.have.length(2);
    expect(adj['B']).to.have.length(1);
    expect(adj['C']).to.be.undefined;
  });

  it('defaults type to fallthrough when missing', () => {
    const adj = buildAdjacency([{ from: 'X', to: 'Y' }]);
    expect(adj['X'][0].type).to.equal('fallthrough');
  });
});

// ---------------------------------------------------------------------------
// buildReverseAdj
// ---------------------------------------------------------------------------
describe('buildReverseAdj', () => {
  it('returns empty object for no edges', () => {
    expect(buildReverseAdj([])).to.deep.equal({});
  });

  it('reverses direction correctly', () => {
    const edges = [{ from: 'A', to: 'B' }, { from: 'C', to: 'B' }];
    const radj = buildReverseAdj(edges);
    expect(radj['B']).to.include.members(['A', 'C']);
    expect(radj['A']).to.be.undefined;
  });
});

// ---------------------------------------------------------------------------
// bfsLevels
// ---------------------------------------------------------------------------
describe('bfsLevels', () => {
  it('returns empty object for null entry', () => {
    expect(bfsLevels({}, null)).to.deep.equal({});
  });

  it('assigns level 0 to entry', () => {
    const adj = buildAdjacency([{ from: 'A', to: 'B' }]);
    const levels = bfsLevels(adj, 'A');
    expect(levels['A']).to.equal(0);
  });

  it('assigns correct levels in a linear chain', () => {
    const adj = buildAdjacency([
      { from: 'A', to: 'B' },
      { from: 'B', to: 'C' },
      { from: 'C', to: 'D' },
    ]);
    const levels = bfsLevels(adj, 'A');
    expect(levels).to.deep.equal({ A: 0, B: 1, C: 2, D: 3 });
  });

  it('handles cycles without infinite loop', () => {
    const adj = buildAdjacency([
      { from: 'A', to: 'B' },
      { from: 'B', to: 'A' },
    ]);
    const levels = bfsLevels(adj, 'A');
    expect(levels['A']).to.equal(0);
    expect(levels['B']).to.equal(1);
  });

  it('does not include unreachable nodes', () => {
    const adj = buildAdjacency([{ from: 'A', to: 'B' }]);
    const levels = bfsLevels(adj, 'A');
    expect(levels['C']).to.be.undefined;
  });
});

// ---------------------------------------------------------------------------
// classifyEdges
// ---------------------------------------------------------------------------
describe('classifyEdges', () => {
  it('returns empty arrays for no edges', () => {
    const { forwardEdges, backEdges } = classifyEdges([], {});
    expect(forwardEdges).to.deep.equal([]);
    expect(backEdges).to.deep.equal([]);
  });

  it('classifies forward edges correctly', () => {
    const edges = [{ from: 'A', to: 'B' }, { from: 'B', to: 'C' }];
    const levels = { A: 0, B: 1, C: 2 };
    const { forwardEdges, backEdges } = classifyEdges(edges, levels);
    expect(forwardEdges).to.have.length(2);
    expect(backEdges).to.have.length(0);
  });

  it('classifies back edges (same or higher level) correctly', () => {
    const edges = [
      { from: 'A', to: 'B' },
      { from: 'B', to: 'A' },  // back-edge: level 1 → level 0
      { from: 'C', to: 'C' },  // self-loop: level 2 → level 2
    ];
    const levels = { A: 0, B: 1, C: 2 };
    const { forwardEdges, backEdges } = classifyEdges(edges, levels);
    expect(forwardEdges).to.have.length(1);
    expect(backEdges).to.have.length(2);
    expect(backEdges[0].from).to.equal('B');
    expect(backEdges[1].from).to.equal('C');
  });

  it('treats edges with unknown levels as forward', () => {
    const edges = [{ from: 'X', to: 'Y' }];
    const levels = { X: 0 }; // Y not in levels
    const { forwardEdges, backEdges } = classifyEdges(edges, levels);
    expect(forwardEdges).to.have.length(1);
    expect(backEdges).to.have.length(0);
  });
});

// ---------------------------------------------------------------------------
// computeLayout
// ---------------------------------------------------------------------------
describe('computeLayout', () => {
  it('returns defaults for empty graph', () => {
    const { positions, width, height } = computeLayout([], [], {});
    expect(positions).to.deep.equal({});
    expect(width).to.be.at.least(600);
    expect(height).to.be.at.least(400);
  });

  it('places entry node at y=padY', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }];
    const edges = [{ from: 'A', to: 'B' }];
    const { positions } = computeLayout(nodes, edges, { padX: 40, padY: 40 });
    expect(positions['A'].y).to.equal(40);
    expect(positions['B'].y).to.be.greaterThan(positions['A'].y);
  });

  it('places nodes at same level side by side on the x axis', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }, { addr: 'C' }];
    // B and C are both reachable from A at level 1
    const edges = [{ from: 'A', to: 'B' }, { from: 'A', to: 'C' }];
    const { positions } = computeLayout(nodes, edges, { nodeW: 100, padX: 20 });
    expect(positions['B'].y).to.equal(positions['C'].y);
    expect(positions['B'].x).to.not.equal(positions['C'].x);
  });

  it('width and height are at least the minimum', () => {
    const nodes = [{ addr: 'X' }];
    const { width, height } = computeLayout(nodes, [], {});
    expect(width).to.be.at.least(600);
    expect(height).to.be.at.least(400);
  });

  it('returns levels in the result', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }, { addr: 'C' }];
    const edges = [{ from: 'A', to: 'B' }, { from: 'B', to: 'C' }];
    const { levels } = computeLayout(nodes, edges, {});
    expect(levels).to.deep.equal({ A: 0, B: 1, C: 2 });
  });

  it('keeps call targets from driving the main CFG levels', () => {
    const nodes = [{ addr: '0x10' }, { addr: '0x20' }, { addr: '0x30' }];
    const edges = [
      { from: '0x10', to: '0x30', type: 'call' },
      { from: '0x10', to: '0x20', type: 'fallthrough' },
      { from: '0x20', to: '0x30', type: 'fallthrough' },
    ];
    const { levels } = computeLayout(nodes, edges, {});
    expect(levels['0x20']).to.equal(1);
    expect(levels['0x30']).to.equal(2);
  });

  it('places call-only targets beside normal successors instead of before them', () => {
    const nodes = [{ addr: '0x10' }, { addr: '0x20' }, { addr: '0x08' }];
    const edges = [
      { from: '0x10', to: '0x08', type: 'call' },
      { from: '0x10', to: '0x20', type: 'fallthrough' },
    ];
    const { positions, levels } = computeLayout(nodes, edges, { nodeW: 100, padX: 20 });
    expect(levels['0x08']).to.equal(levels['0x20']);
    expect(positions['0x20'].x).to.be.lessThan(positions['0x08'].x);
  });

  it('does not let loop back-edges collapse the loop body upward', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }, { addr: 'C' }, { addr: 'D' }];
    const edges = [
      { from: 'A', to: 'B', type: 'fallthrough' },
      { from: 'B', to: 'C', type: 'fallthrough' },
      { from: 'C', to: 'B', type: 'jmp' },
      { from: 'C', to: 'D', type: 'fallthrough' },
    ];
    const { levels } = computeLayout(nodes, edges, {});
    expect(levels['A']).to.equal(0);
    expect(levels['B']).to.equal(1);
    expect(levels['C']).to.equal(2);
    expect(levels['D']).to.equal(3);
  });

  it('keeps the fallthrough spine vertically aligned while moving branches aside', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }, { addr: 'C' }, { addr: 'D' }];
    const edges = [
      { from: 'A', to: 'B', type: 'fallthrough' },
      { from: 'A', to: 'C', type: 'jmp' },
      { from: 'B', to: 'D', type: 'fallthrough' },
      { from: 'C', to: 'D', type: 'jmp' },
    ];
    const { positions } = computeLayout(nodes, edges, { nodeW: 100, padX: 20 });
    expect(Math.abs(positions['A'].x - positions['B'].x)).to.be.lessThan(1);
    expect(positions['C'].x).to.not.equal(positions['B'].x);
  });

  it('can place CFG nodes in explicit readable lanes', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }, { addr: 'C' }, { addr: 'D' }];
    const edges = [
      { from: 'A', to: 'B', type: 'fallthrough' },
      { from: 'A', to: 'C', type: 'jmp' },
      { from: 'A', to: 'D', type: 'call' },
    ];
    const { positions, lanes } = computeLayout(nodes, edges, {
      layoutMode: 'lanes',
      nodeW: 100,
      padX: 20,
      lanePadX: 20,
    });
    const laneByLabel = Object.fromEntries(lanes.map((lane) => [lane.label, lane]));
    expect(positions['B'].x).to.equal(laneByLabel.Flux.x);
    expect(positions['C'].x).to.equal(laneByLabel['Branches / Calls'].x);
    expect(positions['D'].x).to.be.greaterThan(positions['C'].x);
    expect(positions['D'].x).to.be.lessThan(positions['B'].x);
    expect(lanes.map((lane) => lane.label)).to.deep.equal(['Branches / Calls', 'Flux', 'Boucles']);
  });

  it('keeps loop latch blocks to the right of the main flow in lane mode', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }, { addr: 'C' }, { addr: 'D' }];
    const edges = [
      { from: 'A', to: 'B', type: 'fallthrough' },
      { from: 'B', to: 'C', type: 'fallthrough' },
      { from: 'C', to: 'B', type: 'jmp' },
      { from: 'C', to: 'D', type: 'fallthrough' },
    ];
    const { positions, lanes } = computeLayout(nodes, edges, {
      layoutMode: 'lanes',
      nodeW: 100,
      padX: 20,
      lanePadX: 20,
    });
    const laneByLabel = Object.fromEntries(lanes.map((lane) => [lane.label, lane]));
    expect(positions['B'].x).to.equal(laneByLabel.Flux.x);
    expect(positions['C'].x).to.equal(laneByLabel.Boucles.x);
    expect(positions['C'].x).to.be.greaterThan(positions['B'].x);
  });

  it('keeps the flow lane visually centered between side work and loops', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }, { addr: 'C' }];
    const edges = [
      { from: 'A', to: 'B', type: 'fallthrough' },
      { from: 'B', to: 'C', type: 'fallthrough' },
    ];
    const { lanes } = computeLayout(nodes, edges, {
      layoutMode: 'lanes',
      nodeW: 100,
      padX: 20,
      lanePadX: 20,
    });
    const laneByLabel = Object.fromEntries(lanes.map((lane) => [lane.label, lane]));
    expect(lanes[1].label).to.equal('Flux');
    expect(laneByLabel.Flux.x).to.be.greaterThan(laneByLabel['Branches / Calls'].x);
    expect(laneByLabel.Flux.x).to.be.lessThan(laneByLabel.Boucles.x);
  });

  it('uses a Cutter-like layout with fallthrough below and branches to the side', () => {
    const nodes = [{ addr: 'A' }, { addr: 'B' }, { addr: 'C' }, { addr: 'D' }];
    const edges = [
      { from: 'A', to: 'B', type: 'fallthrough' },
      { from: 'A', to: 'C', type: 'jmp' },
      { from: 'B', to: 'D', type: 'fallthrough' },
      { from: 'C', to: 'D', type: 'jmp' },
    ];
    const { positions } = computeLayout(nodes, edges, {
      layoutMode: 'cutter',
      nodeW: 100,
      padX: 20,
      padY: 20,
      lanePadX: 20,
    });
    expect(positions['B'].y).to.be.greaterThan(positions['A'].y);
    expect(positions['B'].x).to.equal(positions['A'].x);
    expect(positions['C'].y).to.be.greaterThan(positions['B'].y);
    expect(positions['C'].x).to.be.greaterThan(positions['B'].x);
    expect(positions['D'].y).to.be.greaterThan(positions['C'].y);
  });

  it('keeps Cutter-like reading order strictly top to bottom by block address', () => {
    const nodes = [{ addr: '0x10' }, { addr: '0x20' }, { addr: '0x30' }, { addr: '0x40' }];
    const edges = [
      { from: '0x10', to: '0x20', type: 'call' },
      { from: '0x20', to: '0x30', type: 'call' },
      { from: '0x30', to: '0x40', type: 'jmp' },
      { from: '0x40', to: '0x20', type: 'jmp' },
    ];
    const { positions } = computeLayout(nodes, edges, {
      layoutMode: 'cutter',
      nodeW: 100,
      padX: 20,
      padY: 20,
      lanePadX: 20,
    });
    expect(positions['0x20'].y).to.be.greaterThan(positions['0x10'].y);
    expect(positions['0x30'].y).to.be.greaterThan(positions['0x20'].y);
    expect(positions['0x40'].y).to.be.greaterThan(positions['0x30'].y);
  });

  it('barycenter ordering reduces crossings in a simple case', () => {
    // Diamond: A→B, A→C, B→D, C→E
    // Without barycenter, B and C could be in any order.
    // With barycenter, B should be left of C (since B→D, C→E)
    // and D should be left of E (aligned with their parents).
    const nodes = [
      { addr: 'A' }, { addr: 'B' }, { addr: 'C' },
      { addr: 'D' }, { addr: 'E' },
    ];
    const edges = [
      { from: 'A', to: 'B' }, { from: 'A', to: 'C' },
      { from: 'B', to: 'D' }, { from: 'C', to: 'E' },
    ];
    const { positions } = computeLayout(nodes, edges, {});
    // D should be to the left of E (aligned under B which is left of C)
    expect(positions['D'].x).to.be.lessThan(positions['E'].x);
  });

  it('wraps levels with more than maxPerRow nodes onto sub-rows', () => {
    // Create 10 nodes at level 1 (all children of A)
    const nodes = [{ addr: 'A' }];
    const edges = [];
    for (let i = 0; i < 10; i++) {
      const addr = 'N' + i;
      nodes.push({ addr });
      edges.push({ from: 'A', to: addr });
    }
    const { positions } = computeLayout(nodes, edges, { maxPerRow: 4 });
    // With maxPerRow=4, 10 nodes at level 1 → 3 sub-rows (4+4+2)
    const level1Ys = new Set();
    for (let i = 0; i < 10; i++) {
      level1Ys.add(positions['N' + i].y);
    }
    // Should span 3 distinct y values
    expect(level1Ys.size).to.equal(3);
  });
});

// ---------------------------------------------------------------------------
// bfsPath
// ---------------------------------------------------------------------------
describe('bfsPath', () => {
  it('returns [start] when start === end', () => {
    const adj = buildAdjacency([]);
    expect(bfsPath(adj, 'A', 'A')).to.deep.equal(['A']);
  });

  it('returns null when no path exists', () => {
    const adj = buildAdjacency([{ from: 'A', to: 'B' }]);
    expect(bfsPath(adj, 'B', 'A')).to.be.null;
  });

  it('finds direct path A→B', () => {
    const adj = buildAdjacency([{ from: 'A', to: 'B' }]);
    expect(bfsPath(adj, 'A', 'B')).to.deep.equal(['A', 'B']);
  });

  it('finds shortest path in a diamond graph', () => {
    // A→B→D and A→C→D — shortest is length 3
    const edges = [
      { from: 'A', to: 'B' },
      { from: 'A', to: 'C' },
      { from: 'B', to: 'D' },
      { from: 'C', to: 'D' },
    ];
    const adj = buildAdjacency(edges);
    const p = bfsPath(adj, 'A', 'D');
    expect(p).to.have.length(3);
    expect(p[0]).to.equal('A');
    expect(p[p.length - 1]).to.equal('D');
  });

  it('handles cycles without infinite loop', () => {
    const edges = [
      { from: 'A', to: 'B' },
      { from: 'B', to: 'A' },
      { from: 'B', to: 'C' },
    ];
    const adj = buildAdjacency(edges);
    expect(bfsPath(adj, 'A', 'C')).to.deep.equal(['A', 'B', 'C']);
  });
});
