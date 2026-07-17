// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('fs');
const path = require('path');
const {
  buildReport: buildCoverageReport,
  latestAuditEventsPath,
  readAuditEvents,
} = require('./runtime-audit-feature-coverage');
const {
  expectedFeatureRows,
} = require('./runtime-audit-feature-map');

const extensionRoot = path.resolve(__dirname, '..', '..');
const artifactsDir = path.join(extensionRoot, '.pile-ou-face', 'test-artifacts', 'e2e-runtime-audit');
const jsonPath = path.join(artifactsDir, 'runtime-audit-workflow-report.json');
const markdownPath = path.join(artifactsDir, 'runtime-audit-workflow-report.md');

const DEPTH_BY_SCENARIO_PREFIX = [
  { prefix: 'static-disasm:', depth: 'functional', workflow: 'Static binary analysis' },
  { prefix: 'static-disasm-section', depth: 'functional', workflow: 'Static binary analysis' },
  { prefix: 'editor-command:', depth: 'functional', workflow: 'Editor navigation / AI context' },
  { prefix: 'dialog-command:', depth: 'smoke', workflow: 'Interactive VS Code command' },
  { prefix: 'command:', depth: 'smoke', workflow: 'Shared command palette command' },
  { prefix: 'hub-handler:runTrace', depth: 'smoke', workflow: 'Dynamic tracing' },
  { prefix: 'hub-handler:hubLoad', depth: 'integration', workflow: 'Backend static analysis loader' },
  { prefix: 'hub-handler:hubExport', depth: 'functional', workflow: 'Export workflow' },
  { prefix: 'hub-handler:hubPatch', depth: 'functional', workflow: 'Patch workflow' },
  { prefix: 'hub-handler:hubRe', depth: 'functional', workflow: 'State mutation workflow' },
  { prefix: 'hub-handler:hubAi', depth: 'mocked-integration', workflow: 'AI provider workflow' },
  { prefix: 'hub-handler:hubOllama', depth: 'mocked-integration', workflow: 'Ollama workflow' },
  { prefix: 'hub-handler:pof.auth.', depth: 'mocked-integration', workflow: 'Auth workflow' },
  { prefix: 'hub-handler:', depth: 'smoke', workflow: 'Hub webview handler' },
  { prefix: 'hub-startup', depth: 'functional', workflow: 'Hub startup' },
];

const DEPTH_RANK = {
  missing: 0,
  'observed-no-perf': 1,
  smoke: 1,
  'mocked-integration': 2,
  functional: 3,
  integration: 4,
};

const HOST_OBSERVABILITY_GAP_NOTES = {
  hubDebugLog: 'Log-channel side effect is not observable from the current E2E harness.',
  hubModeChange: 'Sidebar mode setter is a no-op in the extension host E2E wiring.',
  'pileOuFace.showLogs': 'Output-channel visibility is not exposed to the E2E harness.',
  'pileOuFace.sidebarRefresh': 'Sidebar refresh callback is a no-op in the extension host E2E wiring.',
};

const PERF_PRIORITY_RANK = { P0: 0, P1: 1, P2: 2, P3: 3 };

function readJsonl(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function latestPerfPath() {
  if (process.env.POF_E2E_PERF_EVENTS_PATH && fs.existsSync(process.env.POF_E2E_PERF_EVENTS_PATH)) {
    return process.env.POF_E2E_PERF_EVENTS_PATH;
  }
  if (!fs.existsSync(artifactsDir)) return '';
  const files = fs.readdirSync(artifactsDir)
    .filter((name) => /^runtime-audit-perf-.*\.jsonl$/.test(name))
    .map((name) => path.join(artifactsDir, name))
    .filter((filePath) => fs.statSync(filePath).isFile())
    .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs);
  return files[0] || '';
}

function toMs(timestamp) {
  const value = Date.parse(timestamp);
  return Number.isFinite(value) ? value : 0;
}

function bytes(value) {
  return Number.isFinite(value) ? value : 0;
}

function mb(value) {
  return Math.round((value / 1024 / 1024) * 10) / 10;
}

function classifyScenario(scenario) {
  const match = DEPTH_BY_SCENARIO_PREFIX.find((entry) => scenario.startsWith(entry.prefix));
  return match || { depth: 'smoke', workflow: 'Unclassified workflow' };
}

function promotedDepth(baseDepth, {
  responseValidated = false,
  uiConsumed = false,
  payloadValidated = false,
  sideEffectValidated = false,
  stateValidated = false,
} = {}) {
  if (payloadValidated && DEPTH_RANK[baseDepth] < DEPTH_RANK.functional) return 'functional';
  if (responseValidated && uiConsumed && DEPTH_RANK[baseDepth] < DEPTH_RANK.functional) return 'functional';
  if (stateValidated && DEPTH_RANK[baseDepth] < DEPTH_RANK.functional) return 'functional';
  if (sideEffectValidated && DEPTH_RANK[baseDepth] < DEPTH_RANK.functional) return 'functional';
  if (responseValidated && DEPTH_RANK[baseDepth] < DEPTH_RANK['mocked-integration']) return 'mocked-integration';
  return baseDepth;
}

function targetForScenario(scenario) {
  if (scenario.startsWith('command:')) return scenario.slice('command:'.length);
  if (scenario.startsWith('dialog-command:')) return scenario.slice('dialog-command:'.length);
  if (scenario.startsWith('editor-command:')) return scenario.slice('editor-command:'.length);
  if (scenario.startsWith('hub-handler:')) return scenario.slice('hub-handler:'.length);
  if (scenario.startsWith('static-disasm:')) return 'pileOuFace.goToSymbolInDisasm';
  if (scenario === 'static-disasm-section') return 'pileOuFace.disasmSection';
  if (scenario === 'hub-startup') return 'pileOuFace.open';
  return scenario;
}

function summarizePerf(perfEvents) {
  const active = new Map();
  const spans = [];
  for (const event of perfEvents) {
    if (!event.scenario) continue;
    if (event.type === 'scenario_start') {
      active.set(event.scenario, { start: event, samples: [] });
    } else if (event.type === 'sample') {
      active.get(event.scenario)?.samples.push(event);
    } else if (event.type === 'scenario_stop') {
      const current = active.get(event.scenario);
      if (!current) continue;
      const events = [current.start, ...current.samples, event];
      const rssValues = events.map((item) => bytes(item.memory?.rss));
      const heapValues = events.map((item) => bytes(item.memory?.heapUsed));
      const startMs = toMs(current.start.ts);
      const stopMs = toMs(event.ts);
      const classification = classifyScenario(event.scenario);
      const responseTypes = Array.isArray(event.result?.responseTypes)
        ? event.result.responseTypes
        : (Array.isArray(event.details?.responseTypes) ? event.details.responseTypes : current.start.details?.responseTypes || []);
      const responseValidated = responseTypes.length > 0 && event.result?.ok !== false;
      const uiConsumed = event.result?.uiConsumed === true;
      const payloadValidated = event.result?.payloadValidated === true;
      const stateValidated = event.result?.stateValidated === true;
      const auditDelta = event.result?.auditDelta && typeof event.result.auditDelta === 'object' ? event.result.auditDelta : null;
      const sideEffectValidated = Boolean(
        auditDelta
        && event.result?.ok !== false
        && (
          deltaKind(auditDelta, 'process') > 0
          || deltaKind(auditDelta, 'python') > 0
          || deltaKind(auditDelta, 'host_effect') > 0
          || deltaKind(auditDelta, 'webview_post_message') > 0
        )
      );
      const rssStart = bytes(current.start.memory?.rss);
      const heapStart = bytes(current.start.memory?.heapUsed);
      const rssStop = bytes(event.memory?.rss);
      const heapStop = bytes(event.memory?.heapUsed);
      spans.push({
        scenario: event.scenario,
        target: targetForScenario(event.scenario),
        startTs: current.start.ts,
        stopTs: event.ts,
        workflow: classification.workflow,
        depth: promotedDepth(classification.depth, {
          responseValidated,
          uiConsumed,
          payloadValidated,
          sideEffectValidated,
          stateValidated,
        }),
        ok: event.result?.ok !== false,
        responseTypes,
        responseValidated,
        uiConsumed,
        payloadValidated,
        stateValidated,
        sideEffectValidated,
        auditDelta,
        durationMs: Math.max(0, stopMs - startMs),
        samples: current.samples.length,
        fixture: event.details?.fixture || current.start.details?.fixture || '',
        sizeBytes: event.details?.sizeBytes || current.start.details?.sizeBytes || 0,
        fixtureKind: event.details?.kind || current.start.details?.kind || '',
        compiler: event.details?.compiler || current.start.details?.compiler || '',
        opt: event.details?.opt || current.start.details?.opt || '',
        arch: event.details?.arch || current.start.details?.arch || '',
        stripped: event.details?.stripped === true || current.start.details?.stripped === true,
        rssStart,
        rssStop,
        rssMax: Math.max(...rssValues),
        rssDelta: rssStop - rssStart,
        rssPeakDelta: Math.max(...rssValues) - rssStart,
        heapStart,
        heapStop,
        heapMax: Math.max(...heapValues),
        heapDelta: heapStop - heapStart,
        heapPeakDelta: Math.max(...heapValues) - heapStart,
        error: event.result?.error || '',
      });
      active.delete(event.scenario);
    }
  }
  return spans;
}

function groupByTarget(spans) {
  const map = new Map();
  for (const span of spans) {
    const current = map.get(span.target) || {
      target: span.target,
      workflows: new Set(),
      depth: 'missing',
      runs: 0,
      failedRuns: 0,
      responseValidatedRuns: 0,
      uiConsumedRuns: 0,
      payloadValidatedRuns: 0,
      totalDurationMs: 0,
      maxDurationMs: 0,
      maxRssPeakDelta: 0,
      maxHeapPeakDelta: 0,
      scenarios: [],
    };
    current.workflows.add(span.workflow);
    current.depth = DEPTH_RANK[span.depth] > DEPTH_RANK[current.depth] ? span.depth : current.depth;
    current.runs += 1;
    current.failedRuns += span.ok ? 0 : 1;
    current.responseValidatedRuns += span.responseValidated ? 1 : 0;
    current.uiConsumedRuns += span.uiConsumed ? 1 : 0;
    current.payloadValidatedRuns += span.payloadValidated ? 1 : 0;
    current.totalDurationMs += span.durationMs;
    current.maxDurationMs = Math.max(current.maxDurationMs, span.durationMs);
    current.maxRssPeakDelta = Math.max(current.maxRssPeakDelta, span.rssPeakDelta);
    current.maxHeapPeakDelta = Math.max(current.maxHeapPeakDelta, span.heapPeakDelta);
    current.scenarios.push(span.scenario);
    map.set(span.target, current);
  }
  return [...map.values()]
    .map((entry) => ({
      ...entry,
      workflows: [...entry.workflows].sort(),
      avgDurationMs: Math.round(entry.totalDurationMs / Math.max(1, entry.runs)),
      scenarios: [...new Set(entry.scenarios)].sort(),
    }))
    .sort((left, right) => right.maxDurationMs - left.maxDurationMs || left.target.localeCompare(right.target));
}

function percentile(values, ratio) {
  if (!values.length) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * ratio) - 1));
  return sorted[index];
}

function buildOptimizationCandidates(spans) {
  const successful = spans.filter((span) => span.ok);
  const durationThreshold = Math.max(500, percentile(successful.map((span) => span.durationMs), 0.9));
  const heapThreshold = Math.max(4 * 1024 * 1024, percentile(successful.map((span) => span.heapPeakDelta), 0.9));
  const rssThreshold = Math.max(8 * 1024 * 1024, percentile(successful.map((span) => span.rssPeakDelta), 0.9));

  return successful
    .filter((span) => (
      span.durationMs >= durationThreshold
      || span.heapPeakDelta >= heapThreshold
      || span.rssPeakDelta >= rssThreshold
    ))
    .map((span) => ({
      scenario: span.scenario,
      target: span.target,
      workflow: span.workflow,
      durationMs: span.durationMs,
      rssPeakDelta: span.rssPeakDelta,
      heapPeakDelta: span.heapPeakDelta,
      reasons: [
        span.durationMs >= durationThreshold ? 'duration' : '',
        span.heapPeakDelta >= heapThreshold ? 'heap' : '',
        span.rssPeakDelta >= rssThreshold ? 'rss' : '',
      ].filter(Boolean),
    }))
    .sort((left, right) => (
      right.durationMs - left.durationMs
      || right.rssPeakDelta - left.rssPeakDelta
      || right.heapPeakDelta - left.heapPeakDelta
    ));
}

function buildPerfStepBreakdown(auditEvents, spans) {
  const perfSteps = auditEvents
    .filter((event) => event.kind === 'perf_step' && event.name)
    .map((event) => ({
      ...event,
      tsMs: toMs(event.ts),
      durationMs: Math.max(0, Number(event.durationMs || 0)),
    }))
    .filter((event) => event.tsMs > 0);
  if (!perfSteps.length || !spans.length) return [];

  const rows = [];
  for (const span of spans) {
    const startMs = toMs(span.startTs);
    const stopMs = toMs(span.stopTs);
    if (!startMs || !stopMs || stopMs < startMs) continue;
    const steps = perfSteps.filter((event) => event.tsMs >= startMs && event.tsMs <= stopMs);
    if (!steps.length) continue;
    const byStep = new Map();
    for (const step of steps) {
      const current = byStep.get(step.name) || {
        scenario: span.scenario,
        target: span.target,
        step: step.name,
        count: 0,
        totalDurationMs: 0,
        maxDurationMs: 0,
        sources: new Set(),
        binaryNames: new Set(),
      };
      current.count += 1;
      current.totalDurationMs += step.durationMs;
      current.maxDurationMs = Math.max(current.maxDurationMs, step.durationMs);
      if (step.source) current.sources.add(step.source);
      if (step.binaryName) current.binaryNames.add(step.binaryName);
      byStep.set(step.name, current);
    }
    rows.push(...[...byStep.values()].map((entry) => ({
      ...entry,
      avgDurationMs: Math.round(entry.totalDurationMs / Math.max(1, entry.count)),
      totalDurationMs: Math.round(entry.totalDurationMs),
      sources: [...entry.sources].sort(),
      binaryNames: [...entry.binaryNames].sort(),
    })));
  }
  return rows.sort((left, right) => (
    right.maxDurationMs - left.maxDurationMs
    || right.totalDurationMs - left.totalDurationMs
    || left.scenario.localeCompare(right.scenario)
    || left.step.localeCompare(right.step)
  ));
}

function deltaKind(delta, kind) {
  return Number(delta?.byKind?.[kind] || 0);
}

function normalizeOperationEntry(entry) {
  const kind = String(entry?.kind || '');
  const name = ['python', 'process'].includes(kind)
    ? normalizeBackendName(entry?.name)
    : String(entry?.name || '');
  return {
    kind,
    name,
    count: Number(entry?.count || 0),
  };
}

function buildRuntimeOperationHotspots(spans) {
  return spans
    .filter((span) => span.auditDelta && span.ok)
    .map((span) => {
      const pythonCalls = deltaKind(span.auditDelta, 'python');
      const processCalls = deltaKind(span.auditDelta, 'process');
      const webviewInbound = deltaKind(span.auditDelta, 'webview_message');
      const webviewOutbound = deltaKind(span.auditDelta, 'webview_post_message');
      const uiAckCalls = Array.isArray(span.auditDelta.topNames)
        ? span.auditDelta.topNames
          .filter((entry) => entry?.kind === 'webview_message' && entry?.name === 'hubUiConsumed')
          .reduce((total, entry) => total + Number(entry.count || 0), 0)
        : 0;
      const repeatedNames = Array.isArray(span.auditDelta.repeatedNames)
        ? span.auditDelta.repeatedNames.map(normalizeOperationEntry)
        : [];
      const topNames = Array.isArray(span.auditDelta.topNames)
        ? span.auditDelta.topNames.map(normalizeOperationEntry)
        : [];
      const scoringRepeatedNames = repeatedNames.filter((entry) => !(entry.kind === 'webview_message' && entry.name === 'hubUiConsumed'));
      const maxRepeated = scoringRepeatedNames.reduce((max, item) => Math.max(max, Number(item.count || 0)), 0);
      const scoredEvents = Math.max(0, Number(span.auditDelta.totalEvents || 0) - uiAckCalls);
      const score = (pythonCalls * 4) + (processCalls * 3) + (maxRepeated * 2) + Math.max(0, scoredEvents - 4);
      return {
        scenario: span.scenario,
        target: span.target,
        durationMs: span.durationMs,
        totalEvents: Number(span.auditDelta.totalEvents || 0),
        scoredEvents,
        pythonCalls,
        processCalls,
        uiAckCalls,
        webviewInbound,
        webviewOutbound,
        maxRepeated,
        repeatedNames,
        topNames,
        score,
      };
    })
    .filter((item) => (
      item.score > 0
      && (item.pythonCalls > 0 || item.processCalls > 0 || item.maxRepeated >= 3 || item.totalEvents >= 6)
    ))
    .sort((left, right) => (
      right.score - left.score
      || right.pythonCalls - left.pythonCalls
      || right.processCalls - left.processCalls
      || right.totalEvents - left.totalEvents
      || left.scenario.localeCompare(right.scenario)
    ));
}

function operationLabel(entry) {
  if (!entry) return '<none>';
  return `${entry.kind}:${entry.name} x${entry.count}`;
}

function perfPriorityForScore(score) {
  if (score >= 120) return 'P0';
  if (score >= 60) return 'P1';
  if (score >= 25) return 'P2';
  return 'P3';
}

function perfBottleneckFor({ hotspot, candidate }) {
  const repeatedBackend = (hotspot.repeatedNames || [])
    .filter((entry) => ['python', 'process'].includes(entry.kind) && entry.count >= 2)
    .sort((left, right) => right.count - left.count);
  if (repeatedBackend.length) {
    return {
      category: 'repeated-backend',
      evidence: operationLabel(repeatedBackend[0]),
      recommendation: `Trace why ${repeatedBackend[0].name} runs ${repeatedBackend[0].count} times in one workflow; check cache reuse and nested refresh fan-out before optimizing implementation code.`,
    };
  }
  const topNames = hotspot.topNames || [];
  const hasAnnotationRefreshFanout = [
    'hubSaveBookmark',
    'hubDeleteBookmark',
    'hubDeleteAnnotation',
    'hubSaveFunctionReview',
    'hubClearBookmarks',
  ].includes(hotspot.target)
    && topNames.some((entry) => entry.kind === 'webview_message' && ['getSymbols', 'requestRunTraceInit'].includes(entry.name))
    && topNames.some((entry) => entry.kind === 'python' && ['backends/static/binary/headers.py', 'backends/static/binary/symbols.py'].includes(entry.name));
  if (hasAnnotationRefreshFanout) {
    const evidence = topNames
      .filter((entry) => (
        (entry.kind === 'webview_message' && ['getSymbols', 'requestRunTraceInit'].includes(entry.name))
        || (entry.kind === 'python' && ['backends/static/binary/headers.py', 'backends/static/binary/symbols.py'].includes(entry.name))
      ))
      .slice(0, 4)
      .map(operationLabel)
      .join(', ');
    return {
      category: 'annotation-autoload-fanout',
      evidence,
      recommendation: 'Annotation/bookmark save emits hubAnnotationSaved; the webview then refreshes disassembly and dynamic trace init. Decide in a separate optimization PR whether that refresh fan-out is required for this workflow.',
    };
  }
  if (hotspot.pythonCalls >= 6 || hotspot.processCalls >= 2) {
    return {
      category: 'backend-fanout',
      evidence: `python=${hotspot.pythonCalls}, process=${hotspot.processCalls}`,
      recommendation: 'Inspect the handler fan-out and backend cache boundaries; confirm whether repeated backend calls are expected for this single user workflow.',
    };
  }
  const repeatedPost = (hotspot.repeatedNames || [])
    .find((entry) => entry.kind === 'webview_post_message' && entry.count >= 4);
  if (repeatedPost) {
    return {
      category: 'webview-response-churn',
      evidence: operationLabel(repeatedPost),
      recommendation: 'Inspect repeated host-to-webview responses and verify that the UI requests this payload only once per user workflow.',
    };
  }
  const repeatedHost = (hotspot.repeatedNames || [])
    .find((entry) => entry.kind === 'host_effect' && entry.count >= 4);
  if (repeatedHost) {
    return {
      category: 'host-effect-churn',
      evidence: operationLabel(repeatedHost),
      recommendation: 'Check whether host-only effects are used as progress telemetry or are being repeated by an avoidable dispatch loop.',
    };
  }
  if (candidate?.reasons?.includes('duration')) {
    return {
      category: 'slow-span',
      evidence: `${hotspot.durationMs} ms`,
      recommendation: 'Profile this span with the generated audit/perf JSONL and split backend time from extension-host orchestration time.',
    };
  }
  if (candidate?.reasons?.some((reason) => ['heap', 'rss'].includes(reason))) {
    return {
      category: 'memory-spike',
      evidence: `RSS +${formatBytes(candidate.rssPeakDelta)}, heap +${formatBytes(candidate.heapPeakDelta)}`,
      recommendation: 'Inspect payload sizes and cached objects retained during this workflow before changing product behavior.',
    };
  }
  const top = hotspot.topNames?.[0];
  return {
    category: 'operation-volume',
    evidence: top ? operationLabel(top) : `${hotspot.totalEvents} runtime event(s)`,
    recommendation: 'Review the operation mix and decide whether this should stay as baseline telemetry or become a focused regression test.',
  };
}

function buildPerfPriorities(runtimeOperationHotspots, optimizationCandidates) {
  const candidatesByScenario = new Map(optimizationCandidates.map((item) => [item.scenario, item]));
  return runtimeOperationHotspots
    .map((hotspot) => {
      const candidate = candidatesByScenario.get(hotspot.scenario) || null;
      const bottleneck = perfBottleneckFor({ hotspot, candidate });
      const memoryMb = candidate ? Math.max(candidate.rssPeakDelta, candidate.heapPeakDelta) / 1024 / 1024 : 0;
      const durationScore = Math.round((hotspot.durationMs || 0) / 50);
      const memoryScore = Math.round(memoryMb * 2);
      const priorityScore = hotspot.score + durationScore + memoryScore + (candidate ? 10 : 0);
      const priority = perfPriorityForScore(priorityScore);
      return {
        priority,
        priorityScore,
        scenario: hotspot.scenario,
        target: hotspot.target,
        category: bottleneck.category,
        evidence: bottleneck.evidence,
        recommendation: bottleneck.recommendation,
        durationMs: hotspot.durationMs,
        runtimeScore: hotspot.score,
        totalEvents: hotspot.totalEvents,
        scoredEvents: hotspot.scoredEvents,
        pythonCalls: hotspot.pythonCalls,
        processCalls: hotspot.processCalls,
        uiAckCalls: hotspot.uiAckCalls,
        webviewInbound: hotspot.webviewInbound,
        webviewOutbound: hotspot.webviewOutbound,
        maxRepeated: hotspot.maxRepeated,
        repeatedNames: hotspot.repeatedNames,
        topNames: hotspot.topNames,
        optimizationReasons: candidate?.reasons || [],
        rssPeakDelta: candidate?.rssPeakDelta || 0,
        heapPeakDelta: candidate?.heapPeakDelta || 0,
      };
    })
    .sort((left, right) => (
      PERF_PRIORITY_RANK[left.priority] - PERF_PRIORITY_RANK[right.priority]
      || right.priorityScore - left.priorityScore
      || right.durationMs - left.durationMs
      || left.scenario.localeCompare(right.scenario)
    ));
}

function buildDepthGaps(coverageReport, targetSummaries) {
  const byTarget = new Map(targetSummaries.map((entry) => [entry.target, entry]));
  const gaps = [];
  for (const command of coverageReport.commands) {
    const summary = byTarget.get(command.command);
    if (!summary && !command.covered) {
      gaps.push({ target: command.command, kind: 'command', currentDepth: 'missing', recommendedNextStep: command.note || 'Add a workflow scenario.' });
    } else if (!summary) {
      gaps.push({ target: command.command, kind: 'command', currentDepth: 'observed-no-perf', recommendedNextStep: 'Add a named perf scenario around this observed path.' });
    } else if (DEPTH_RANK[summary.depth] < DEPTH_RANK.functional) {
      gaps.push({ target: command.command, kind: 'command', currentDepth: summary.depth, recommendedNextStep: 'Add a result assertion or backend fixture so this is more than smoke.' });
    }
  }
  for (const handler of coverageReport.webviewHandlers) {
    const summary = byTarget.get(handler.message);
    if (!summary && !handler.covered) {
      gaps.push({ target: handler.message, kind: 'webview_message', currentDepth: 'missing', recommendedNextStep: handler.note || 'Dispatch this handler from the E2E workflow.' });
    } else if (!summary) {
      gaps.push({ target: handler.message, kind: 'webview_message', currentDepth: 'observed-no-perf', recommendedNextStep: 'Add an explicit workflow step so this observed handler has its own perf span.' });
    } else if (DEPTH_RANK[summary.depth] < DEPTH_RANK.functional) {
      gaps.push({ target: handler.message, kind: 'webview_message', currentDepth: summary.depth, recommendedNextStep: 'Assert the emitted payload, generated artifact, or state change.' });
    }
  }
  return gaps.sort((left, right) => DEPTH_RANK[left.currentDepth] - DEPTH_RANK[right.currentDepth] || left.target.localeCompare(right.target));
}

function normalizeBackendName(name) {
  const value = String(name || '');
  const marker = `${path.sep}backends${path.sep}`;
  const normalized = path.normalize(value);
  if (normalized.startsWith(`backends${path.sep}`)) return normalized;
  const markerIndex = normalized.indexOf(marker);
  if (markerIndex >= 0) return normalized.slice(markerIndex + 1);
  if (path.isAbsolute(normalized)) {
    const relative = path.relative(extensionRoot, normalized);
    if (!relative.startsWith('..')) return relative;
  }
  return normalized;
}

function buildBackendSummary(auditEvents) {
  const counts = new Map();
  for (const event of auditEvents) {
    if (!['python', 'process'].includes(event.kind) || !event.name) continue;
    const name = normalizeBackendName(event.name);
    const key = `${event.kind}:${name}`;
    const current = counts.get(key) || {
      kind: event.kind,
      name,
      count: 0,
      failed: 0,
      totalDurationMs: 0,
      maxDurationMs: 0,
      maxStdoutBytes: 0,
      maxStderrBytes: 0,
      sources: new Set(),
    };
    const durationMs = Math.max(0, Number(event.durationMs || 0));
    current.count += 1;
    current.failed += event.ok === false ? 1 : 0;
    current.totalDurationMs += durationMs;
    current.maxDurationMs = Math.max(current.maxDurationMs, durationMs);
    current.maxStdoutBytes = Math.max(current.maxStdoutBytes, Number(event.stdoutBytes || 0));
    current.maxStderrBytes = Math.max(current.maxStderrBytes, Number(event.stderrBytes || 0));
    if (event.source) current.sources.add(event.source);
    counts.set(key, current);
  }
  return [...counts.values()]
    .map((entry) => ({
      ...entry,
      avgDurationMs: Math.round(entry.totalDurationMs / Math.max(1, entry.count)),
      totalDurationMs: Math.round(entry.totalDurationMs),
      sources: [...entry.sources].sort(),
    }))
    .sort((left, right) => (
      right.totalDurationMs - left.totalDurationMs
      || right.maxDurationMs - left.maxDurationMs
      || right.count - left.count
      || left.name.localeCompare(right.name)
    ));
}

function buildPayloadSignalSummary(auditEvents) {
  const byResponse = new Map();
  for (const event of auditEvents) {
    if (event.kind !== 'webview_post_message' || !event.name) continue;
    const current = byResponse.get(event.name) || {
      responseType: event.name,
      events: 0,
      errorEvents: 0,
      countFields: {},
      keys: new Set(),
    };
    current.events += 1;
    if (event.hasError || event.hasResultError || event.ok === false || event.resultOk === false) {
      current.errorEvents += 1;
    }
    if (Array.isArray(event.keys)) {
      for (const key of event.keys) current.keys.add(key);
    }
    for (const [key, value] of Object.entries(event)) {
      if (!key.endsWith('Count') || !Number.isFinite(value)) continue;
      current.countFields[key] = Math.max(current.countFields[key] || 0, value);
    }
    byResponse.set(event.name, current);
  }
  return [...byResponse.values()]
    .map((entry) => ({
      ...entry,
      keys: [...entry.keys].sort(),
    }))
    .sort((left, right) => right.events - left.events || left.responseType.localeCompare(right.responseType));
}

function buildFeatureAssertionMatrix(coverageReport, targetSummaries) {
  const byTarget = new Map(targetSummaries.map((entry) => [entry.target, entry]));
  const coveredByTarget = new Map(coverageReport.webviewHandlers.map((handler) => [handler.message, handler.covered]));
  return expectedFeatureRows(coverageReport.webviewHandlers.map((handler) => handler.message))
    .map((entry) => {
      const summary = byTarget.get(entry.target);
      const observed = Boolean(summary) || coveredByTarget.get(entry.target) === true;
      const responseValidated = (summary?.responseValidatedRuns || 0) > 0;
      const uiConsumed = (summary?.uiConsumedRuns || 0) > 0;
      const payloadValidated = (summary?.payloadValidatedRuns || 0) > 0;
      const businessAssertionRequired = Boolean(entry.businessAssertion);
      const missing = [];
      if (!observed) missing.push('observed');
      if (entry.expectedResponses.length && !responseValidated) missing.push('response');
      if (entry.requiresUiConsumed && !uiConsumed) missing.push('ui-consumed');
      if (businessAssertionRequired && !payloadValidated) missing.push('business-assertion');
      return {
        target: entry.target,
        observed,
        depth: summary?.depth || 'missing',
        runs: summary?.runs || 0,
        expectedResponses: entry.expectedResponses,
        responseValidated,
        uiConsumedExpected: entry.requiresUiConsumed,
        uiConsumed,
        payloadAssertions: entry.payloadAssertions,
        payloadValidated,
        businessAssertionRequired,
        businessAssertion: entry.businessAssertion,
        missing,
        nextStep: missing.includes('observed')
          ? 'Dispatch this handler from the E2E workflow and wrap it in a named perf scenario.'
          : (missing.includes('business-assertion')
          ? entry.businessAssertion
          : (missing.includes('ui-consumed')
            ? 'Make the UI-consumed acknowledgement deterministic for this flow.'
            : (missing.includes('response')
              ? 'Add the expected host->UI response type to the E2E wait map.'
              : 'No immediate assertion gap.'))),
      };
    })
    .sort((left, right) => (
      right.missing.length - left.missing.length
      || Number(right.businessAssertionRequired) - Number(left.businessAssertionRequired)
      || left.target.localeCompare(right.target)
    ));
}

function buildAuditReadiness({
  coverageReport,
  spans,
  targetSummaries,
  featureAssertions,
  payloadSignals,
  backendActivity,
  depthGaps,
  hostObservabilityGaps,
}) {
  const missingResponses = featureAssertions.filter((entry) => entry.missing.includes('response'));
  const missingUiConsumed = featureAssertions.filter((entry) => entry.missing.includes('ui-consumed'));
  const missingBusinessAssertions = featureAssertions.filter((entry) => entry.missing.includes('business-assertion'));
  const failedSpans = spans.filter((span) => !span.ok);
  const realCorpusScenarios = spans.filter((span) => span.fixtureKind === 'real-compiled');
  const summarizedTargets = new Set(targetSummaries.map((entry) => entry.target));
  const observedWithoutNamedPerf = [
    ...coverageReport.commands
      .filter((entry) => entry.covered && !summarizedTargets.has(entry.command))
      .map((entry) => entry.command),
    ...coverageReport.webviewHandlers
      .filter((entry) => entry.covered && !summarizedTargets.has(entry.message))
      .map((entry) => entry.message),
  ].sort();
  const gates = [
    {
      id: 'audit-events-present',
      label: 'Runtime audit events were captured',
      severity: 'blocking',
      ok: Boolean(coverageReport.auditEventsPath),
      details: coverageReport.auditEventsPath || '<missing>',
      nextStep: 'Enable Runtime Usage Audit and rerun the E2E workflow.',
    },
    {
      id: 'perf-events-present',
      label: 'Perf spans were captured for the workflow',
      severity: 'blocking',
      ok: spans.length > 0,
      details: `${spans.length} span(s)`,
      nextStep: 'Run through scripts/e2e/run-runtime-audit.js so POF_E2E_PERF_PATH is set.',
    },
    {
      id: 'command-coverage',
      label: 'All contributed commands are observed',
      severity: 'blocking',
      ok: coverageReport.summary.missingCommands === 0,
      details: `${coverageReport.summary.coveredCommands}/${coverageReport.summary.contributedCommands}`,
      nextStep: 'Add command scenarios in runtime-audit-suite.js for every missing command.',
    },
    {
      id: 'host-webview-coverage',
      label: 'All host webview handlers are observed',
      severity: 'blocking',
      ok: coverageReport.summary.missingHostWebviewHandlers === 0,
      details: `${coverageReport.summary.coveredHostWebviewHandlers}/${coverageReport.summary.hostWebviewHandlers}`,
      nextStep: 'Dispatch each missing handler through pileOuFace.e2eDispatchHubMessage.',
    },
    {
      id: 'scenario-success',
      label: 'Every named workflow scenario completed',
      severity: 'blocking',
      ok: failedSpans.length === 0,
      details: `${failedSpans.length} failed / ${spans.length} total`,
      nextStep: 'Fix the failing wait/assertion before trusting coverage numbers.',
    },
    {
      id: 'response-assertions',
      label: 'Expected backend/UI responses are validated',
      severity: 'blocking',
      ok: missingResponses.length === 0,
      details: `${missingResponses.length} missing response assertion(s)`,
      nextStep: 'Add expected response types to the wait map or dispatch a deeper scenario.',
    },
    {
      id: 'ui-consumed-assertions',
      label: 'UI consumption is validated where required',
      severity: 'blocking',
      ok: missingUiConsumed.length === 0,
      details: `${missingUiConsumed.length} missing UI-consumed assertion(s)`,
      nextStep: 'Wait for hubUiConsumed acknowledgements for UI-rendered flows.',
    },
    {
      id: 'business-payload-assertions',
      label: 'Business payload assertions are present',
      severity: 'blocking',
      ok: missingBusinessAssertions.length === 0,
      details: `${missingBusinessAssertions.length} missing business assertion(s)`,
      nextStep: 'Add PAYLOAD_ASSERTIONS_BY_MESSAGE entries for feature-level payload checks.',
    },
    {
      id: 'backend-activity-present',
      label: 'Backend activity is visible in the audit',
      severity: 'blocking',
      ok: backendActivity.length > 0,
      details: `${backendActivity.length} backend target(s)`,
      nextStep: 'Run fixture-backed flows that execute Python/process backends.',
    },
    {
      id: 'payload-signals-present',
      label: 'Host response payload shapes are summarized',
      severity: 'advisory',
      ok: payloadSignals.length > 0,
      details: `${payloadSignals.length} response type(s)`,
      nextStep: 'Add payload assertions for the highest-value handlers first.',
    },
    {
      id: 'real-corpus-present',
      label: 'Real compiled binaries are included',
      severity: 'advisory',
      ok: realCorpusScenarios.length > 0,
      details: `${realCorpusScenarios.length} real corpus scenario(s)`,
      nextStep: 'Run with POF_E2E_REAL_CORPUS=1 or POF_E2E_FIXTURE_PATHS for user binaries.',
    },
    {
      id: 'depth-backlog-empty',
      label: 'No remaining shallow coverage depth backlog',
      severity: 'advisory',
      ok: depthGaps.length === 0,
      details: `${depthGaps.length} depth gap(s)`,
      nextStep: 'Promote smoke-only handlers into functional/integration scenarios.',
    },
    {
      id: 'host-observability-gaps',
      label: 'Host-only UI/log effects are observable',
      severity: 'advisory',
      ok: hostObservabilityGaps.length === 0,
      details: `${hostObservabilityGaps.length} host observability gap(s)`,
      nextStep: 'Add explicit test seams or audit events for host-only UI/log side effects.',
    },
    {
      id: 'target-perf-spans',
      label: 'Observed targets have named perf summaries',
      severity: 'advisory',
      ok: observedWithoutNamedPerf.length === 0,
      details: `${observedWithoutNamedPerf.length} observed target(s) without named span`,
      nextStep: 'Wrap observed-but-unnamed paths in startPerfSampler spans.',
    },
  ];
  const failedBlocking = gates.filter((gate) => gate.severity === 'blocking' && !gate.ok);
  const failedAdvisory = gates.filter((gate) => gate.severity === 'advisory' && !gate.ok);
  return {
    status: failedBlocking.length ? 'fail' : (failedAdvisory.length ? 'pass-with-advisories' : 'pass'),
    failedBlocking: failedBlocking.length,
    failedAdvisory: failedAdvisory.length,
    gates,
  };
}

function scenarioRecipeForBacklogItem(item) {
  if (item.reason === 'perf-hotspot') {
    return {
      scenario: item.scenario || `hub-handler:${item.target}`,
      file: '.pile-ou-face/test-artifacts/e2e-runtime-audit/runtime-audit-workflow-report.md',
      sketch: 'Use perfPriority, runtimeOperationHotspots, and perfStepBreakdown for this existing workflow before deciding on a product optimization.',
    };
  }
  if (item.kind === 'webview_message') {
    return {
      scenario: `hub-handler:${item.target}`,
      file: 'scripts/e2e/runtime-audit-suite.js',
      sketch: `dispatchHubMessageAndWaitForResponses(userDataDir, { type: '${item.target}', ...payload }, responseTypesForMessage('${item.target}'), { requireUiConsumed: requiresUiConsumed('${item.target}'), payloadAssertions: payloadAssertionsForMessage('${item.target}') })`,
    };
  }
  return {
    scenario: `command:${item.target}`,
    file: 'scripts/e2e/runtime-audit-suite.js',
    sketch: `executeCommand('${item.target}') then waitForCommandAudit(userDataDir, '${item.target}') and assert the visible result/artifact`,
  };
}

function buildNextScenarioBacklog({ featureAssertions, depthGaps, hostObservabilityGaps, perfPriorities }) {
  const items = [];
  const seen = new Set();
  const push = (item) => {
    const key = `${item.reason}:${item.target}`;
    if (seen.has(key)) return;
    seen.add(key);
    items.push({ ...item, recipe: scenarioRecipeForBacklogItem(item) });
  };

  for (const entry of featureAssertions.filter((item) => item.missing.length)) {
    push({
      priority: entry.missing.includes('observed') ? 'P0' : 'P1',
      reason: entry.missing.join(','),
      target: entry.target,
      kind: 'webview_message',
      currentDepth: entry.depth,
      nextStep: entry.nextStep,
    });
  }

  for (const gap of depthGaps) {
    push({
      priority: gap.currentDepth === 'missing' ? 'P0' : (gap.currentDepth === 'observed-no-perf' ? 'P1' : 'P2'),
      reason: 'depth',
      target: gap.target,
      kind: gap.kind,
      currentDepth: gap.currentDepth,
      nextStep: gap.recommendedNextStep,
    });
  }

  for (const gap of hostObservabilityGaps) {
    push({
      priority: 'P2',
      reason: 'host-observability',
      target: gap.target,
      kind: gap.kind,
      currentDepth: gap.currentDepth,
      nextStep: gap.recommendedNextStep,
    });
  }

  for (const hotspot of perfPriorities.slice(0, 15)) {
    push({
      priority: hotspot.priority,
      reason: 'perf-hotspot',
      target: hotspot.target,
      kind: hotspot.scenario.startsWith('hub-handler:') ? 'webview_message' : 'command',
      scenario: hotspot.scenario,
      currentDepth: 'observed',
      nextStep: `${hotspot.category}: ${hotspot.evidence}. ${hotspot.recommendation}`,
    });
  }

  return items.sort((left, right) => (
    PERF_PRIORITY_RANK[left.priority] - PERF_PRIORITY_RANK[right.priority]
    || left.target.localeCompare(right.target)
  ));
}

function buildReport() {
  const coverageReport = buildCoverageReport();
  const perfPath = latestPerfPath();
  const auditPath = latestAuditEventsPath();
  const perfEvents = readJsonl(perfPath);
  const auditEvents = readAuditEvents(auditPath);
  const spans = summarizePerf(perfEvents);
  const targetSummaries = groupByTarget(spans);
  const payloadSignals = buildPayloadSignalSummary(auditEvents);
  const featureAssertions = buildFeatureAssertionMatrix(coverageReport, targetSummaries);
  const failedSpans = spans.filter((span) => !span.ok);
  const optimizationCandidates = buildOptimizationCandidates(spans);
  const runtimeOperationHotspots = buildRuntimeOperationHotspots(spans);
  const perfPriorities = buildPerfPriorities(runtimeOperationHotspots, optimizationCandidates);
  const perfStepBreakdown = buildPerfStepBreakdown(auditEvents, spans);
  const rawDepthGaps = buildDepthGaps(coverageReport, targetSummaries);
  const hostObservabilityGaps = rawDepthGaps
    .filter((gap) => HOST_OBSERVABILITY_GAP_NOTES[gap.target])
    .map((gap) => ({
      ...gap,
      recommendedNextStep: HOST_OBSERVABILITY_GAP_NOTES[gap.target],
    }));
  const depthGaps = rawDepthGaps.filter((gap) => !HOST_OBSERVABILITY_GAP_NOTES[gap.target]);
  const backendActivity = buildBackendSummary(auditEvents);
  const readiness = buildAuditReadiness({
    coverageReport,
    spans,
    targetSummaries,
    featureAssertions,
    payloadSignals,
    backendActivity,
    depthGaps,
    hostObservabilityGaps,
  });
  const nextScenarioBacklog = buildNextScenarioBacklog({
    featureAssertions,
    depthGaps,
    hostObservabilityGaps,
    perfPriorities,
  });

  return {
    generatedAt: new Date().toISOString(),
    auditEventsPath: auditPath,
    perfEventsPath: perfPath,
    summary: {
      commandCoverage: `${coverageReport.summary.coveredCommands}/${coverageReport.summary.contributedCommands}`,
      commandCoveragePercent: coverageReport.summary.coveragePercent,
      hostWebviewCoverage: `${coverageReport.summary.coveredHostWebviewHandlers}/${coverageReport.summary.hostWebviewHandlers}`,
      hostWebviewCoveragePercent: coverageReport.summary.hostWebviewCoveragePercent,
      scenarios: spans.length,
      failedScenarios: failedSpans.length,
      responseValidatedScenarios: spans.filter((span) => span.responseValidated).length,
      uiConsumedScenarios: spans.filter((span) => span.uiConsumed).length,
      payloadValidatedScenarios: spans.filter((span) => span.payloadValidated).length,
      featureAssertionTargets: featureAssertions.length,
      featureAssertionGaps: featureAssertions.filter((entry) => entry.missing.length).length,
      businessAssertionGaps: featureAssertions.filter((entry) => entry.missing.includes('business-assertion')).length,
      auditReadiness: readiness.status,
      readinessBlockingFailures: readiness.failedBlocking,
      readinessAdvisoryFailures: readiness.failedAdvisory,
      nextScenarioBacklog: nextScenarioBacklog.length,
      auditedTargets: targetSummaries.length,
      optimizationCandidates: optimizationCandidates.length,
      runtimeOperationHotspots: runtimeOperationHotspots.length,
      perfPriorities: perfPriorities.length,
      perfStepBreakdown: perfStepBreakdown.length,
      topPerfPriority: perfPriorities[0]?.priority || '',
      depthGaps: depthGaps.length,
      hostObservabilityGaps: hostObservabilityGaps.length,
    },
    scenarios: spans,
    targets: targetSummaries,
    readiness,
    nextScenarioBacklog,
    featureAssertions,
    payloadSignals,
    perfPriorities,
    perfStepBreakdown,
    optimizationCandidates,
    runtimeOperationHotspots,
    depthGaps,
    hostObservabilityGaps,
    backendActivity,
  };
}

function formatBytes(value) {
  if (Math.abs(value) < 1024 * 1024) {
    return `${Math.round((value / 1024) * 10) / 10} KB`;
  }
  return `${mb(value)} MB`;
}

function markdownForReport(report) {
  const lines = [
    '# Runtime Audit Workflow Report',
    '',
    `Generated: ${report.generatedAt}`,
    report.auditEventsPath ? `Runtime audit events: ${report.auditEventsPath}` : 'Runtime audit events: <not found>',
    report.perfEventsPath ? `Perf events: ${report.perfEventsPath}` : 'Perf events: <not found>',
    '',
    '## Summary',
    '',
    `- Command coverage: ${report.summary.commandCoverage} (${report.summary.commandCoveragePercent}%)`,
    `- Host webview handler coverage: ${report.summary.hostWebviewCoverage} (${report.summary.hostWebviewCoveragePercent}%)`,
    `- Workflow scenarios: ${report.summary.scenarios}`,
    `- Audited targets: ${report.summary.auditedTargets}`,
    `- Failed scenarios: ${report.summary.failedScenarios}`,
    `- Response-validated scenarios: ${report.summary.responseValidatedScenarios}`,
    `- UI-consumed scenarios: ${report.summary.uiConsumedScenarios}`,
    `- Payload-validated scenarios: ${report.summary.payloadValidatedScenarios}`,
    `- Feature assertion gaps: ${report.summary.featureAssertionGaps}/${report.summary.featureAssertionTargets}`,
    `- Business assertion gaps: ${report.summary.businessAssertionGaps}`,
    `- Audit readiness: ${report.summary.auditReadiness} (${report.summary.readinessBlockingFailures} blocking, ${report.summary.readinessAdvisoryFailures} advisory)`,
    `- Next scenario backlog: ${report.summary.nextScenarioBacklog}`,
    `- Optimization candidates: ${report.summary.optimizationCandidates}`,
    `- Runtime operation hotspots: ${report.summary.runtimeOperationHotspots}`,
    `- Perf priorities: ${report.summary.perfPriorities}${report.summary.topPerfPriority ? ` (top ${report.summary.topPerfPriority})` : ''}`,
    `- Perf step breakdown rows: ${report.summary.perfStepBreakdown}`,
    `- Depth gaps: ${report.summary.depthGaps}`,
    `- Host observability gaps: ${report.summary.hostObservabilityGaps}`,
    '',
    '## Audit Readiness',
    '',
  ];

  for (const gate of report.readiness.gates) {
    lines.push(`- ${gate.ok ? 'OK' : 'FAIL'} [${gate.severity}] ${gate.label}: ${gate.details}${gate.ok ? '' : `. Next: ${gate.nextStep}`}`);
  }

  lines.push(
    '',
    '## Next Scenario Backlog',
    ''
  );
  if (!report.nextScenarioBacklog.length) {
    lines.push('- <none>');
  } else {
    for (const item of report.nextScenarioBacklog.slice(0, 30)) {
      lines.push(`- ${item.priority} \`${item.target}\` (${item.reason}, ${item.currentDepth}): ${item.nextStep}`);
      const action = item.reason === 'perf-hotspot' ? 'Inspect' : 'Add';
      lines.push(`  - ${action} \`${item.recipe.scenario}\` in \`${item.recipe.file}\`: ${item.recipe.sketch}`);
    }
  }

  lines.push(
    '',
    '## Perf Priority Triage',
    '',
  );

  const priorities = report.perfPriorities.slice(0, 15);
  if (!priorities.length) {
    lines.push('- <none>');
  } else {
    for (const item of priorities) {
      const repeats = item.repeatedNames
        .slice(0, 3)
        .map(operationLabel)
        .join(', ');
      const reasons = item.optimizationReasons.length ? `, candidate=${item.optimizationReasons.join('+')}` : '';
      lines.push(`- ${item.priority} \`${item.scenario}\` [${item.category}] priority=${item.priorityScore}, runtime=${item.runtimeScore}, duration=${item.durationMs} ms${reasons}`);
      lines.push(`  Evidence: ${item.evidence}; events=${item.totalEvents}, scored-events=${item.scoredEvents}, uiAck=${item.uiAckCalls}, python=${item.pythonCalls}, process=${item.processCalls}, webview in/out=${item.webviewInbound}/${item.webviewOutbound}, max-repeat=${item.maxRepeated}${repeats ? `, repeats=[${repeats}]` : ''}`);
      lines.push(`  Next: ${item.recommendation}`);
    }
  }

  lines.push('', '## Perf Step Breakdown', '');
  const perfSteps = report.perfStepBreakdown.slice(0, 25);
  if (!perfSteps.length) {
    lines.push('- <none>');
  } else {
    for (const item of perfSteps) {
      const binaries = item.binaryNames.length ? `, binaries=[${item.binaryNames.slice(0, 3).join(', ')}]` : '';
      lines.push(`- \`${item.scenario}\` / \`${item.step}\`: max ${item.maxDurationMs} ms, avg ${item.avgDurationMs} ms, total ${item.totalDurationMs} ms, count=${item.count}${binaries}`);
    }
  }

  lines.push(
    '',
    '## Optimization Candidates',
    '',
  );

  const candidates = report.optimizationCandidates.slice(0, 15);
  if (!candidates.length) {
    lines.push('- <none>');
  } else {
    for (const item of candidates) {
      lines.push(`- \`${item.scenario}\` (${item.reasons.join(', ')}): ${item.durationMs} ms, RSS peak +${formatBytes(item.rssPeakDelta)}, heap peak +${formatBytes(item.heapPeakDelta)}`);
    }
  }

  lines.push('', '## Runtime Operation Hotspots', '');
  const operationHotspots = report.runtimeOperationHotspots.slice(0, 20);
  if (!operationHotspots.length) {
    lines.push('- <none>');
  } else {
    for (const item of operationHotspots) {
      const repeats = item.repeatedNames
        .slice(0, 3)
        .map((entry) => `${entry.kind}:${entry.name} x${entry.count}`)
        .join(', ');
      const top = item.topNames
        .slice(0, 3)
        .map((entry) => `${entry.kind}:${entry.name} x${entry.count}`)
        .join(', ');
      lines.push(`- \`${item.scenario}\`: score=${item.score}, total=${item.totalEvents}, scored=${item.scoredEvents}, uiAck=${item.uiAckCalls}, python=${item.pythonCalls}, process=${item.processCalls}, webview in/out=${item.webviewInbound}/${item.webviewOutbound}, max-repeat=${item.maxRepeated}, ${repeats ? `repeats=[${repeats}]` : `top=[${top}]`}`);
    }
  }

  lines.push('', '## Feature Assertion Matrix', '');
  const assertionGaps = report.featureAssertions.filter((entry) => entry.missing.length).slice(0, 50);
  if (!assertionGaps.length) {
    lines.push('- <none>');
  } else {
    for (const item of assertionGaps) {
      const checks = [
        item.expectedResponses.length ? `response=${item.responseValidated ? 'ok' : 'missing'}` : 'response=n/a',
        item.uiConsumedExpected ? `ui=${item.uiConsumed ? 'ok' : 'missing'}` : 'ui=n/a',
        item.businessAssertionRequired ? `payload=${item.payloadValidated ? 'ok' : 'missing'}` : 'payload=n/a',
        item.businessAssertionRequired ? `business=${item.payloadValidated ? 'ok' : 'missing'}` : 'business=n/a',
      ].join(', ');
      lines.push(`- \`${item.target}\` [${item.depth}] ${checks}. Next: ${item.nextStep}`);
    }
  }

  lines.push('', '## Response Payload Signals', '');
  const payloadSignals = report.payloadSignals
    .filter((entry) => entry.keys.length || Object.keys(entry.countFields).length || entry.errorEvents)
    .slice(0, 40);
  if (!payloadSignals.length) {
    lines.push('- <none>');
  } else {
    for (const item of payloadSignals) {
      const counts = Object.entries(item.countFields)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, value]) => `${key}<=${value}`)
        .join(', ');
      const keys = item.keys.slice(0, 8).join(', ');
      lines.push(`- \`${item.responseType}\`: ${item.events} event(s), errors=${item.errorEvents}${counts ? `, ${counts}` : ''}${keys ? `, keys=[${keys}]` : ''}`);
    }
  }

  lines.push('', '## Target Perf Summary', '');
  for (const item of report.targets.slice(0, 40)) {
    lines.push(`- \`${item.target}\` [${item.depth}] ${item.runs} run(s), ${item.responseValidatedRuns} response-validated, ${item.uiConsumedRuns} UI-consumed, ${item.payloadValidatedRuns} payload-validated, max ${item.maxDurationMs} ms, RSS peak +${formatBytes(item.maxRssPeakDelta)}, heap peak +${formatBytes(item.maxHeapPeakDelta)}`);
  }

  const fixtureScenarios = report.scenarios.filter((item) => item.fixture);
  if (fixtureScenarios.length) {
    lines.push('', '## Tested Binaries', '');
    for (const item of fixtureScenarios) {
      const tags = [
        item.fixtureKind,
        item.compiler,
        item.opt,
        item.arch,
        item.stripped ? 'stripped' : '',
      ].filter(Boolean).join(', ');
      lines.push(`- \`${item.fixture}\`: ${formatBytes(item.sizeBytes)}${tags ? ` (${tags})` : ''}, scenario \`${item.scenario}\``);
    }
  }

  lines.push('', '## Coverage Depth Gaps', '');
  if (!report.depthGaps.length) {
    lines.push('- <none>');
  } else {
    for (const gap of report.depthGaps.slice(0, 40)) {
      lines.push(`- \`${gap.target}\` [${gap.currentDepth}] ${gap.recommendedNextStep}`);
    }
  }

  lines.push('', '## Host Observability Gaps', '');
  if (!report.hostObservabilityGaps.length) {
    lines.push('- <none>');
  } else {
    for (const gap of report.hostObservabilityGaps.slice(0, 40)) {
      lines.push(`- \`${gap.target}\` [${gap.currentDepth}] ${gap.recommendedNextStep}`);
    }
  }

  lines.push('', '## Backend Activity', '');
  if (!report.backendActivity.length) {
    lines.push('- <none>');
  } else {
    for (const item of report.backendActivity.slice(0, 20)) {
      const duration = item.totalDurationMs
        ? `, total=${item.totalDurationMs} ms, max=${item.maxDurationMs} ms, avg=${item.avgDurationMs} ms`
        : '';
      const outputs = item.maxStdoutBytes || item.maxStderrBytes
        ? `, stdout<=${item.maxStdoutBytes}B, stderr<=${item.maxStderrBytes}B`
        : '';
      const failures = item.failed ? `, failed=${item.failed}` : '';
      lines.push(`- \`${item.kind}:${item.name}\` ${item.count} event(s)${duration}${failures}${outputs}${item.sources.length ? ` via ${item.sources.join(', ')}` : ''}`);
    }
  }

  lines.push(
    '',
    '## Workflow Use',
    '',
    '1. Run `npm run test:e2e:audit`.',
    '2. Open this report first for optimization and missing-depth decisions.',
    '3. Open `runtime-audit-feature-coverage.md` for the raw command/handler inventory.',
    '4. Add missing or shallow flows in `scripts/e2e/runtime-audit-suite.js`, then rerun the audit.',
    ''
  );

  return `${lines.join('\n')}\n`;
}

function main() {
  const report = buildReport();
  fs.mkdirSync(artifactsDir, { recursive: true });
  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(markdownPath, markdownForReport(report));
  console.log(`Workflow audit report: ${markdownPath}`);
  console.log(`Workflow audit scenarios: ${report.summary.scenarios}, targets: ${report.summary.auditedTargets}, optimization candidates: ${report.summary.optimizationCandidates}`);
}

if (require.main === module) {
  main();
}

module.exports = {
  buildReport,
  buildFeatureAssertionMatrix,
  buildPayloadSignalSummary,
  summarizePerf,
};
