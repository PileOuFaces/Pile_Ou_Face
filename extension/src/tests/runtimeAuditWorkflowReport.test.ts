const { expect } = require('chai');

const {
  buildPerfStepBreakdown,
  countAnnotationDisasmRebuilds,
  markdownForReport,
} = require('../../scripts/e2e/runtime-audit-workflow-report');

describe('runtime audit workflow report', () => {
  it('classifies annotation-driven disasm rebuilds separately from generic cache misses', () => {
    const spans = [{
      scenario: 'hub-handler:hubSaveAnnotation',
      target: 'hubSaveAnnotation',
      startTs: '2026-07-17T10:00:00.000Z',
      stopTs: '2026-07-17T10:00:02.000Z',
    }];
    const auditEvents = [{
      kind: 'perf_step',
      name: 'hubOpenDisasm.ensureDisasmArtifacts',
      ts: '2026-07-17T10:00:01.000Z',
      durationMs: 320,
      source: 'hubOpenDisasm',
      binaryName: 'fixture.elf',
      rebuildReason: 'annotation-overlay',
    }];

    const breakdown = buildPerfStepBreakdown(auditEvents, spans);

    expect(breakdown).to.have.length(1);
    expect(breakdown[0].rebuildReasons).to.deep.equal(['annotation-overlay']);
    expect(countAnnotationDisasmRebuilds(breakdown)).to.equal(1);
  });

  it('prints annotation-sensitive disasm rebuilds in the markdown summary and breakdown', () => {
    const markdown = markdownForReport({
      generatedAt: '2026-07-17T10:00:00.000Z',
      auditEventsPath: '/tmp/audit.jsonl',
      perfEventsPath: '/tmp/perf.jsonl',
      summary: {
        commandCoverage: '18/18',
        commandCoveragePercent: 100,
        hostWebviewCoverage: '102/102',
        hostWebviewCoveragePercent: 100,
        scenarios: 1,
        auditedTargets: 1,
        failedScenarios: 0,
        responseValidatedScenarios: 1,
        uiConsumedScenarios: 1,
        payloadValidatedScenarios: 1,
        featureAssertionGaps: 0,
        featureAssertionTargets: 1,
        businessAssertionGaps: 0,
        auditReadiness: 'ready',
        readinessBlockingFailures: 0,
        readinessAdvisoryFailures: 0,
        nextScenarioBacklog: 0,
        optimizationCandidates: 0,
        runtimeOperationHotspots: 0,
        perfPriorities: 0,
        topPerfPriority: '',
        perfStepBreakdown: 1,
        annotationDisasmRebuilds: 1,
        backendScenarioHotspots: 0,
        performanceBudgetSignals: 0,
        performanceBudgetFailCandidates: 0,
        depthGaps: 0,
        hostObservabilityGaps: 0,
      },
      readiness: { gates: [] },
      nextScenarioBacklog: [],
      perfPriorities: [],
      performanceBudgetSignals: [],
      perfStepBreakdown: [{
        scenario: 'hub-handler:hubSaveAnnotation',
        step: 'hubOpenDisasm.ensureDisasmArtifacts',
        maxDurationMs: 320,
        avgDurationMs: 320,
        totalDurationMs: 320,
        count: 1,
        binaryNames: ['fixture.elf'],
        rebuildReasons: ['annotation-overlay'],
      }],
      optimizationCandidates: [],
      backendScenarioHotspots: [],
      runtimeOperationHotspots: [],
      featureAssertions: [],
      payloadSignals: [],
      targets: [],
      scenarios: [],
      depthGaps: [],
      hostObservabilityGaps: [],
      backendActivity: [],
    });

    expect(markdown).to.include('- Annotation-sensitive disasm rebuilds: 1');
    expect(markdown).to.include('rebuildReasons=[annotation-overlay]');
  });
});
