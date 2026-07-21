// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('fs');
const path = require('path');

const extensionRoot = path.resolve(__dirname, '..', '..');
const packageJsonPath = path.join(extensionRoot, 'package.json');
const suitePath = path.join(__dirname, 'runtime-audit-suite.js');
const artifactsDir = path.join(extensionRoot, '.pile-ou-face', 'test-artifacts', 'e2e-runtime-audit');
const jsonPath = path.join(artifactsDir, 'runtime-audit-feature-coverage.json');
const markdownPath = path.join(artifactsDir, 'runtime-audit-feature-coverage.md');
const HOST_HANDLER_FILES = [
  'src/static/hub/actions.ts',
  'src/static/hub/graphRenderers.ts',
  'src/static/hub/loaders.ts',
  'src/static/hub/navigation.ts',
  'src/static/hub/traceHistory.ts',
  'src/static/staticHandlers.ts',
  'src/shared/sharedHandlers.ts',
];
const INTERNAL_E2E_COMMANDS = new Set(['pileOuFace.e2eDispatchHubMessage']);

const COMMAND_NOTES = {
  'pileOuFace.open': 'Hub startup and runtime audit boot path.',
  'pileOuFace.goToSymbolInDisasm': 'Static disassembly command over generated ELF fixtures.',
  'pileOuFace.sidebarRefresh': 'Requires input box mocking or command args support.',
  'pileOuFace.calculator': 'Requires input box mocking and webview assertion.',
  'pileOuFace.xrefsTo': 'Requires an active disassembly editor and mapping file.',
  'pileOuFace.xrefsFrom': 'Requires an active disassembly editor and mapping file.',
  'pileOuFace.askAiAboutDisasm': 'Requires active ASM editor selection and AI prompt assertion.',
  'pileOuFace.exportDisasm': 'Requires save dialog mocking.',
  'pileOuFace.disasmSection': 'Can be covered with generated fixture and section name.',
  'pileOuFace.goToAddress': 'Opens hub with go-to-address focus.',
  'pileOuFace.decompilerAdd': 'Mutating wizard; keep as manual until dialog mocking is introduced.',
  'pileOuFace.decompilerEdit': 'Mutating wizard; keep as manual until dialog mocking is introduced.',
  'pileOuFace.decompilerRemove': 'Mutating wizard; keep as manual until dialog mocking is introduced.',
  'pileOuFace.decompilerList': 'Can be covered by asserting backend list command/process audit.',
  'pileOuFace.decompilerTest': 'Requires test decompiler config fixture.',
  'pileOuFace.decompilerOpenConfig': 'Can be covered by asserting decompilers.json opens.',
  'pileOuFace.showLogs': 'Can be covered by command audit only.',
  'pileOuFace.perfSnapshot': 'Requires enabling pileOuFace.perfDiagnostics in test settings.',
};

const WEBVIEW_HANDLER_NOTES = {
  hubLoadAnnotations: 'Annotation load flow.',
  hubSaveAnnotation: 'Annotation save flow.',
  hubDeleteAnnotation: 'Annotation delete flow.',
  hubLoadCfg: 'CFG backend renderer.',
  hubLoadCallGraph: 'Call graph backend renderer.',
  hubLoadFunctions: 'Functions/radar/calling-convention backend flow.',
  hubLoadHexView: 'Hex view backend flow.',
  hubLoadImports: 'Imports backend flow.',
  hubLoadExports: 'Exports backend flow.',
  hubLoadPluginState: 'Plugin discovery/state flow.',
  hubRequestRecentBinaries: 'Recent binaries state flow.',
  listGeneratedFiles: 'Generated artifacts listing flow.',
  getPlatform: 'Platform/bootstrap flow.',
  compilerListRequest: 'Static compiler discovery flow.',
  'pof.auth.getState': 'Account/auth state flow.',
  hubBrowseImportRule: 'Interactive file picker; cover with dialog mocking or fixture import hook.',
  hubInstallDecompiler: 'Interactive/developer setup flow; keep out of smoke until dialog mocking exists.',
  hubInstallPlugin: 'Interactive install flow; requires plugin package fixture and dialog mocking.',
  hubOpenPluginDirectory: 'Opens a folder in the OS; avoid in automated smoke.',
  hubPickFile: 'Interactive file picker; cover with dialog mocking.',
  hubPullDecompilerImage: 'Docker/network flow; keep outside default E2E smoke.',
  hubLoadDecompile: 'Decompiler execution; requires deterministic local/docker backend fixture.',
  hubPluginInvoke: 'Plugin runtime flow; requires installed plugin fixture.',
  runTrace: 'Dynamic trace backend flow; requires dynamic binary/payload fixture.',
  hubCompileStaticBinary: 'Compiler toolchain flow; requires gcc/toolchain assumptions.',
  hubExportCfgSvg: 'Export/write artifact flow; needs generated CFG state.',
  hubExportDisasm: 'Export/write artifact flow; needs generated disasm state.',
  hubExportConversation: 'Export/write artifact flow; needs AI conversation state.',
  hubExportData: 'Export/write artifact flow; needs populated panel state.',
  hubPatchBytes: 'Mutating binary flow; should use a disposable copy fixture.',
  hubRedoPatch: 'Patch history mutation; should follow a patch fixture.',
  hubRevertPatch: 'Patch history mutation; should follow a patch fixture.',
  hubRevertAllPatches: 'Patch history mutation; should follow a patch fixture.',
  hubAiProviderSet: 'Writes provider settings/secrets; requires isolated secrets fixture.',
  hubAiProviderDefaultSet: 'Writes provider settings; safe only with isolated settings fixture.',
  hubAiProviderPrompt: 'AI provider prompt flow; requires provider fixture/mocking.',
  hubAiProviderTest: 'Provider test flow; requires provider fixture/mocking.',
  hubAiCancel: 'Requires active AI request.',
  hubOllamaPrompt: 'External Ollama flow; requires service fixture/mocking.',
  hubOllamaModelSelected: 'Settings flow; can be covered with isolated settings fixture.',
  'pof.auth.login': 'Network/auth flow; requires mocked auth server.',
  'pof.auth.logout': 'Auth state flow.',
  clearDynamicTraceHistory: 'Dynamic trace history flow.',
  deleteDynamicTraceHistory: 'Dynamic trace history flow.',
  openDynamicTraceHistory: 'Dynamic trace history flow.',
};

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function contributedCommands(packageJson) {
  const commands = packageJson.contributes?.commands || [];
  return [...new Set(commands.map((entry) => entry.command).filter((id) => id?.startsWith('pileOuFace.')))].sort();
}

function auditedCommandsFromSuite(source) {
  const commandIds = new Set();
  const commandPattern = /['"`](pileOuFace\.[A-Za-z0-9_.-]+)['"`]/g;
  let match = commandPattern.exec(source);
  while (match) {
    commandIds.add(match[1]);
    match = commandPattern.exec(source);
  }
  return [...commandIds].sort();
}

function latestAuditEventsPath() {
  if (process.env.POF_E2E_AUDIT_EVENTS_PATH && fs.existsSync(process.env.POF_E2E_AUDIT_EVENTS_PATH)) {
    return process.env.POF_E2E_AUDIT_EVENTS_PATH;
  }
  if (!fs.existsSync(artifactsDir)) return '';
  const files = fs.readdirSync(artifactsDir)
    .filter((name) => /^audit-runtime-usage-.*\.jsonl$/.test(name))
    .map((name) => path.join(artifactsDir, name))
    .filter((filePath) => fs.statSync(filePath).isFile())
    .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs);
  return files[0] || '';
}

function readAuditEvents(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function observedByKind(events, kind) {
  return [...new Set(events
    .filter((event) => event.kind === kind && event.name)
    .map((event) => String(event.name)))].sort();
}

function discoverHostWebviewHandlers() {
  const handlers = new Set(['hubReady', 'runTrace']);
  const handlerPattern = /^\s{4}(?:['"]([^'"]+)['"]|([A-Za-z][A-Za-z0-9_]*))\s*:\s*(?:async\b|\([^)]*\)\s*=>|[^,]*=>)/gm;
  for (const relativePath of HOST_HANDLER_FILES) {
    const filePath = path.join(extensionRoot, relativePath);
    if (!fs.existsSync(filePath)) continue;
    const source = fs.readFileSync(filePath, 'utf8');
    let match = handlerPattern.exec(source);
    while (match) {
      const name = match[1] || match[2];
      if (
        name.startsWith('hub')
        || name.startsWith('pof.auth.')
        || name === 'getPlatform'
        || name === 'listGeneratedFiles'
        || name === 'compilerListRequest'
        || name === 'requestDynamicTraceHistory'
        || name === 'openDynamicTraceHistory'
        || name === 'deleteDynamicTraceHistory'
        || name === 'clearDynamicTraceHistory'
      ) {
        handlers.add(name);
      }
      match = handlerPattern.exec(source);
    }
  }
  return [...handlers].sort();
}

function scenarioForCommand(commandId, suiteSource) {
  const commandIndex = suiteSource.indexOf(commandId);
  if (commandIndex < 0) return '';
  const before = suiteSource.slice(0, commandIndex);
  const testMatch = [...before.matchAll(/new Mocha\.Test\('([^']+)'/g)].pop();
  return testMatch?.[1] || '';
}

function buildReport() {
  const packageJson = readJson(packageJsonPath);
  const suiteSource = fs.readFileSync(suitePath, 'utf8');
  const auditEventsPath = latestAuditEventsPath();
  const auditEvents = readAuditEvents(auditEventsPath);
  const observedCommands = observedByKind(auditEvents, 'command').filter((command) => !INTERNAL_E2E_COMMANDS.has(command));
  const observedWebviewMessages = observedByKind(auditEvents, 'webview_message');
  const contributed = contributedCommands(packageJson);
  const suiteAuditedCommands = auditedCommandsFromSuite(suiteSource).filter((command) => !INTERNAL_E2E_COMMANDS.has(command));
  const auditedSet = new Set([...suiteAuditedCommands, ...observedCommands]);
  const commands = contributed.map((command) => ({
    command,
    covered: auditedSet.has(command),
    scenario: scenarioForCommand(command, suiteSource),
    note: COMMAND_NOTES[command] || '',
  }));
  const covered = commands.filter((entry) => entry.covered);
  const missing = commands.filter((entry) => !entry.covered);
  const unknownAudited = [...new Set([...suiteAuditedCommands, ...observedCommands])]
    .filter((command) => !contributed.includes(command))
    .sort();
  const webviewHandlers = discoverHostWebviewHandlers().map((message) => ({
    message,
    covered: observedWebviewMessages.includes(message),
    note: WEBVIEW_HANDLER_NOTES[message] || '',
  }));
  const coveredWebviewHandlers = webviewHandlers.filter((entry) => entry.covered);
  const missingWebviewHandlers = webviewHandlers.filter((entry) => !entry.covered);

  return {
    generatedAt: new Date().toISOString(),
    auditEventsPath,
    summary: {
      contributedCommands: contributed.length,
      coveredCommands: covered.length,
      missingCommands: missing.length,
      coveragePercent: contributed.length ? Math.round((covered.length / contributed.length) * 100) : 100,
      hostWebviewHandlers: webviewHandlers.length,
      coveredHostWebviewHandlers: coveredWebviewHandlers.length,
      missingHostWebviewHandlers: missingWebviewHandlers.length,
      hostWebviewCoveragePercent: webviewHandlers.length ? Math.round((coveredWebviewHandlers.length / webviewHandlers.length) * 100) : 100,
    },
    commands,
    webviewHandlers,
    observed: {
      commands: observedCommands,
      webviewMessages: observedWebviewMessages,
      python: observedByKind(auditEvents, 'python'),
      process: observedByKind(auditEvents, 'process'),
    },
    unknownAudited,
  };
}

function markdownForReport(report) {
  const lines = [
    '# Runtime Audit E2E Feature Coverage',
    '',
    `Generated: ${report.generatedAt}`,
    report.auditEventsPath ? `Runtime audit events: ${report.auditEventsPath}` : 'Runtime audit events: <not found>',
    '',
    `Command coverage: ${report.summary.coveredCommands}/${report.summary.contributedCommands} (${report.summary.coveragePercent}%)`,
    `Host webview handler coverage: ${report.summary.coveredHostWebviewHandlers}/${report.summary.hostWebviewHandlers} (${report.summary.hostWebviewCoveragePercent}%)`,
    '',
    '## Covered Commands',
    '',
  ];

  for (const entry of report.commands.filter((item) => item.covered)) {
    lines.push(`- [x] \`${entry.command}\`${entry.scenario ? ` - ${entry.scenario}` : ''}`);
  }

  lines.push('', '## Missing Commands', '');
  for (const entry of report.commands.filter((item) => !item.covered)) {
    lines.push(`- [ ] \`${entry.command}\`${entry.note ? ` - ${entry.note}` : ''}`);
  }

  lines.push('', '## Covered Host Webview Handlers', '');
  for (const entry of report.webviewHandlers.filter((item) => item.covered)) {
    lines.push(`- [x] \`${entry.message}\`${entry.note ? ` - ${entry.note}` : ''}`);
  }

  lines.push('', '## Missing Host Webview Handlers', '');
  for (const entry of report.webviewHandlers.filter((item) => !item.covered)) {
    lines.push(`- [ ] \`${entry.message}\`${entry.note ? ` - ${entry.note}` : ''}`);
  }

  lines.push('', '## Observed Runtime Backend Activity', '');
  lines.push(`- Python scripts: ${report.observed.python.length ? report.observed.python.map((name) => `\`${name}\``).join(', ') : '<none>'}`);
  lines.push(`- Processes: ${report.observed.process.length ? report.observed.process.map((name) => `\`${name}\``).join(', ') : '<none>'}`);

  if (report.unknownAudited.length) {
    lines.push('', '## Audited But Not Contributed', '');
    for (const command of report.unknownAudited) {
      lines.push(`- \`${command}\``);
    }
  }

  lines.push(
    '',
    '## Add A Feature Quickly',
    '',
    '1. Add a Mocha test or a loop entry in `scripts/e2e/runtime-audit-suite.js`.',
    '2. For VS Code commands, execute `vscode.commands.executeCommand(...)`.',
    '3. For backend/webview features, post or trigger the matching `hub...` message and assert the observed `webview_message` audit event.',
    '4. Wrap the scenario with `startPerfSampler(...)` so perf is captured during the real action.',
    '5. Run `npm run test:e2e:audit` then `npm run test:e2e:audit:coverage`.',
    ''
  );

  return `${lines.join('\n')}\n`;
}

function main() {
  const report = buildReport();
  fs.mkdirSync(artifactsDir, { recursive: true });
  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(markdownPath, markdownForReport(report));
  console.log(`Runtime audit E2E command coverage: ${report.summary.coveredCommands}/${report.summary.contributedCommands} (${report.summary.coveragePercent}%)`);
  console.log(`Runtime audit E2E host webview coverage: ${report.summary.coveredHostWebviewHandlers}/${report.summary.hostWebviewHandlers} (${report.summary.hostWebviewCoveragePercent}%)`);
  console.log(`Coverage report: ${markdownPath}`);
  if (report.summary.missingCommands > 0) {
    console.log(`Missing commands: ${report.summary.missingCommands}`);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  buildReport,
  discoverHostWebviewHandlers,
  latestAuditEventsPath,
  readAuditEvents,
};
