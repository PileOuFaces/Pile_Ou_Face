// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { runTests } = require('@vscode/test-electron');

const AUDIT_FILE = 'audit-runtime-usage.jsonl';
const FIXTURE_SPECS = [
  { name: 'tiny', paddedBytes: 0 },
  { name: 'padded-1mb', paddedBytes: 1024 * 1024 },
];

function createFixtureBinary(extensionRoot, workspacePath, spec) {
  const fixturePath = path.join(workspacePath, `e2e-fixture-${spec.name}.elf`);
  const makerPath = path.join(extensionRoot, 'backends', 'static', 'tests', 'fixtures', 'make_elf.py');
  const pythonCmd = process.env.PYTHON || 'python3';
  const script = [
    'import importlib.util, pathlib, sys',
    'maker = pathlib.Path(sys.argv[1])',
    'out = pathlib.Path(sys.argv[2])',
    'spec = importlib.util.spec_from_file_location("make_elf", maker)',
    'mod = importlib.util.module_from_spec(spec)',
    'spec.loader.exec_module(mod)',
    'mod.make_minimal_elf(str(out))',
  ].join('; ');
  const result = spawnSync(pythonCmd, ['-c', script, makerPath, fixturePath], {
    cwd: extensionRoot,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(`Failed to create E2E fixture with ${pythonCmd}: ${result.stderr || result.stdout}`);
  }
  if (spec.paddedBytes > 0) {
    const fd = fs.openSync(fixturePath, 'a');
    try {
      fs.writeSync(fd, Buffer.alloc(spec.paddedBytes));
    } finally {
      fs.closeSync(fd);
    }
  }
  return {
    name: spec.name,
    path: fixturePath,
    entry: '0x400078',
    sizeBytes: fs.statSync(fixturePath).size,
    kind: 'synthetic-minimal',
  };
}

function createRealCorpusFixtures(extensionRoot, workspacePath) {
  if (!['1', 'true', 'yes'].includes(String(process.env.POF_E2E_REAL_CORPUS || '').toLowerCase())) {
    return [];
  }
  const pythonCmd = process.env.PYTHON || 'python3';
  const script = [
    'import json, pathlib, sys',
    'extension_root = pathlib.Path(sys.argv[1])',
    'workspace = pathlib.Path(sys.argv[2])',
    'sys.path.insert(0, str(extension_root))',
    'from backends.static.tests.fixtures.real_binary_corpus import build_corpus_binary, default_corpus_specs',
    'fixtures = []',
    'root = workspace / "e2e-real-corpus"',
    'for spec in default_corpus_specs():',
    '    built = build_corpus_binary(root, spec)',
    '    if not built.built:',
    '        continue',
    '    fixtures.append({',
    '        "name": "real-" + spec.case_id,',
    '        "path": str(built.binary_path),',
    '        "entry": built.expected_functions.get("main") or next(iter(built.expected_functions.values()), "0x0"),',
    '        "sizeBytes": built.binary_path.stat().st_size,',
    '        "kind": "real-compiled",',
    '        "compiler": pathlib.Path(spec.compiler).name,',
    '        "opt": spec.opt,',
    '        "pie": spec.pie,',
    '        "stripped": spec.stripped,',
    '        "arch": spec.arch,',
    '        "expectedFunctions": built.expected_functions,',
    '    })',
    'print(json.dumps(fixtures))',
  ].join('\n');
  const result = spawnSync(pythonCmd, ['-c', script, extensionRoot, workspacePath], {
    cwd: extensionRoot,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 10,
  });
  if (result.status !== 0) {
    console.log(`[e2e] real corpus skipped: ${result.stderr || result.stdout || `exit ${result.status}`}`);
    return [];
  }
  try {
    const fixtures = JSON.parse(result.stdout || '[]');
    console.log(`[e2e] real corpus fixtures: ${fixtures.length}`);
    return fixtures;
  } catch (error) {
    console.log(`[e2e] real corpus skipped: invalid fixture metadata: ${error.message || error}`);
    return [];
  }
}

function readUserFixturePaths() {
  const raw = process.env.POF_E2E_FIXTURE_PATHS || '';
  return raw
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((fixturePath, index) => {
      const resolved = path.resolve(fixturePath);
      return {
        name: `user-${index + 1}-${path.basename(resolved, path.extname(resolved))}`,
        path: resolved,
        entry: process.env.POF_E2E_FIXTURE_ENTRY || '0x0',
        sizeBytes: fs.existsSync(resolved) ? fs.statSync(resolved).size : 0,
        kind: 'user-provided',
      };
    })
    .filter((fixture) => fs.existsSync(fixture.path));
}

function createPerfPath(extensionRoot) {
  const artifactsDir = path.join(extensionRoot, '.pile-ou-face', 'test-artifacts', 'e2e-runtime-audit');
  fs.mkdirSync(artifactsDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return {
    artifactsDir,
    stamp,
    perfPath: path.join(artifactsDir, `runtime-audit-perf-${stamp}.jsonl`),
    auditCopyPath: path.join(artifactsDir, `audit-runtime-usage-${stamp}.jsonl`),
  };
}

function findAuditFiles(root) {
  const results = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && entry.name === AUDIT_FILE) {
        results.push(fullPath);
      }
    }
  }
  return results.sort();
}

function copyRuntimeAuditArtifact(userDataDir, auditCopyPath) {
  const auditFiles = findAuditFiles(userDataDir);
  if (!auditFiles.length) {
    console.log(`[e2e] runtime audit events: <missing under ${userDataDir}>`);
    return '';
  }
  const newest = auditFiles
    .map((filePath) => ({ filePath, mtimeMs: fs.statSync(filePath).mtimeMs }))
    .sort((left, right) => right.mtimeMs - left.mtimeMs)[0].filePath;
  fs.copyFileSync(newest, auditCopyPath);
  console.log(`[e2e] runtime audit events: ${auditCopyPath}`);
  return auditCopyPath;
}

function writeFeatureCoverageReport(extensionRoot, auditCopyPath) {
  const scriptPath = path.join(extensionRoot, 'scripts', 'e2e', 'runtime-audit-feature-coverage.js');
  const env = { ...process.env };
  if (auditCopyPath) env.POF_E2E_AUDIT_EVENTS_PATH = auditCopyPath;
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: extensionRoot,
    stdio: 'inherit',
    env,
  });
  if (result.status !== 0) {
    throw new Error(`Failed to write runtime audit feature coverage report: exit ${result.status}`);
  }
}

function writeWorkflowAuditReport(extensionRoot, auditCopyPath, perfPath) {
  const scriptPath = path.join(extensionRoot, 'scripts', 'e2e', 'runtime-audit-workflow-report.js');
  const env = { ...process.env };
  if (auditCopyPath) env.POF_E2E_AUDIT_EVENTS_PATH = auditCopyPath;
  if (perfPath) env.POF_E2E_PERF_EVENTS_PATH = perfPath;
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: extensionRoot,
    stdio: 'inherit',
    env,
  });
  if (result.status !== 0) {
    throw new Error(`Failed to write runtime audit workflow report: exit ${result.status}`);
  }
}

async function main() {
  const extensionRoot = path.resolve(__dirname, '..', '..');
  const workspacePath = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-e2e-workspace-'));
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-e2e-user-data-'));
  const extensionsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-e2e-extensions-'));
  const logsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-e2e-logs-'));
  const extensionTestsPath = path.resolve(__dirname, 'runtime-audit-suite.js');
  const fixtures = [
    ...FIXTURE_SPECS.map((spec) => createFixtureBinary(extensionRoot, workspacePath, spec)),
    ...createRealCorpusFixtures(extensionRoot, workspacePath),
    ...readUserFixturePaths(),
  ];
  const { perfPath, auditCopyPath } = createPerfPath(extensionRoot);

  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const build = spawnSync(npmCmd, ['run', 'build'], {
    cwd: extensionRoot,
    stdio: 'inherit',
  });
  if (build.status !== 0) process.exit(build.status || 1);

  process.env.POF_AUDIT_TRACE = '1';
  process.env.POF_E2E_USER_DATA_DIR = userDataDir;
  process.env.POF_E2E_WORKSPACE_DIR = workspacePath;
  process.env.POF_E2E_EXTENSION_ROOT = extensionRoot;
  process.env.POF_E2E_FIXTURE_BINARY = fixtures[0].path;
  process.env.POF_E2E_FIXTURES_JSON = JSON.stringify(fixtures);
  process.env.POF_E2E_PERF_PATH = perfPath;

  let failed = false;
  try {
    await runTests({
      extensionDevelopmentPath: extensionRoot,
      extensionTestsPath,
      launchArgs: [
        workspacePath,
        `--user-data-dir=${userDataDir}`,
        `--extensions-dir=${extensionsDir}`,
        `--logsPath=${logsDir}`,
        '--skip-welcome',
        '--skip-release-notes',
      ],
      extensionTestsEnv: {
        POF_AUDIT_TRACE: '1',
        POF_E2E_USER_DATA_DIR: userDataDir,
        POF_E2E_WORKSPACE_DIR: workspacePath,
        POF_E2E_EXTENSION_ROOT: extensionRoot,
        POF_E2E_FIXTURE_BINARY: fixtures[0].path,
        POF_E2E_FIXTURES_JSON: JSON.stringify(fixtures),
        POF_E2E_PERF_PATH: perfPath,
      },
    });
    console.log(`[e2e] perf samples: ${perfPath}`);
    const copiedAuditPath = copyRuntimeAuditArtifact(userDataDir, auditCopyPath);
    writeFeatureCoverageReport(extensionRoot, copiedAuditPath);
    writeWorkflowAuditReport(extensionRoot, copiedAuditPath, perfPath);
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    if (!process.env.POF_E2E_KEEP_ARTIFACTS && !failed) {
      fs.rmSync(workspacePath, { recursive: true, force: true });
      fs.rmSync(userDataDir, { recursive: true, force: true });
      fs.rmSync(extensionsDir, { recursive: true, force: true });
      fs.rmSync(logsDir, { recursive: true, force: true });
    } else {
      console.log(`[e2e] kept workspace: ${workspacePath}`);
      console.log(`[e2e] kept user-data: ${userDataDir}`);
      console.log(`[e2e] kept extensions: ${extensionsDir}`);
      console.log(`[e2e] kept logs: ${logsDir}`);
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
