#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only

import fs from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (!item.startsWith('--')) continue;
    const key = item.slice(2);
    const value = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
    out[key] = value;
  }
  return out;
}

function readJson(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function pct(value) {
  if (value === null || value === undefined || value === '') return 'n/a';
  const num = typeof value === 'string' ? Number.parseFloat(value) : Number(value);
  return Number.isFinite(num) ? `${num.toFixed(1)}%` : 'n/a';
}

function pythonTotals(payload) {
  const totals = payload?.totals || {};
  const overall = totals.percent_covered_display ?? totals.percent_covered;
  return {
    lines: overall,
    statements: totals.percent_statements_covered_display ?? totals.percent_statements_covered ?? overall,
    branches: totals.num_branches
      ? (totals.percent_branches_covered_display ?? totals.percent_branches_covered)
      : null,
    functions: null,
  };
}

function jsTotals(payload) {
  const total = payload?.total || {};
  return {
    lines: total.lines?.pct,
    statements: total.statements?.pct,
    branches: total.branches?.pct,
    functions: total.functions?.pct,
  };
}

function tableRow(label, totals) {
  return `| ${label} | ${pct(totals.lines)} | ${pct(totals.statements)} | ${pct(totals.branches)} | ${pct(totals.functions)} |`;
}

const args = parseArgs(process.argv.slice(2));
const python = readJson(args.python);
const javascript = readJson(args.javascript);

const lines = [
  '## Test coverage baseline',
  '',
  '| Scope | Lines | Statements | Branches | Functions |',
  '| --- | ---: | ---: | ---: | ---: |',
];

if (python) lines.push(tableRow('Python backends', pythonTotals(python)));
else lines.push('| Python backends | n/a | n/a | n/a | n/a |');

if (javascript) lines.push(tableRow('Extension JS/TS', jsTotals(javascript)));
else lines.push('| Extension JS/TS | n/a | n/a | n/a | n/a |');

lines.push(
  '',
  'Current gates are intentionally baseline gates, not the final 80% target.',
  'Issue #85 tracks moving from baseline reporting to a progressive v1 threshold.',
  '',
);

const markdown = `${lines.join('\n')}`;
if (args.output) {
  fs.mkdirSync(path.dirname(args.output), { recursive: true });
  fs.writeFileSync(args.output, markdown, 'utf8');
}
process.stdout.write(markdown);
