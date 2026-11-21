// SPDX-License-Identifier: AGPL-3.0-only
/**
 * POF-P1-010: measures event-loop delay (p50, p95, max) while the static cache
 * runs N write+read pairs, once with the sync API and once with the async API.
 *
 * Usage (from extension/, DEV only, temporary storage):
 *   npx tsx scripts/measure-static-cache-event-loop.ts [iterations]
 */
// Same `vscode` module mock as the unit tests: the cache modules import it at load time.
require('../src/tests/setup');

const fs = require('fs');
const os = require('os');
const path = require('path');
const { monitorEventLoopDelay } = require('perf_hooks');
const cache = require('../src/shared/staticCache');
const { setExtensionPath } = require('../src/shared/utils');

const DEFAULT_ITERATIONS = 20;
const HISTOGRAM_RESOLUTION_MS = 1;
const NS_PER_MS = 1e6;
const PAYLOAD_ITEMS = 2000;

const payload = Array.from({ length: PAYLOAD_ITEMS }, (_, i) => ({ name: `sym_${i}`, addr: i }));

function parseIterations(raw) {
  const value = Number.parseInt(raw ?? String(DEFAULT_ITERATIONS), 10);
  if (!Number.isInteger(value) || value < 1) throw new RangeError(`iterations invalide : ${raw}`);
  return value;
}

async function runSync(dir, bin, iterations) {
  for (let i = 0; i < iterations; i += 1) {
    cache.writeCache(dir, bin, 'symbols', payload);
    cache.readCache(dir, bin, 'symbols');
    // Yield so the histogram timer can record the delay caused by each blocking pair.
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function runAsync(dir, bin, iterations) {
  for (let i = 0; i < iterations; i += 1) {
    await cache.writeCacheAsync(dir, bin, 'symbols', payload);
    await cache.readCacheAsync(dir, bin, 'symbols');
  }
}

async function measure(label, run, iterations) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-cache-bench-'));
  const bin = path.join(dir, 'sample.bin');
  fs.writeFileSync(bin, 'binary');
  const histogram = monitorEventLoopDelay({ resolution: HISTOGRAM_RESOLUTION_MS });
  const started = process.hrtime.bigint();
  histogram.enable();
  try {
    await run(dir, bin, iterations);
  } finally {
    histogram.disable();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const toMs = (ns) => (Number(ns) / NS_PER_MS).toFixed(1);
  return {
    mode: label,
    iterations,
    p50_ms: toMs(histogram.percentile(50)),
    p95_ms: toMs(histogram.percentile(95)),
    max_ms: toMs(histogram.max),
    wall_ms: toMs(process.hrtime.bigint() - started),
  };
}

async function main() {
  setExtensionPath(path.resolve(__dirname, '..'));
  const iterations = parseIterations(process.argv[2]);
  console.table([
    await measure('sync', runSync, iterations),
    await measure('async', runAsync, iterations),
  ]);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
