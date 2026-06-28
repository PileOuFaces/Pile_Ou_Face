const STACK_FRAME_DEBUG = false;
let lastStackFrameDebugConsoleKey = '';

export function isStackFrameDebugEnabled() {
  return STACK_FRAME_DEBUG || globalThis.__POF_STACK_FRAME_DEBUG === true;
}

export function renderStackFrameDebugPanel(container, frameModel) {
  if (!container) return;

  const debugModel = frameModel?.debug;
  if (!debugModel) return;

  const details = document.createElement('details');
  details.className = 'stack-debug-panel';

  const summary = document.createElement('summary');
  summary.textContent = `Debug frame (${Array.isArray(debugModel.items) ? debugModel.items.length : 0} items)`;
  details.appendChild(summary);

  const itemsTitle = document.createElement('div');
  itemsTitle.textContent = 'Final items';
  details.appendChild(itemsTitle);

  const itemsPre = document.createElement('pre');
  itemsPre.textContent = formatStackFrameDebugItems(debugModel.items);
  details.appendChild(itemsPre);

  if (Array.isArray(debugModel.seeds) && debugModel.seeds.length) {
    const seedsTitle = document.createElement('div');
    seedsTitle.textContent = 'Seeds';
    details.appendChild(seedsTitle);

    const seedsPre = document.createElement('pre');
    seedsPre.textContent = formatStackFrameDebugSeeds(debugModel.seeds);
    details.appendChild(seedsPre);
  }

  container.appendChild(details);
  logStackFrameDebug(frameModel);
}

export function formatStackFrameDebugItems(items) {
  const lines = (Array.isArray(items) ? items : []).map((item) => (
    [
      padRight(item?.name || 'item', 14),
      `kind=${item?.kind || 'unknown'}`,
      `off=${item?.offset || 'n/a'}`,
      `size=${item?.size ?? 'unknown'}`,
      `source=${item?.source || 'unknown'}`,
      `merged=${item?.mergedObservationCount ?? 0}`,
      `id=${item?.key || 'n/a'}`
    ].join('   ')
  ));
  return lines.length ? lines.join('\n') : '(no final items)';
}

export function formatStackFrameDebugSeeds(seeds) {
  const lines = (Array.isArray(seeds) ? seeds : []).map((seed) => (
    [
      `[${seed?.stage || 'seed'}]`,
      `kind=${seed?.kind || 'unknown'}`,
      `off=${seed?.offset || 'n/a'}`,
      `size=${seed?.size ?? 'unknown'}`,
      `source=${seed?.source || 'unknown'}`,
      seed?.label ? `label=${seed.label}` : '',
      `key=${seed?.key || 'n/a'}`
    ].filter(Boolean).join('   ')
  ));
  return lines.length ? lines.join('\n') : '(no seeds)';
}

function logStackFrameDebug(frameModel) {
  const debugModel = frameModel?.debug;
  if (!debugModel) return;
  const consoleKey = [
    frameModel?.functionName || 'frame',
    frameModel?.currentStep || 'na',
    Array.isArray(debugModel.items) ? debugModel.items.length : 0,
    Array.isArray(debugModel.seeds) ? debugModel.seeds.length : 0
  ].join(':');
  if (consoleKey === lastStackFrameDebugConsoleKey) return;
  lastStackFrameDebugConsoleKey = consoleKey;
  console.debug('[stack-frame-debug]', debugModel);
}

function padRight(value, width) {
  const text = String(value || '');
  if (text.length >= width) return text;
  return `${text}${' '.repeat(width - text.length)}`;
}
