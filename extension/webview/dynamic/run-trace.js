const vscode = acquireVsCodeApi();

const form = document.getElementById('runTraceForm');
const changeBinaryBtn = document.getElementById('changeBinaryBtn');
const runTraceBtn = document.getElementById('runTraceBtn');
const statusLine = document.getElementById('statusLine');
const binaryPathInput = document.getElementById('binaryPath');
const archBitsBadge = document.getElementById('archBitsBadge');
const pieBadge = document.getElementById('pieBadge');
const sourceHint = document.getElementById('sourceHint');
const bufferOffsetInput = document.getElementById('bufferOffset');
const bufferSizeInput = document.getElementById('bufferSize');
const maxStepsInput = document.getElementById('maxSteps');
const startSymbolInput = document.getElementById('startSymbol');
const stopSymbolInput = document.getElementById('stopSymbol');

let currentInit = {
  archBits: 64,
  pie: false,
  sourcePath: '',
};

function setStatus(text) {
  if (statusLine) statusLine.textContent = text;
}

function applyInit(data) {
  currentInit = {
    archBits: Number(data.archBits) === 32 ? 32 : 64,
    pie: data.pie === true,
    sourcePath: String(data.sourcePath || '').trim(),
  };

  binaryPathInput.value = String(data.binaryPath || '');
  archBitsBadge.textContent = `${currentInit.archBits}-bit`;
  pieBadge.textContent = currentInit.pie ? 'Yes' : 'No';
  sourceHint.textContent = currentInit.sourcePath ? `Source liée: ${currentInit.sourcePath}` : 'Aucune source associée mémorisée pour ce binaire.';

  const profile = data.mvpProfile || {};
  bufferOffsetInput.value = String(profile.bufferOffset ?? '');
  bufferSizeInput.value = String(profile.bufferSize ?? '');
  maxStepsInput.value = String(profile.maxSteps ?? '800');
  startSymbolInput.value = String(profile.startSymbol || data.symbols?.startDefault || 'main');
  stopSymbolInput.value = String(profile.stopSymbol || data.symbols?.stopDefault || '');
  setStatus(data.binaryPath ? 'Prêt.' : 'Sélectionne un binaire pour lancer la trace.');
}

window.addEventListener('message', (event) => {
  const msg = event.data;
  if (!msg || !msg.type) return;

  if (msg.type === 'initRunTrace') {
    applyInit(msg);
    return;
  }

  if (msg.type === 'runTraceDone') {
    runTraceBtn.disabled = false;
    setStatus('Trace terminée.');
  }
});

changeBinaryBtn?.addEventListener('click', () => {
  setStatus('Sélection du binaire...');
  vscode.postMessage({ type: 'selectRunTraceBinary' });
});

binaryPathInput?.addEventListener('blur', () => {
  const binaryPath = binaryPathInput.value.trim();
  if (!binaryPath) return;
  setStatus('Actualisation du profil binaire...');
  vscode.postMessage({ type: 'refreshRunTraceBinary', binaryPath });
});

form?.addEventListener('submit', (event) => {
  event.preventDefault();
  const binaryPath = binaryPathInput.value.trim();
  if (!binaryPath) {
    setStatus('Chemin binaire requis.');
    return;
  }

  runTraceBtn.disabled = true;
  setStatus('Trace en cours...');
  vscode.postMessage({
    type: 'runTrace',
    config: {
      traceMode: 'dynamic',
      useExistingBinary: true,
      binaryPath,
      archBits: currentInit.archBits,
      pie: currentInit.pie,
      bufferOffset: bufferOffsetInput.value.trim(),
      bufferSize: bufferSizeInput.value.trim(),
      maxSteps: maxStepsInput.value.trim(),
      startSymbol: startSymbolInput.value.trim(),
      stopSymbol: stopSymbolInput.value.trim(),
    }
  });
});

vscode.postMessage({ type: 'readyRunTrace' });
