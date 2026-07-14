// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file sharedHandlers.js
 * @brief Handlers de messages partagés (plateforme, fichiers, erreurs).
 * @see docs/ARCHITECTURE_AUDIT_PLAN.md Phase 2.2
 */

const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const cp = require('child_process');
const readline = require('readline');
const fileManager = require('./fileManager');
const { detectPythonExecutable, getExtensionPath, buildRuntimeEnv } = require('./utils');
const { makeAnnotationsBridge } = require('./annotationsBridge');
const {
  cancelAiProcess,
  clearAiProcess,
  registerAiProcess,
} = require('./aiProcessRegistry');
const {
  getRecentBinaries: getRecentBinariesState,
  rememberRecentBinary,
  forgetRecentBinary: forgetRecentBinaryState,
  clearRecentBinaries: clearRecentBinariesState,
} = require('./recentBinaries');

/**
 * Inspecte un fichier et indique s'il s'agit d'un binaire natif supporté.
 * @param {string} filePath
 * @returns {{ supported: boolean, format: string }}
 */
function inspectBinaryInput(filePath) {
  try {
    const buf = Buffer.alloc(4);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    // ELF: 0x7f 'E' 'L' 'F'
    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return { supported: true, format: 'ELF' };
    // PE: 'M' 'Z'
    if (buf[0] === 0x4d && buf[1] === 0x5a) return { supported: true, format: 'PE' };
    // Mach-O 64-bit LE: 0xcf 0xfa 0xed 0xfe
    if (buf[0] === 0xcf && buf[1] === 0xfa && buf[2] === 0xed && buf[3] === 0xfe) return { supported: true, format: 'Mach-O' };
    // Mach-O 32-bit LE: 0xce 0xfa 0xed 0xfe
    if (buf[0] === 0xce && buf[1] === 0xfa && buf[2] === 0xed && buf[3] === 0xfe) return { supported: true, format: 'Mach-O' };
    // Mach-O fat binary: 0xca 0xfe 0xba 0xbe
    if (buf[0] === 0xca && buf[1] === 0xfe && buf[2] === 0xba && buf[3] === 0xbe) return { supported: true, format: 'Mach-O' };
    return { supported: false, format: 'RAW' };
  } catch {
    return { supported: false, format: 'UNKNOWN' };
  }
}

/**
 * Vérifie si un fichier est un binaire supporté (ELF, PE, Mach-O) par magic bytes.
 * @param {string} filePath
 * @returns {boolean}
 */
function isSupportedBinary(filePath) {
  return inspectBinaryInput(filePath).supported;
}

function normalizeHexAddress(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  const raw = text.startsWith('0x') || text.startsWith('0X') ? text.slice(2) : text;
  if (!/^[0-9a-fA-F]+$/.test(raw)) return text.toLowerCase();
  return `0x${raw.replace(/^0+/, '') || '0'}`.toLowerCase();
}

function resolveArtifactMappingPath(candidatePath) {
  const absCandidate = path.resolve(String(candidatePath || ''));
  const fileName = path.basename(absCandidate);
  if (fileName.endsWith('.disasm.mapping.json')) return absCandidate;
  if (fileName.endsWith('.disasm.asm')) return absCandidate.replace(/\.disasm\.asm$/i, '.disasm.mapping.json');
  if (fileName.endsWith('.symbols.json')) return absCandidate.replace(/\.symbols\.json$/i, '.disasm.mapping.json');
  if (fileName.endsWith('.discovered.json')) return absCandidate.replace(/\.discovered\.json$/i, '.disasm.mapping.json');
  return '';
}

function getDisasmMappingPathForBinary(binaryPath, { root, storageDir, getTempDir }) {
  const artifactMappingPath = resolveArtifactMappingPath(binaryPath);
  if (artifactMappingPath) return artifactMappingPath;
  const absPath = path.resolve(String(binaryPath || ''));
  const tempDir = storageDir || (typeof getTempDir === 'function' ? getTempDir(root) : root);
  const baseName = path.basename(absPath, path.extname(absPath)) || 'binary';
  return path.join(tempDir, `${baseName}.disasm.mapping.json`);
}

function loadFunctionAddrsFromDisasmMapping(binaryPath, options) {
  const mappingPath = getDisasmMappingPathForBinary(binaryPath, options);
  if (!mappingPath || !fs.existsSync(mappingPath)) return [];
  try {
    const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
    const addrs = new Set<string>();
    for (const fn of Array.isArray(mapping?.functions) ? mapping.functions : []) {
      const addr = normalizeHexAddress(fn?.addr);
      if (addr) addrs.add(addr);
    }
    for (const line of Array.isArray(mapping?.lines) ? mapping.lines : []) {
      const addr = normalizeHexAddress(line?.addr);
      const functionAddr = normalizeHexAddress(line?.function_addr);
      if (addr && functionAddr && addr === functionAddr) addrs.add(addr);
    }
    return Array.from(addrs).sort((a, b) => parseInt(a, 16) - parseInt(b, 16));
  } catch (_) {
    return [];
  }
}

const RAW_ARCH_ITEMS = [
  { label: 'x86-64', description: 'Capstone: i386:x86-64', value: 'i386:x86-64' },
  { label: 'x86 (32-bit)', description: 'Capstone: i386', value: 'i386' },
  { label: 'ARM', description: 'Capstone: arm', value: 'arm' },
  { label: 'Thumb', description: 'Capstone: thumb', value: 'thumb' },
  { label: 'AArch64', description: 'Capstone: aarch64', value: 'aarch64' },
  { label: 'MIPS32', description: 'Capstone: mips32', value: 'mips32' },
  { label: 'MIPS64', description: 'Capstone: mips64', value: 'mips64' },
  { label: 'PowerPC 32', description: 'Capstone: ppc32', value: 'ppc32' },
  { label: 'PowerPC 64', description: 'Capstone: ppc64', value: 'ppc64' },
  { label: 'SPARC', description: 'Capstone: sparc', value: 'sparc' },
  { label: 'SPARC V9', description: 'Capstone: sparcv9', value: 'sparcv9' },
  { label: 'SystemZ', description: 'Capstone: sysz', value: 'sysz' },
  { label: 'XCore', description: 'Capstone: xcore', value: 'xcore' },
  { label: 'M68K', description: 'Capstone: m68k', value: 'm68k' },
  { label: 'M680X', description: 'Capstone: m680x', value: 'm680x' },
  { label: 'TMS320C64x', description: 'Capstone: tms320c64x', value: 'tms320c64x' },
  { label: 'EVM', description: 'Capstone: evm', value: 'evm' },
  { label: 'MOS65XX / 6502', description: 'Capstone: mos65xx', value: 'mos65xx' },
  { label: 'WebAssembly', description: 'Capstone: wasm', value: 'wasm' },
  { label: 'BPF / eBPF', description: 'Capstone: bpf', value: 'bpf' },
  { label: 'RISC-V 32', description: 'Capstone: riscv32', value: 'riscv32' },
  { label: 'RISC-V 64', description: 'Capstone: riscv64', value: 'riscv64' },
  { label: 'SuperH', description: 'Capstone: sh', value: 'sh' },
  { label: 'SuperH4', description: 'Capstone: sh4', value: 'sh4' },
  { label: 'TriCore', description: 'Capstone: tricore', value: 'tricore' },
];

const RAW_ARCH_METADATA = {
  'i386:x86-64': { bits: 64, pointerSize: 8, displayName: 'x86-64', endianAware: false },
  i386: { bits: 32, pointerSize: 4, displayName: 'x86', endianAware: false },
  arm: { bits: 32, pointerSize: 4, displayName: 'ARM', endianAware: true },
  thumb: { bits: 32, pointerSize: 4, displayName: 'Thumb', endianAware: true },
  aarch64: { bits: 64, pointerSize: 8, displayName: 'AArch64', endianAware: true },
  mips32: { bits: 32, pointerSize: 4, displayName: 'MIPS32', endianAware: true },
  mips64: { bits: 64, pointerSize: 8, displayName: 'MIPS64', endianAware: true },
  ppc32: { bits: 32, pointerSize: 4, displayName: 'PowerPC 32', endianAware: true },
  ppc64: { bits: 64, pointerSize: 8, displayName: 'PowerPC 64', endianAware: true },
  sparc: { bits: 32, pointerSize: 4, displayName: 'SPARC', endianAware: true },
  sparcv9: { bits: 64, pointerSize: 8, displayName: 'SPARC V9', endianAware: true },
  sysz: { bits: 64, pointerSize: 8, displayName: 'SystemZ', endianAware: false },
  xcore: { bits: 32, pointerSize: 4, displayName: 'XCore', endianAware: false },
  m68k: { bits: 32, pointerSize: 4, displayName: 'M68K', endianAware: true },
  m680x: { bits: 16, pointerSize: 2, displayName: 'M680X', endianAware: false },
  tms320c64x: { bits: 32, pointerSize: 4, displayName: 'TMS320C64x', endianAware: false },
  evm: { bits: 256, pointerSize: 32, displayName: 'EVM', endianAware: false },
  mos65xx: { bits: 16, pointerSize: 2, displayName: 'MOS65XX / 6502', endianAware: false },
  wasm: { bits: 32, pointerSize: 4, displayName: 'WebAssembly', endianAware: false },
  bpf: { bits: 64, pointerSize: 8, displayName: 'BPF / eBPF', endianAware: false },
  riscv32: { bits: 32, pointerSize: 4, displayName: 'RISC-V 32', endianAware: false },
  riscv64: { bits: 64, pointerSize: 8, displayName: 'RISC-V 64', endianAware: false },
  sh: { bits: 32, pointerSize: 4, displayName: 'SuperH', endianAware: false },
  sh4: { bits: 32, pointerSize: 4, displayName: 'SuperH4', endianAware: false },
  tricore: { bits: 32, pointerSize: 4, displayName: 'TriCore', endianAware: false },
};

function normalizeRawArchName(rawArch) {
  const archAliases = {
    x86_64: 'i386:x86-64',
    amd64: 'i386:x86-64',
    x64: 'i386:x86-64',
    'x86-64': 'i386:x86-64',
    'i386:x86_64': 'i386:x86-64',
    'i386:x86-64': 'i386:x86-64',
    i386: 'i386',
    x86: 'i386',
    arm64: 'aarch64',
    aarch64: 'aarch64',
    arm: 'arm',
    arm32: 'arm',
    thumb: 'thumb',
    armthumb: 'thumb',
    mips: 'mips32',
    mips32: 'mips32',
    mips64: 'mips64',
    ppc: 'ppc32',
    powerpc: 'ppc32',
    ppc32: 'ppc32',
    powerpc32: 'ppc32',
    ppc64: 'ppc64',
    powerpc64: 'ppc64',
    sparc: 'sparc',
    sparc32: 'sparc',
    sparcv9: 'sparcv9',
    sparc64: 'sparcv9',
    s390x: 'sysz',
    systemz: 'sysz',
    sysz: 'sysz',
    xcore: 'xcore',
    m68k: 'm68k',
    m680x: 'm680x',
    tms: 'tms320c64x',
    tms320c64x: 'tms320c64x',
    evm: 'evm',
    mos65xx: 'mos65xx',
    '6502': 'mos65xx',
    wasm: 'wasm',
    webassembly: 'wasm',
    bpf: 'bpf',
    ebpf: 'bpf',
    riscv: 'riscv64',
    riscv32: 'riscv32',
    riscv64: 'riscv64',
    sh: 'sh',
    sh4: 'sh4',
    tricore: 'tricore',
  };
  const normalized = String(rawArch || '').trim().toLowerCase();
  return archAliases[normalized] || normalized;
}

function getRawArchDescriptor(rawArch) {
  const arch = normalizeRawArchName(rawArch);
  const meta = RAW_ARCH_METADATA[arch];
  if (!meta) return { arch, bits: '', pointerSize: '', displayName: arch || 'unknown', endianAware: true };
  return { arch, ...meta };
}

function normalizeRawProfile(profile) {
  if (!profile || typeof profile !== 'object') return null;
  const rawArch = String(profile.arch || profile.rawArch || '').trim().toLowerCase();
  const arch = normalizeRawArchName(rawArch);
  if (!arch) return null;
  const rawEndian = String(profile.endian || profile.rawEndian || '').trim().toLowerCase();
  const endianAliases = {
    le: 'little',
    little: 'little',
    'little-endian': 'little',
    be: 'big',
    big: 'big',
    'big-endian': 'big',
  };
  const descriptor = getRawArchDescriptor(arch);
  const endian = descriptor.endianAware === false ? 'little' : (endianAliases[rawEndian] || 'little');
  const baseRaw = String(profile.baseAddr || profile.rawBaseAddr || '0x0').trim();
  const parsedBase = /^0x[0-9a-f]+$/i.test(baseRaw)
    ? parseInt(baseRaw, 16)
    : (/^\d+$/.test(baseRaw) ? parseInt(baseRaw, 10) : NaN);
  if (!Number.isFinite(parsedBase) || parsedBase < 0) return null;
  return {
    kind: 'raw',
    arch,
    baseAddr: `0x${parsedBase.toString(16)}`,
    endian,
  };
}

/**
 * @brief Handlers partagés (getPlatform, requestBinarySelection, listGeneratedFiles, etc.).
 * @param {object} ctx - { root, panel, getTempDir, ensureTempDir, refreshSidebar }
 */
function sharedHandlers(ctx) {
  const {
    root,
    storageDir,
    panel,
    context,
    getTempDir,
    refreshSidebar,
    getRawProfile,
    setRawProfile,
    clearRawProfile,
  } = ctx;
  const annotationsBridge = ctx.annotationsBridge || makeAnnotationsBridge({
    root,
    extensionPath: context?.extensionPath || getExtensionPath() || root,
    getPythonExecutable: () => detectPythonExecutable(root),
    buildPythonEnv: () => buildRuntimeEnv(root, storageDir),
  });

  const buildAnnotationsMessage = (binaryPath, annotations) => ({
    type: 'hubAnnotations',
    binaryPath,
    annotations,
    functionAddrs: binaryPath
      ? loadFunctionAddrsFromDisasmMapping(binaryPath, { root, storageDir, getTempDir })
      : [],
  });

  const notifyAnnotations = (binaryPath, annotations) => {
    panel.webview.postMessage(buildAnnotationsMessage(binaryPath, annotations));
    panel.webview.postMessage({ type: 'hubAnnotationSaved', binaryPath });
  };

  const forgetRecentBinary = (binaryPath) => {
    panel.webview.postMessage({ type: 'hubForgetRecentBinary', binaryPath });
  };

  const rememberBinarySelection = async (resolved) => {
    if (!context || !resolved?.absPath) return;
    await rememberRecentBinary(context, resolved.absPath, resolved.binaryMeta || null);
  };

  const handleMissingBinarySelection = async (binaryPath) => {
    const target = String(binaryPath || '').trim();
    const displayName = path.basename(target) || target || 'ce fichier';
    const answer = await vscode.window.showWarningMessage(
      `${displayName} est introuvable. Voulez-vous retirer cette entrée des récents et nettoyer les fichiers générés obsolètes ?`,
      { modal: true },
      'Retirer seulement',
      'Retirer et nettoyer',
      'Annuler'
    );
    if (!answer || answer === 'Annuler') return null;
    forgetRecentBinary(target);
    if (context) await forgetRecentBinaryState(context, target);
    await Promise.resolve(clearRawProfile?.(target));
    if (answer === 'Retirer et nettoyer') {
      const result = fileManager.cleanupForBinary(storageDir || root, target, {
        purgeStale: true,
        root,
      });
      if (result.total > 0) {
        vscode.window.showInformationMessage(`Reverse Workspace : ${result.total} fichier(s) généré(s) supprimé(s).`);
      }
      panel.webview.postMessage({ type: 'refreshGeneratedFiles' });
      panel.webview.postMessage({ type: 'generatedFiles', files: fileManager.listAll(storageDir || root) });
    }
    return null;
  };

  const promptRawProfile = async (binaryPath, existingProfile = null) => {
    const preset = normalizeRawProfile(existingProfile) || normalizeRawProfile(await Promise.resolve(getRawProfile?.(binaryPath)));
    const defaultArch = preset?.arch || 'i386:x86-64';
    const pickedArch = await vscode.window.showQuickPick(
      RAW_ARCH_ITEMS.map((item) => ({ ...item, picked: item.value === defaultArch })),
      {
        title: `Blob brut — architecture (${path.basename(binaryPath)})`,
        placeHolder: 'Choisissez l’architecture à utiliser pour le désassemblage',
      }
    );
    if (!pickedArch) return null;

    let pickedEndianValue = 'little';
    if (!pickedArch.value.startsWith('i386')) {
      const endianItems = [
        { label: 'Little-endian', description: 'Ordre d’octets le plus courant', value: 'little' },
        { label: 'Big-endian', description: 'Utile pour certains firmwares et blobs réseau', value: 'big' },
      ];
      const defaultEndian = preset?.endian || 'little';
      const pickedEndian = await vscode.window.showQuickPick(
        endianItems.map((item) => ({ ...item, picked: item.value === defaultEndian })),
        {
          title: `Blob brut — endianness (${path.basename(binaryPath)})`,
          placeHolder: 'Choisissez l’endianness du blob brut',
        }
      );
      if (!pickedEndian) return null;
      pickedEndianValue = pickedEndian.value;
    }

    const baseAddr = await vscode.window.showInputBox({
      title: `Blob brut — adresse de base (${path.basename(binaryPath)})`,
      prompt: 'Adresse virtuelle de base (ex: 0x401000)',
      value: preset?.baseAddr || '0x0',
      validateInput: (value) => {
        const text = String(value || '').trim();
        if (!text) return 'Adresse requise.';
        if (/^0x[0-9a-f]+$/i.test(text)) return null;
        if (/^\d+$/.test(text)) return null;
        return 'Entrez une adresse en hexadécimal (0x...) ou en décimal.';
      },
    });
    if (baseAddr == null) return null;
    return normalizeRawProfile({ arch: pickedArch.value, baseAddr, endian: pickedEndianValue });
  };

  const resolveBinarySelection = async (binaryPath, preferredMeta = null, options = null) => {
    if (!binaryPath || !fs.existsSync(binaryPath)) {
      return handleMissingBinarySelection(binaryPath);
    }
    const normalizeArtifactBinaryPath = (candidatePath) => {
      const absCandidate = path.resolve(candidatePath);
      const fileName = path.basename(absCandidate);
      const isDisasmArtifact = (
        fileName.endsWith('.disasm.asm')
        || fileName.endsWith('.disasm.mapping.json')
        || fileName.endsWith('.symbols.json')
        || fileName.endsWith('.discovered.json')
      );
      if (!isDisasmArtifact) return absCandidate;
      const mappingPath = fileName.endsWith('.disasm.mapping.json')
        ? absCandidate
        : absCandidate
          .replace(/\.disasm\.asm$/i, '.disasm.mapping.json')
          .replace(/\.symbols\.json$/i, '.disasm.mapping.json')
          .replace(/\.discovered\.json$/i, '.disasm.mapping.json');
      if (!fs.existsSync(mappingPath)) return absCandidate;
      try {
        const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
        const mappedBinary = String(mapping?.binary || '').trim();
        if (!mappedBinary) return absCandidate;
        const resolvedBinary = path.isAbsolute(mappedBinary)
          ? mappedBinary
          : path.resolve(path.dirname(mappingPath), mappedBinary);
        return fs.existsSync(resolvedBinary) ? resolvedBinary : absCandidate;
      } catch (_) {
        return absCandidate;
      }
    };
    const normalizedBinaryPath = normalizeArtifactBinaryPath(binaryPath);
    const inspection = inspectBinaryInput(normalizedBinaryPath);
    const relPath = path.relative(root, normalizedBinaryPath);
    const pathForWebview = relPath.startsWith('..') ? normalizedBinaryPath : relPath;
    if (inspection.supported) {
      await Promise.resolve(clearRawProfile?.(normalizedBinaryPath));
      return {
        absPath: normalizedBinaryPath,
        pathForWebview,
        binaryMeta: { kind: 'native', format: inspection.format },
      };
    }

    const preferredRawProfile = normalizeRawProfile(preferredMeta?.rawConfig || preferredMeta);
    const storedRawProfile = normalizeRawProfile(await Promise.resolve(getRawProfile?.(normalizedBinaryPath)));
    let rawProfile = null;
    const existingRawProfile = preferredRawProfile || storedRawProfile;
    const forcedRawAction = String(options?.rawProfileAction || '').trim().toLowerCase();
    if (existingRawProfile) {
      if (forcedRawAction === 'reuse') {
        rawProfile = existingRawProfile;
      } else if (forcedRawAction === 'reconfigure') {
        rawProfile = await promptRawProfile(binaryPath, existingRawProfile);
        if (!rawProfile) return null;
      } else {
        const reuseChoice = await vscode.window.showQuickPick(
          [
            {
              label: 'Utiliser le profil enregistré',
              description: `${existingRawProfile.arch} · ${existingRawProfile.endian} · ${existingRawProfile.baseAddr}`,
              value: 'reuse',
            },
            {
              label: 'Reconfigurer le blob',
              description: 'Changer architecture, endianness ou base virtuelle',
              value: 'reconfigure',
            },
          ],
          {
            title: `Blob brut — profil existant (${path.basename(normalizedBinaryPath)})`,
            placeHolder: 'Choisissez le profil à appliquer à ce blob brut',
          }
        );
        if (!reuseChoice) return null;
        if (reuseChoice.value === 'reuse') {
          rawProfile = existingRawProfile;
        } else {
          rawProfile = await promptRawProfile(binaryPath, existingRawProfile);
          if (!rawProfile) return null;
        }
      }
    }
    if (!rawProfile) {
      const answer = await vscode.window.showWarningMessage(
        `${path.basename(normalizedBinaryPath)} n'est pas reconnu comme ELF, PE ou Mach-O. Voulez-vous l'ouvrir comme blob brut ?`,
        { modal: true },
        'Configurer le blob',
        'Annuler'
      );
      if (answer !== 'Configurer le blob') return null;
      rawProfile = await promptRawProfile(normalizedBinaryPath, null);
      if (!rawProfile) return null;
    }
    await Promise.resolve(setRawProfile?.(normalizedBinaryPath, rawProfile));
    return {
      absPath: normalizedBinaryPath,
      pathForWebview,
      binaryMeta: {
        kind: 'raw',
        format: 'RAW',
        arch: rawProfile.arch,
        rawConfig: rawProfile,
      },
    };
  };

  return {
    getPlatform: () => {
      panel.webview.postMessage({ type: 'platformInfo', platform: process.platform });
    },
    requestBinarySelection: async () => {
      const binaryUri = await vscode.window.showOpenDialog({
        title: 'Choisir le fichier de travail à analyser',
        defaultUri: vscode.Uri.file(root),
        canSelectMany: false,
        filters: { 'Tous les fichiers': ['*'] }
      });
      if (!binaryUri?.length) return;
      const binaryPath = binaryUri[0].fsPath;
      const resolved = await resolveBinarySelection(binaryPath);
      if (!resolved) return;
      await rememberBinarySelection(resolved);
      panel.webview.postMessage({
        type: 'hubSetBinaryPath',
        binaryPath: resolved.pathForWebview,
        binaryMeta: resolved.binaryMeta,
      });
      if (refreshSidebar) refreshSidebar(resolved.pathForWebview);
    },
    hubUseBinaryPath: async (message) => {
      const binaryPath = String(message?.binaryPath || '').trim();
      if (!binaryPath) return;
      const absPath = path.isAbsolute(binaryPath) ? binaryPath : path.join(root, binaryPath);
      const resolved = await resolveBinarySelection(absPath, message?.binaryMeta || null, {
        rawProfileAction: message?.rawProfileAction || null,
      });
      if (!resolved) return;
      await rememberBinarySelection(resolved);
      panel.webview.postMessage({
        type: 'hubSetBinaryPath',
        binaryPath: resolved.pathForWebview,
        binaryMeta: resolved.binaryMeta,
      });
      if (refreshSidebar) refreshSidebar(resolved.pathForWebview);
    },
    hubForgetRecentBinary: async (message) => {
      const binaryPath = String(message?.binaryPath || '').trim();
      if (!binaryPath || !context) return;
      const absPath = path.isAbsolute(binaryPath) ? binaryPath : path.join(root, binaryPath);
      await forgetRecentBinaryState(context, absPath);
      await Promise.resolve(clearRawProfile?.(absPath));
      const result = fileManager.cleanupForBinary(storageDir || root, absPath, {
        purgeStale: true,
        root,
      });
      if (result.total > 0) {
        panel.webview.postMessage({ type: 'refreshGeneratedFiles' });
        panel.webview.postMessage({ type: 'generatedFiles', files: fileManager.listAll(storageDir || root) });
      }
    },
    hubClearRecentBinaries: async () => {
      if (!context) return;
      await clearRecentBinariesState(context);
    },
    hubRequestRecentBinaries: async () => {
      const all = context ? getRecentBinariesState(context) : [];
      const existing = all.filter((e) => e?.path && fs.existsSync(e.path));
      if (existing.length !== all.length && context) {
        const { setRecentBinaries: setRecentBinariesState } = require('./recentBinaries');
        await setRecentBinariesState(context, existing);
      }
      panel.webview.postMessage({ type: 'hubSetRecentBinaries', recent: existing });
    },
    requestRulesSelection: async (message) => {
      const target = String(message?.target || 'manual').trim() || 'manual';
      const uri = await vscode.window.showOpenDialog({
        title: target === 'global'
          ? 'Reverse Workspace — Définir la bibliothèque YARA globale'
          : 'Reverse Workspace — Sélectionner un fichier .yar ou un dossier de règles',
        defaultUri: vscode.Uri.file(root),
        canSelectMany: false,
        canSelectFiles: true,
        canSelectFolders: true,
        filters: { 'Règles YARA': ['yar', 'yara'], 'Tous': ['*'] }
      });
      if (uri?.length) {
        const p = uri[0].fsPath;
        const relPath = path.relative(root, p);
        const pathForWebview = relPath.startsWith('..') ? p : relPath;
        panel.webview.postMessage({ type: 'hubRulesPath', rulesPath: pathForWebview, target });
      }
    },
    listGeneratedFiles: () => {
      const summary = fileManager.listAll(storageDir || root);
      panel.webview.postMessage({ type: 'generatedFiles', files: summary });
    },
    cleanupGeneratedFiles: async (message) => {
      if (message?.confirm) {
        const choice = await vscode.window.showWarningMessage(
          'Supprimer tous les artifacts et le cache ? Cette action est irréversible.',
          { modal: true },
          'Supprimer',
          'Annuler'
        );
        if (choice !== 'Supprimer') return;
      }
      const { removedArtifacts, removedCache } = fileManager.cleanupAll(storageDir || root);
      const total = removedArtifacts + removedCache;
      if (total > 0) {
        vscode.window.showInformationMessage(`Reverse Workspace : ${total} fichier(s) supprimé(s).`);
      }
      panel.webview.postMessage({ type: 'refreshGeneratedFiles' });
      panel.webview.postMessage({ type: 'generatedFiles', files: fileManager.listAll(storageDir || root) });
    },
    purgeStaleCache: () => {
      const { removed } = fileManager.purgeStaleCache(storageDir || root, root);
      vscode.window.showInformationMessage(
        removed > 0
          ? `Reverse Workspace : ${removed} entrée(s) de cache obsolète(s) supprimée(s).`
          : 'Reverse Workspace : aucune entrée de cache obsolète trouvée.'
      );
      panel.webview.postMessage({ type: 'refreshGeneratedFiles' });
      panel.webview.postMessage({ type: 'generatedFiles', files: fileManager.listAll(storageDir || root) });
    },
    hubError: (message) => {
      vscode.window.showErrorMessage(message.message || 'Erreur');
    },
    hubLoadAnnotations: async (message) => {
      const { binaryPath } = message;
      if (!binaryPath) {
        panel.webview.postMessage(buildAnnotationsMessage('', {}));
        return;
      }
      try {
        const annotations = await annotationsBridge.loadAnnotations(binaryPath);
        panel.webview.postMessage(buildAnnotationsMessage(binaryPath, annotations));
      } catch (err) {
        vscode.window.showErrorMessage(`Impossible de charger les annotations : ${err?.message || err}`);
      }
    },
    hubSaveAnnotation: async (message) => {
      const { binaryPath, addr, comment, name } = message;
      if (!binaryPath || !addr) return;
      const normAddr = addr.startsWith('0x') ? addr : '0x' + addr;
      try {
        const annotations = await annotationsBridge.saveAnnotation(binaryPath, normAddr, { comment, name });
        notifyAnnotations(binaryPath, annotations);
        vscode.window.showInformationMessage(`Annotation enregistrée pour ${normAddr}`);
      } catch (err) {
        vscode.window.showErrorMessage(`Impossible d'enregistrer l'annotation : ${err?.message || err}`);
      }
    },
    hubSaveFunctionReview: async (message) => {
      const { binaryPath, addr, reviewStatus, reviewNotes } = message;
      if (!binaryPath || !addr) return;
      const normAddr = addr.startsWith('0x') ? addr : '0x' + addr;
      try {
        const annotations = await annotationsBridge.saveFunctionReview(binaryPath, normAddr, { reviewStatus, reviewNotes });
        notifyAnnotations(binaryPath, annotations);
      } catch (err) {
        vscode.window.showErrorMessage(`Impossible d'enregistrer la revue : ${err?.message || err}`);
      }
    },
    hubSaveBookmark: async (message) => {
      const { binaryPath, addr, label, color } = message;
      if (!binaryPath || !addr) return;
      const normAddr = addr.startsWith('0x') ? addr : '0x' + addr;
      try {
        const existing = (await annotationsBridge.loadAnnotations(binaryPath))[normAddr] || {};
        const resolvedLabel = label || existing.bookmarkLabel || existing.name || normAddr;
        const resolvedColor = color || existing.bookmarkColor || '#4ec9b0';
        const annotations = await annotationsBridge.saveBookmark(binaryPath, normAddr, { label: resolvedLabel, color: resolvedColor });
        notifyAnnotations(binaryPath, annotations);
      } catch (err) {
        vscode.window.showErrorMessage(`Impossible d'enregistrer le bookmark : ${err?.message || err}`);
      }
    },
    hubDeleteBookmark: async (message) => {
      const { binaryPath, addr } = message;
      if (!binaryPath || !addr) return;
      const normAddr = addr.startsWith('0x') ? addr : '0x' + addr;
      try {
        const annotations = await annotationsBridge.deleteBookmark(binaryPath, normAddr);
        notifyAnnotations(binaryPath, annotations);
      } catch (err) {
        vscode.window.showErrorMessage(`Impossible de supprimer le bookmark : ${err?.message || err}`);
      }
    },
    hubClearBookmarks: async (message) => {
      const { binaryPath } = message;
      if (!binaryPath) return;
      try {
        const annotations = await annotationsBridge.clearBookmarks(binaryPath);
        notifyAnnotations(binaryPath, annotations);
      } catch (err) {
        vscode.window.showErrorMessage(`Impossible d'effacer les bookmarks : ${err?.message || err}`);
      }
    },
    hubDeleteAnnotation: async (message) => {
      const { binaryPath, addr } = message;
      if (!binaryPath || !addr) return;
      const normAddr = addr.startsWith('0x') ? addr : '0x' + addr;
      try {
        const annotations = await annotationsBridge.deleteAnnotation(binaryPath, normAddr);
        notifyAnnotations(binaryPath, annotations);
      } catch (err) {
        vscode.window.showErrorMessage(`Impossible de supprimer l'annotation : ${err?.message || err}`);
      }
    },
    hubAiProvidersGet: () => {
      const getSavedSettings = () => {
        try { return context?.globalState?.get('pof-settings', {}) || {}; } catch (_) { return {}; }
      };
      const pythonExe = getSavedSettings().pythonPath || detectPythonExecutable(root);
      const script = path.join(getExtensionPath() || root, 'backends', 'mcp', 'ai_provider.py');
      cp.execFile(pythonExe, [script, 'list'], { encoding: 'utf8', cwd: root, timeout: 15000 }, (err, stdout) => {
        if (err) {
          panel.webview.postMessage({ type: 'hubAiProvidersResult', data: { error: String(err.message || err) } });
          return;
        }
        try {
          const result = JSON.parse(stdout || '{}');
          panel.webview.postMessage({ type: 'hubAiProvidersResult', data: result });
        } catch (_) {
          panel.webview.postMessage({ type: 'hubAiProvidersResult', data: { error: 'Parse error' } });
        }
      });
    },
    hubAiProviderSet: (message) => {
      const getSavedSettings = () => {
        try { return context?.globalState?.get('pof-settings', {}) || {}; } catch (_) { return {}; }
      };
      const pythonExe = getSavedSettings().pythonPath || detectPythonExecutable(root);
      const script = path.join(getExtensionPath() || root, 'backends', 'mcp', 'ai_provider.py');
      const args = [script, 'set', '--provider', String(message.provider || ''), '--api-key-stdin'];
      if (message.model) { args.push('--model', String(message.model)); }
      const proc = cp.execFile(pythonExe, args, { encoding: 'utf8', cwd: root, timeout: 15000 }, (err, stdout) => {
        if (err) {
          panel.webview.postMessage({ type: 'hubError', message: String(err.message || err) });
          return;
        }
        try {
          const setResult = JSON.parse(stdout || '{}');
          if (!setResult.ok) {
            panel.webview.postMessage({ type: 'hubError', message: String(setResult.error || 'Erreur inconnue') });
            return;
          }
        } catch (_) {
          // ignore parse error on set, still refresh list
        }
        // Refresh the provider list after saving
        const listArgs = [script, 'list'];
        cp.execFile(pythonExe, listArgs, { encoding: 'utf8', cwd: root, timeout: 15000 }, (_err2, stdout2) => {
          try {
            const listResult = JSON.parse(stdout2 || '{}');
            panel.webview.postMessage({ type: 'hubAiProvidersResult', data: listResult });
          } catch (_) {
            panel.webview.postMessage({ type: 'hubAiProvidersResult', data: { error: 'Mise à jour enregistrée — actualisation échouée' } });
          }
        });
      });
      // Write the API key to stdin and close it
      proc.stdin.write(String(message.api_key || '') + '\n');
      proc.stdin.end();
    },
    hubAiProviderTest: (message) => {
      const getSavedSettings = () => {
        try { return context?.globalState?.get('pof-settings', {}) || {}; } catch (_) { return {}; }
      };
      const pythonExe = getSavedSettings().pythonPath || detectPythonExecutable(root);
      const script = path.join(getExtensionPath() || root, 'backends', 'mcp', 'ai_provider.py');
      // Test = refresh list and show current configured state
      cp.execFile(pythonExe, [script, 'list'], { encoding: 'utf8', cwd: root, timeout: 15000 }, (err, stdout) => {
        if (err) {
          panel.webview.postMessage({ type: 'hubAiProvidersResult', data: { error: String(err.message || err) } });
          return;
        }
        try {
          const result = JSON.parse(stdout || '{}');
          panel.webview.postMessage({ type: 'hubAiProvidersResult', data: result });
          const provider = String(message.provider || '');
          const found = Array.isArray(result.providers) && result.providers.find((p) => p.name === provider);
          if (found) {
            vscode.window.showInformationMessage(
              found.configured
                ? `AI Provider "${provider}" : clé configurée (modèle : ${found.model || '—'})`
                : `AI Provider "${provider}" : aucune clé configurée`
            );
          }
        } catch (_) {
          panel.webview.postMessage({ type: 'hubAiProvidersResult', data: { error: 'Parse error' } });
        }
      });
    },
    hubAiProviderDefaultSet: (message) => {
      const getSavedSettings = () => {
        try { return context?.globalState?.get('pof-settings', {}) || {}; } catch (_) { return {}; }
      };
      const pythonExe = getSavedSettings().pythonPath || detectPythonExecutable(root);
      const script = path.join(getExtensionPath() || root, 'backends', 'mcp', 'ai_provider.py');
      cp.execFile(
        pythonExe,
        [script, 'set-default', '--provider', String(message.provider || '')],
        { encoding: 'utf8', cwd: root, timeout: 15000 },
        (err, stdout) => {
          if (err) {
            panel.webview.postMessage({
              type: 'hubError',
              message: String(err.message || err),
            });
            return;
          }
          try {
            const result = JSON.parse(stdout || '{}');
            panel.webview.postMessage({
              type: 'hubAiProviderDefaultSaved',
              data: result,
            });
          } catch (_) {
            panel.webview.postMessage({
              type: 'hubError',
              message: 'Provider par défaut enregistré, réponse illisible.',
            });
          }
        },
      );
    },
    hubAiProviderPrompt: (message) => {
      const requestId = String(message.requestId || '').trim();
      const getSavedSettings = () => {
        try { return context?.globalState?.get('pof-settings', {}) || {}; } catch (_) { return {}; }
      };
      const pythonExe = getSavedSettings().pythonPath || detectPythonExecutable(root);
      const script = path.join(getExtensionPath() || root, 'backends', 'mcp', 'ai_provider.py');
      const provider = String(message.provider || '');
      const model = String(message.model || '');
      const displayModel = model ? `${provider}@${model}` : provider;
      const args = [script, 'call', '--provider', provider, '--stream-output'];
      if (message.model) args.push('--model', String(message.model));
      if (message.context) args.push('--context', String(message.context));
      const temperature = Number(message.temperature);
      const topP = Number(message.top_p);
      const maxTokens = Number(message.max_tokens);
      if (Number.isFinite(temperature) && temperature >= 0 && temperature <= 2) {
        args.push('--temperature', String(temperature));
      }
      if (Number.isFinite(topP) && topP > 0 && topP <= 1) {
        args.push('--top-p', String(topP));
      }
      if (Number.isInteger(maxTokens) && maxTokens >= 1 && maxTokens <= 131072) {
        args.push('--max-tokens', String(maxTokens));
      }
      const proc = cp.spawn(pythonExe, args, { cwd: root, timeout: 90000 });
      let resultSent = false;
      let stderrBuf = '';
      let tokenBuffer = '';
      let tokenBufferFragments = 0;
      let tokenFlushTimer = null;
      let rl = null;
      const flushTokenBuffer = () => {
        if (tokenFlushTimer !== null) {
          clearTimeout(tokenFlushTimer);
          tokenFlushTimer = null;
        }
        if (!tokenBuffer) return;
        const content = tokenBuffer;
        const fragments = tokenBufferFragments;
        tokenBuffer = '';
        tokenBufferFragments = 0;
        panel.webview.postMessage({
          type: 'hubOllamaStream',
          event: { type: 'token', content, fragments },
          model: displayModel,
          ...(requestId ? { requestId } : {}),
        });
      };
      const scheduleTokenFlush = () => {
        if (tokenFlushTimer === null) {
          tokenFlushTimer = setTimeout(flushTokenBuffer, 80);
        }
      };
      const sendResult = (event) => {
        if (resultSent) return;
        resultSent = true;
        clearAiProcess(requestId);
        flushTokenBuffer();
        setTimeout(() => {
          panel.webview.postMessage({
            type: 'hubOllamaResult',
            ok: event.ok !== false,
            model: displayModel,
            output: event.text || '',
            usage: event.usage && typeof event.usage === 'object' ? event.usage : {},
            error: event.ok === false ? (event.error || 'Erreur inconnue') : undefined,
            ...(requestId ? { requestId } : {}),
          });
        }, 100);
      };

      const cancelRequest = () => {
        if (resultSent) return;
        resultSent = true;
        flushTokenBuffer();
        rl?.close?.();
        proc.kill?.('SIGTERM');
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: false,
          cancelled: true,
          model: displayModel,
          output: '',
          ...(requestId ? { requestId } : {}),
        });
      };
      registerAiProcess(requestId, cancelRequest);

      proc.stderr.on('data', (chunk) => { stderrBuf += String(chunk); });
      rl = readline.createInterface({ input: proc.stdout, crlfDelay: Infinity });
      rl.on('line', (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;
        let event;
        try { event = JSON.parse(trimmed); } catch { return; }
        if (event.type === 'token') {
          tokenBuffer += String(event.content || '');
          tokenBufferFragments += 1;
          scheduleTokenFlush();
        } else if (event.type === 'done' || event.type === 'error') {
          sendResult(event);
        }
      });
      proc.on('close', (code) => {
        if (!resultSent) {
          sendResult({
            ok: false,
            error: stderrBuf.trim() || `Provider bridge exited with code ${code}`,
          });
        }
      });
      proc.on('error', (err) => {
        sendResult({ ok: false, error: String(err.message || err) });
      });
      proc.stdin.write(String(message.prompt || '') + '\n');
      proc.stdin.end();
    },
    hubAiCancel: (message) => {
      const requestId = String(message.requestId || '').trim();
      if (!cancelAiProcess(requestId)) {
        panel.webview.postMessage({
          type: 'hubOllamaResult',
          ok: false,
          cancelled: true,
          output: '',
          ...(requestId ? { requestId } : {}),
        });
      }
    },
    hubExportConversation: async (message) => {
      const markdown = String(message.markdown || '');
      const json = message.json && typeof message.json === 'object' ? message.json : null;
      if (!markdown || !json) return;
      const selected = await vscode.window.showQuickPick(
        [
          {
            label: 'Markdown',
            description: 'Lisible, partageable et compatible avec les outils de documentation',
            value: 'markdown',
          },
          {
            label: 'JSON',
            description: 'Structuré avec métadonnées, modèles et consommation de tokens',
            value: 'json',
          },
        ],
        {
          title: 'Exporter la conversation IA',
          placeHolder: 'Choisir un format',
        },
      );
      if (!selected) return;
      const format = selected.value === 'json' ? 'json' : 'markdown';
      const ext = format === 'json' ? 'json' : 'md';
      const safeBaseName = path.basename(String(message.suggestedName || 'conversation-ia'))
        .replace(/\.[^.]+$/, '')
        .replace(/[^a-z0-9._-]+/gi, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 80) || 'conversation-ia';
      const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(path.join(root, `${safeBaseName}.${ext}`)),
        filters: format === 'json'
          ? { 'JSON': ['json'] }
          : { 'Markdown': ['md', 'markdown'] },
      });
      if (!uri) return;
      const content = format === 'json' ? `${JSON.stringify(json, null, 2)}\n` : markdown;
      fs.writeFileSync(uri.fsPath, content, 'utf8');
      vscode.window.showInformationMessage(
        `Conversation exportée : ${path.basename(uri.fsPath)}`,
      );
    },
    hubExportData: async (message) => {
      const { dataType, format, data, suggestedName } = message;
      if (!data || !format) return;
      const ext = format === 'csv' ? '.csv' : '.json';
      const defaultName = suggestedName || `${dataType}_export${ext}`;
      const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(path.join(ctx.root, defaultName)),
        filters: format === 'csv' ? { 'CSV': ['csv'] } : { 'JSON': ['json'] },
      });
      if (!uri) return;
      let content;
      if (format === 'json') {
        content = JSON.stringify(data, null, 2);
      } else {
        let rows = Array.isArray(data) ? data : (data.items || data.rows || []);
        if (dataType === 'xrefs' && data.refs) {
          rows = data.refs.map((r) => ({ from_addr: r.from_addr, type: r.type, text: (r.text || '').substring(0, 200), target_addr: data.addr }));
        } else if (dataType === 'xrefs' && data.targets?.length) {
          rows = data.targets.map((a) => ({ from_addr: data.addr, target_addr: a }));
        }
        const headers = rows.length ? Object.keys(rows[0]) : [];
        const csvRow = (obj) => headers.map((h) => {
          const v = obj[h];
          const s = String(v == null ? '' : v);
          return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g, '""')}"` : s;
        }).join(',');
        content = [headers.join(','), ...rows.map(csvRow)].join('\n');
      }
      fs.writeFileSync(uri.fsPath, content, 'utf8');
      vscode.window.showInformationMessage(`Exporté : ${path.basename(uri.fsPath)}`);
    },
  };
}

module.exports = sharedHandlers;
module.exports.isSupportedBinary = isSupportedBinary;
module.exports.inspectBinaryInput = inspectBinaryInput;
module.exports.normalizeRawProfile = normalizeRawProfile;
module.exports.RAW_ARCH_ITEMS = RAW_ARCH_ITEMS;
module.exports.getRawArchDescriptor = getRawArchDescriptor;
module.exports.normalizeRawArchName = normalizeRawArchName;
