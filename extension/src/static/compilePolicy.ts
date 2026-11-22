// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file compilePolicy.ts
 * @brief What the untrusted webview may ask the compiler to do (#548).
 *
 * The compilers run on the user's machine: a free option such as `-wrapper`,
 * `-fplugin=`, `-specs=`, `-B<dir>`, `@<file>` or clang's `-Xclang -load`
 * executes arbitrary code, and a free output path overwrites any file. So:
 * - options: only the exact tokens the panel produces (no free options in V1);
 * - source: an existing regular file with a source extension (realpath too),
 *   so another file (key, config) is never fed to the compiler;
 * - output: always a fresh private directory; copying elsewhere needs a path
 *   the user picked in the native save dialog of this session.
 */
const fs = require('fs');
const path = require('path');

const COMPILE_LANGS = ['c', 'cpp', 'rust', 'go'] as const;
// Union des cibles des chaînes livrées (docker/compilers/*/compilers.json, vérifiée par test).
const COMPILE_TARGETS = [
  'elf-x64', 'elf-x86', 'elf-arm64', 'elf-arm', 'elf-riscv64', 'elf-mips', 'elf-mipsel', 'elf-mips64el',
  'elf-ppc', 'elf-ppc64', 'elf-ppc64le', 'elf-sparc64', 'elf-s390x', 'elf-m68k', 'elf-sh4',
  'pe-x64', 'pe-x86', 'macho-arm64', 'macho-x64',
] as const;

const OPTIMIZATION_FLAGS = ['-O0', '-Og', '-O1', '-O2', '-O3', '-Os'];
const DEBUG_FLAGS = ['-g', '-ggdb'];
const CANARY_FLAGS = ['-fno-stack-protector', '-fstack-protector', '-fstack-protector-strong', '-fstack-protector-all'];
const PIE_FLAGS = ['-fno-pie', '-no-pie', '-fpie', '-pie'];
const RELRO_FLAGS = ['-Wl,-z,relro', '-Wl,-z,relro,-z,now'];
const SINGLE_FLAGS = new Set([
  ...OPTIMIZATION_FLAGS, ...DEBUG_FLAGS, ...CANARY_FLAGS, ...PIE_FLAGS, ...RELRO_FLAGS, '-static', '-s',
]);
// `-z` is a linker option prefix: only `-z execstack` is produced by the panel.
const PAIRED_FLAGS: Record<string, string> = { '-z': 'execstack' };

const SOURCE_EXTENSIONS: Record<string, string[]> = {
  c: ['.c'],
  cpp: ['.cpp', '.cc', '.cxx'],
  rust: ['.rs'],
  go: ['.go'],
};
const OUTPUT_EXTENSIONS: Record<string, string> = { pe: '.exe', elf: '.elf', macho: '' };
const MAX_FLAGS = 32;
const SAFE_STEM = /[^A-Za-z0-9._-]/g;
const MAX_STEM_LENGTH = 64;

type Result<T> = { ok: true; value: T } | { ok: false; reason: string };

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}

/** Exact-token allowlist; any other option rejects the whole request (never silently dropped). */
function validateCompileFlags(flags: unknown, lang: string): Result<string[]> {
  if (flags === undefined || flags === null) return { ok: true, value: [] };
  if (!Array.isArray(flags) || flags.length > MAX_FLAGS) return { ok: false, reason: 'compiler options must be a short list' };
  if (flags.length && lang !== 'c' && lang !== 'cpp') return { ok: false, reason: `no compiler options for ${lang}` };
  const accepted: string[] = [];
  for (let i = 0; i < flags.length; i += 1) {
    const flag = flags[i];
    if (typeof flag !== 'string') return { ok: false, reason: 'compiler options must be strings' };
    if (SINGLE_FLAGS.has(flag)) { accepted.push(flag); continue; }
    if (flag in PAIRED_FLAGS && flags[i + 1] === PAIRED_FLAGS[flag]) {
      accepted.push(flag, PAIRED_FLAGS[flag]);
      i += 1;
      continue;
    }
    return { ok: false, reason: `compiler option not allowed: ${JSON.stringify(flag.slice(0, 80))}` };
  }
  return { ok: true, value: accepted };
}

function validateLangTarget(lang: unknown, target: unknown): Result<{ lang: string; target: string }> {
  if (!isOneOf(lang, COMPILE_LANGS)) return { ok: false, reason: 'unknown source language' };
  if (!isOneOf(target, COMPILE_TARGETS)) return { ok: false, reason: 'unknown compilation target' };
  return { ok: true, value: { lang, target } };
}

/** Source to compile: absolute, existing regular file whose name and real name have a source extension. */
function validateSourcePath(source: unknown, lang: string, fsApi = fs): Result<string> {
  if (typeof source !== 'string' || !source || !path.isAbsolute(source)) {
    return { ok: false, reason: 'choose the source file with the … button' };
  }
  const allowed = SOURCE_EXTENSIONS[lang] || [];
  const hasSourceExtension = (p: string) => allowed.includes(path.extname(p).toLowerCase());
  let real: string;
  try {
    real = fsApi.realpathSync(source);
    if (!fsApi.statSync(real).isFile()) return { ok: false, reason: 'the source is not a regular file' };
  } catch {
    return { ok: false, reason: 'source file not found' };
  }
  if (!hasSourceExtension(source) || !hasSourceExtension(real)) {
    return { ok: false, reason: `the source must be a ${allowed.join('/')} file` };
  }
  return { ok: true, value: real };
}

/** File name of the compiled binary inside the private directory (never a path from the webview). */
function privateOutputName(source: string, target: string): string {
  const stem = path.basename(source, path.extname(source)).replace(SAFE_STEM, '_').slice(0, MAX_STEM_LENGTH);
  const ext = OUTPUT_EXTENSIONS[target.split('-')[0]] ?? '';
  return `${stem && !/^\.+$/.test(stem) ? stem : 'output'}${ext}`;
}

const STATIC_COMPILE_CHOICES: Record<string, readonly string[]> = {
  archBits: ['32', '64'],
  pieChoice: ['yes', 'no'],
  canary: ['off', 'basic', 'strong', 'all'],
  relro: ['off', 'partial', 'full'],
};

/**
 * hubCompileStaticBinary (C only, gcc of compileCSource): returns the refusal reason, or null.
 * Absent fields keep their defaults; present ones must be panel values.
 */
function checkStaticCompileMessage(message, resolveSource = (p: string) => p, fsApi = fs): string | null {
  for (const [field, allowed] of Object.entries(STATIC_COMPILE_CHOICES)) {
    if (message?.[field] !== undefined && !isOneOf(String(message[field]), allowed)) return `invalid ${field}`;
  }
  if (message?.optim !== undefined && !isOneOf(message.optim, OPTIMIZATION_FLAGS)) return 'invalid optimization level';
  if (message?.debug !== undefined && message.debug !== '' && !isOneOf(message.debug, DEBUG_FLAGS)) return 'invalid debug option';
  if (String(message?.extraFlags ?? '').trim()) return 'free compiler options are not supported';
  if (String(message?.binaryPath ?? '').trim()) return 'the output path cannot come from the panel';
  const source = validateSourcePath(resolveSource(String(message?.sourcePath || '').trim()), 'c', fsApi);
  return source.ok === false ? source.reason : null;
}

/**
 * Output paths chosen by the user in the native save dialog during this session. Matching is exact
 * (no normalisation: `a/link/../x` may resolve elsewhere through a symlink) and the write always uses
 * the path kept by the host, never the string sent back by the webview.
 */
function createExportRegistry() {
  const chosen = new Set<string>();
  return {
    remember(fsPath: string) { if (fsPath) chosen.add(fsPath); },
    attested(fsPath: unknown): string | null {
      return typeof fsPath === 'string' && chosen.has(fsPath) ? fsPath : null;
    },
  };
}

/** Exported to the chosen path without following a symlink planted there (temp file + rename). */
function exportCompiledBinary(privatePath: string, exportPath: string, writeFileAtomic, fsApi = fs): void {
  writeFileAtomic(exportPath, fsApi.readFileSync(privatePath), fsApi, 0o755);
}

module.exports = {
  COMPILE_LANGS,
  COMPILE_TARGETS,
  OPTIMIZATION_FLAGS,
  DEBUG_FLAGS,
  validateCompileFlags,
  validateLangTarget,
  validateSourcePath,
  checkStaticCompileMessage,
  privateOutputName,
  createExportRegistry,
  exportCompiledBinary,
};
