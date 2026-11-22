// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file privateTempDir.ts
 * @brief Per-user private temporary directory.
 *
 * The previous `os.tmpdir()/pile-ou-face/<hash>` path was predictable and shared: on a
 * multi-user machine another account could create it first and plant files (e.g. a trace
 * read by the visualizer) or symbolic links that the extension would then write through.
 * Here the base directory is `os.tmpdir()/pile-ou-face-<user>`, created with mode 0700 and
 * accepted only if it is a real directory owned by the current user and closed to others.
 * Otherwise a fresh random directory (mkdtemp, 0700) is used for this process.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const PRIVATE_DIR_MODE = 0o700;
const OTHERS_ACCESS_BITS = 0o077;
const BASE_PREFIX = 'pile-ou-face-';

type Deps = {
  tmpdir?: () => string;
  platform?: string;
  getuid?: (() => number) | undefined;
  username?: () => string;
  fsApi?: typeof fs;
  warn?: (message: string) => void;
};

let cachedBase: string | null = null;

function userTag({ platform = process.platform as string, getuid = process.getuid, username = () => os.userInfo().username }: Deps = {}): string {
  if (platform !== 'win32' && typeof getuid === 'function') return String(getuid());
  return String(username() || 'user').replace(/[^A-Za-z0-9_.-]/g, '_');
}

/** Problem that makes `dir` unsafe as a private base, or null. Never follows a symlink. */
function privateDirProblem(dir: string, { platform = process.platform, getuid = process.getuid, fsApi = fs }: Deps = {}): string | null {
  let info;
  try {
    info = fsApi.lstatSync(dir);
  } catch (err) {
    return `cannot inspect (${err?.code || err?.message || err})`;
  }
  if (info.isSymbolicLink()) return 'is a symbolic link';
  if (!info.isDirectory()) return 'is not a directory';
  // Windows: os.tmpdir() is already inside the user's profile; POSIX modes do not apply.
  if (platform === 'win32' || typeof getuid !== 'function') return null;
  if (info.uid !== getuid()) return `is owned by uid ${info.uid}`;
  if ((info.mode & OTHERS_ACCESS_BITS) !== 0) return `is accessible to other users (mode ${(info.mode & 0o777).toString(8)})`;
  return null;
}

/** The current user's private base directory (created on first use, cached per process). */
function privateTempBase(deps: Deps = {}): string {
  if (cachedBase && !deps.fsApi) return cachedBase;
  const { tmpdir = os.tmpdir, fsApi = fs, warn = () => {} } = deps;
  const base = path.join(tmpdir(), `${BASE_PREFIX}${userTag(deps)}`);
  try {
    fsApi.mkdirSync(base, { mode: PRIVATE_DIR_MODE });
  } catch (err) {
    if (err?.code !== 'EEXIST') warn(`[temp] cannot create ${base}: ${err?.message || err}`);
  }
  const problem = privateDirProblem(base, deps);
  let result = base;
  if (problem) {
    // Never reuse a directory someone else may control: take a random private one instead.
    result = fsApi.mkdtempSync(path.join(tmpdir(), BASE_PREFIX));
    warn(`[temp] ${base} ${problem}; using ${result} for this session`);
  }
  if (!deps.fsApi) cachedBase = result;
  return result;
}

/** Private subdirectory of the base (0700), created if needed. */
function ensurePrivateSubdir(name: string, deps: Deps = {}): string {
  const fsApi = deps.fsApi || fs;
  const dir = path.join(privateTempBase(deps), name);
  fsApi.mkdirSync(dir, { recursive: true, mode: PRIVATE_DIR_MODE });
  return dir;
}

/** File name derived from an untrusted identifier: no separator, no traversal. */
function safeFileStem(untrusted: unknown): string {
  return crypto.createHash('sha256').update(String(untrusted ?? '')).digest('hex').slice(0, 24);
}

/**
 * Writes `content` to `target` without following a symbolic link planted at `target`:
 * the data goes to a fresh file created exclusively next to it, then renamed over it.
 */
function writeFileAtomic(target: string, content: string | Uint8Array, fsApi = fs): void {
  const temp = `${target}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fsApi.writeFileSync(temp, content, { flag: 'wx', mode: 0o600 });
  try {
    fsApi.renameSync(temp, target);
  } catch (err) {
    try { fsApi.rmSync(temp, { force: true }); } catch { /* best effort: the rename error is what matters */ }
    throw err;
  }
}

function resetPrivateTempBaseForTests(): void {
  cachedBase = null;
}

module.exports = {
  PRIVATE_DIR_MODE,
  privateDirProblem,
  privateTempBase,
  ensurePrivateSubdir,
  safeFileStem,
  writeFileAtomic,
  resetPrivateTempBaseForTests,
};
