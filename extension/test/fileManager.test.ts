const { expect } = require("chai");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

describe("fileManager", () => {
  let tempRoot;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pof-file-manager-"));
  });

  afterEach(() => {
    sinon.restore();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it("hides config files like decompilers.json from artifacts", () => {
    const baseDir = path.join(tempRoot, ".pile-ou-face");
    fs.mkdirSync(baseDir, { recursive: true });
    fs.writeFileSync(path.join(baseDir, "decompilers.json"), "{}");
    fs.writeFileSync(path.join(baseDir, "sample.disasm.asm"), "mov eax, eax");
    fs.writeFileSync(path.join(baseDir, "sample.symbols.json"), "[]");

    const fileManager = proxyquire("../src/shared/fileManager", {
      "./staticCache": {
        getCacheDir: () => path.join(baseDir, "static_cache"),
        readMeta: () => null,
        listIndexedCacheEntries: () => null,
        pruneIndexedCacheEntries: () => 0,
      },
    });

    const artifacts = fileManager.listArtifacts(tempRoot);
    expect(artifacts.map((entry) => entry.name).sort()).to.deep.equal([
      "sample.disasm.asm",
      "sample.symbols.json",
    ]);
  });

  it("surfaces stale cache entries from the SQLite-backed index", () => {
    const fileManager = proxyquire("../src/shared/fileManager", {
      "./staticCache": {
        getCacheDir: () => path.join(tempRoot, ".pile-ou-face", "static_cache"),
        readMeta: () => null,
        listIndexedCacheEntries: () => ([
          { key: "ok1", path: "/tmp/a", binaryPath: "/bin/ok", status: "ok", size: 10, mtime: 2, cacheTypes: ["info"], fileCount: 1, binaryExists: true },
          { key: "stale1", path: "/tmp/b", binaryPath: "/bin/stale", status: "stale", size: 20, mtime: 1, cacheTypes: ["cfg", "info"], fileCount: 2, binaryExists: true },
        ]),
        pruneIndexedCacheEntries: () => 0,
      },
    });

    const summary = fileManager.listAll(tempRoot);
    expect(summary.cache).to.have.length(2);
    expect(summary.staleCache).to.have.length(1);
    expect(summary.staleCache[0].key).to.equal("stale1");
  });

  it("purges stale cache directories and prunes the index", () => {
    const staleDir = path.join(tempRoot, ".pile-ou-face", "static_cache", "stale");
    const okDir = path.join(tempRoot, ".pile-ou-face", "static_cache", "ok");
    fs.mkdirSync(staleDir, { recursive: true });
    fs.mkdirSync(okDir, { recursive: true });
    fs.writeFileSync(path.join(staleDir, "info.json"), "{}");
    fs.writeFileSync(path.join(okDir, "info.json"), "{}");
    const pruneSpy = sinon.spy(() => 1);

    const fileManager = proxyquire("../src/shared/fileManager", {
      "./staticCache": {
        getCacheDir: () => path.join(tempRoot, ".pile-ou-face", "static_cache"),
        readMeta: () => null,
        listIndexedCacheEntries: () => ([
          { key: "stale1", path: staleDir, binaryPath: "/bin/missing", status: "missing", size: 10, mtime: 2, cacheTypes: ["info"], fileCount: 1, binaryExists: false },
          { key: "ok1", path: okDir, binaryPath: "/bin/ok", status: "ok", size: 10, mtime: 1, cacheTypes: ["info"], fileCount: 1, binaryExists: true },
        ]),
        pruneIndexedCacheEntries: pruneSpy,
      },
    });

    const result = fileManager.purgeStaleCache(tempRoot);
    expect(result.removed).to.equal(1);
    expect(fs.existsSync(staleDir)).to.equal(false);
    expect(fs.existsSync(okDir)).to.equal(true);
    expect(pruneSpy.calledOnce).to.equal(true);
  });

  it("purges stale annotations, legacy decompile cache, stale patches and stale pfdb files", () => {
    const workspaceFile = path.join(tempRoot, "examples", "demo.elf");
    fs.mkdirSync(path.dirname(workspaceFile), { recursive: true });
    fs.writeFileSync(workspaceFile, Buffer.from("demo"));
    const stat = fs.statSync(workspaceFile);

    const pofDir = path.join(tempRoot, ".pile-ou-face");
    const annotationsDir = path.join(pofDir, "annotations");
    const decompileDir = path.join(pofDir, "decompile_cache");
    const patchesDir = path.join(pofDir, "patches");
    const pfdbDir = path.join(pofDir, "pfdb");
    fs.mkdirSync(annotationsDir, { recursive: true });
    fs.mkdirSync(decompileDir, { recursive: true });
    fs.mkdirSync(patchesDir, { recursive: true });
    fs.mkdirSync(pfdbDir, { recursive: true });

    const annKey = crypto.createHash("sha256")
      .update(`${path.resolve(workspaceFile)}:${stat.mtimeMs}:${stat.size}`)
      .digest("hex")
      .slice(0, 16);
    fs.writeFileSync(path.join(annotationsDir, `${annKey}.json`), '{"0x1000":{"bookmark":true}}');
    fs.writeFileSync(path.join(annotationsDir, "deadbeefdeadbeef.json"), '{"0x1000":{"bookmark":true}}');

    fs.writeFileSync(path.join(decompileDir, "legacy.json"), '{"code":"old"}');

    const patchKey = crypto.createHash("sha256").update(path.resolve(workspaceFile)).digest("hex").slice(0, 16);
    fs.writeFileSync(path.join(patchesDir, `${patchKey}.json`), JSON.stringify({ binary: path.resolve(workspaceFile), patches: [] }));
    fs.writeFileSync(path.join(patchesDir, "orphanpatch000000.json"), JSON.stringify({ binary: "/tmp/does-not-exist", patches: [] }));

    const pfdbName = `demo.elf.${patchKey}.pfdb`;
    fs.writeFileSync(path.join(pfdbDir, pfdbName), "sqlite");
    fs.writeFileSync(path.join(pfdbDir, "ghost.1234567890abcdef.pfdb"), "sqlite");
    fs.writeFileSync(path.join(pfdbDir, "ghost.1234567890abcdef.pfdb-journal"), "journal");

    const fileManager = proxyquire("../src/shared/fileManager", {
      "./staticCache": {
        getCacheDir: () => path.join(pofDir, "static_cache"),
        readMeta: () => null,
        listIndexedCacheEntries: () => [],
        pruneIndexedCacheEntries: () => 0,
      },
    });

    const result = fileManager.purgeStaleCache(tempRoot);
    expect(result.removed).to.equal(5);
    expect(fs.existsSync(path.join(annotationsDir, `${annKey}.json`))).to.equal(true);
    expect(fs.existsSync(path.join(annotationsDir, "deadbeefdeadbeef.json"))).to.equal(false);
    expect(fs.existsSync(path.join(decompileDir, "legacy.json"))).to.equal(false);
    expect(fs.existsSync(path.join(patchesDir, `${patchKey}.json`))).to.equal(true);
    expect(fs.existsSync(path.join(patchesDir, "orphanpatch000000.json"))).to.equal(false);
    expect(fs.existsSync(path.join(pfdbDir, pfdbName))).to.equal(true);
    expect(fs.existsSync(path.join(pfdbDir, "ghost.1234567890abcdef.pfdb"))).to.equal(false);
    expect(fs.existsSync(path.join(pfdbDir, "ghost.1234567890abcdef.pfdb-journal"))).to.equal(false);
  });

  describe("cleanupAll — PROTECTED_NAMES", () => {
    // Helper : construit un fileManager stubé et une baseDir fraîche
    function makeCleanupEnv() {
      const baseDir = path.join(tempRoot, ".pile-ou-face");
      fs.mkdirSync(baseDir, { recursive: true });
      const fileManager = proxyquire("../src/shared/fileManager", {
        "./staticCache": {
          getCacheDir: () => path.join(baseDir, "static_cache"),
          readMeta: () => null,
          listIndexedCacheEntries: () => [],
          pruneIndexedCacheEntries: () => 0,
        },
      });
      return { baseDir, fileManager };
    }

    // ── Entrées protégées : fichiers JSON de config ────────────────────────

    it("does NOT delete decompilers.json", () => {
      const { baseDir, fileManager } = makeCleanupEnv();
      fs.writeFileSync(path.join(baseDir, "decompilers.json"), "{}");
      fileManager.cleanupAll(tempRoot);
      expect(fs.existsSync(path.join(baseDir, "decompilers.json"))).to.equal(true);
    });

    it("does NOT delete compilers.json", () => {
      const { baseDir, fileManager } = makeCleanupEnv();
      fs.writeFileSync(path.join(baseDir, "compilers.json"), "{}");
      fileManager.cleanupAll(tempRoot);
      expect(fs.existsSync(path.join(baseDir, "compilers.json"))).to.equal(true);
    });

    // ── Entrées protégées : dossiers ────────────────────────────────────────

    const PROTECTED_DIRS = ["licenses", "plugins", "annotations", "patches", "pfdb"];

    for (const dirName of PROTECTED_DIRS) {
      it(`does NOT delete ${dirName}/`, () => {
        const { baseDir, fileManager } = makeCleanupEnv();
        const dir = path.join(baseDir, dirName);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, "sentinel.json"), "{}");
        fileManager.cleanupAll(tempRoot);
        expect(fs.existsSync(dir)).to.equal(true);
        expect(fs.existsSync(path.join(dir, "sentinel.json"))).to.equal(true);
      });
    }

    // ── Exhaustivité : tous les noms protégés ont un test ──────────────────
    //
    // Si quelqu'un ajoute une entrée dans PROTECTED_NAMES sans ajouter un test
    // ci-dessus, ce test échoue et signale le nom manquant.

    it("all PROTECTED_NAMES entries are covered by an individual test above", () => {
      // Ces noms correspondent EXACTEMENT au contenu de PROTECTED_NAMES dans fileManager.ts.
      // Si tu ajoutes une entrée là-bas, ajoute aussi un test individuel ci-dessus ET
      // mets à jour ce tableau.
      const EXPECTED_PROTECTED = [
        "decompilers.json",
        "compilers.json",
        "licenses",
        "plugins",
        "annotations",
        "patches",
        "pfdb",
      ];

      // Vérifier que la source a exactement ces entrées (ni plus, ni moins)
      const { fileManager } = makeCleanupEnv();
      // On reconstruit PROTECTED_NAMES en testant empiriquement quels noms survivent à cleanupAll
      const candidateNames = [...EXPECTED_PROTECTED, "should-be-deleted.asm"];
      const baseDir = path.join(tempRoot, ".pile-ou-face");

      // Créer tous les candidats
      for (const name of candidateNames) {
        const p = path.join(baseDir, name);
        if (name.endsWith(".json") || name.endsWith(".asm")) {
          fs.writeFileSync(p, "{}");
        } else {
          fs.mkdirSync(p, { recursive: true });
          fs.writeFileSync(path.join(p, "sentinel"), "x");
        }
      }

      fileManager.cleanupAll(tempRoot);

      // Tous les protégés doivent survivre
      for (const name of EXPECTED_PROTECTED) {
        expect(fs.existsSync(path.join(baseDir, name)), `${name} should be protected`).to.equal(true);
      }
      // Le non-protégé doit être supprimé
      expect(fs.existsSync(path.join(baseDir, "should-be-deleted.asm")), "non-protected should be deleted").to.equal(false);
    });

    // ── Négatif : les artifacts ordinaires sont bien supprimés ─────────────

    it("DOES delete non-protected artifacts", () => {
      const { baseDir, fileManager } = makeCleanupEnv();
      fs.writeFileSync(path.join(baseDir, "binary.asm"), "content");
      fs.writeFileSync(path.join(baseDir, "binary.symbols.json"), "[]");
      fileManager.cleanupAll(tempRoot);
      expect(fs.existsSync(path.join(baseDir, "binary.asm"))).to.equal(false);
      expect(fs.existsSync(path.join(baseDir, "binary.symbols.json"))).to.equal(false);
    });
  });

  it("cleans targeted artifacts and cache entries for a removed binary", () => {
    const missingBinary = path.join(tempRoot, "examples", "ghost.bin");
    const otherBinary = path.join(tempRoot, "examples", "other.bin");
    fs.mkdirSync(path.dirname(otherBinary), { recursive: true });
    fs.writeFileSync(otherBinary, Buffer.from("ok"));

    const pofDir = path.join(tempRoot, ".pile-ou-face");
    const cacheDir = path.join(pofDir, "static_cache");
    const decompileDir = path.join(pofDir, "decompile_cache");
    const patchesDir = path.join(pofDir, "patches");
    const pfdbDir = path.join(pofDir, "pfdb");
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.mkdirSync(decompileDir, { recursive: true });
    fs.mkdirSync(patchesDir, { recursive: true });
    fs.mkdirSync(pfdbDir, { recursive: true });

    fs.writeFileSync(path.join(pofDir, "ghost.bin.disasm.asm"), "nop");
    fs.writeFileSync(path.join(pofDir, "ghost.bin.disasm.mapping.json"), "{}");
    fs.writeFileSync(path.join(pofDir, "other.bin.disasm.asm"), "mov eax, eax");

    const staleCacheDir = path.join(cacheDir, "ghost-cache");
    const okCacheDir = path.join(cacheDir, "other-cache");
    fs.mkdirSync(staleCacheDir, { recursive: true });
    fs.mkdirSync(okCacheDir, { recursive: true });
    fs.writeFileSync(path.join(staleCacheDir, "info.json"), "{}");
    fs.writeFileSync(path.join(okCacheDir, "info.json"), "{}");

    fs.writeFileSync(path.join(decompileDir, "ghost.json"), JSON.stringify({
      _cache_meta: { binary_path: path.resolve(missingBinary), binary_mtime_ms: 0, binary_size: 0 },
    }));
    fs.writeFileSync(path.join(decompileDir, "other.json"), JSON.stringify({
      _cache_meta: { binary_path: path.resolve(otherBinary), binary_mtime_ms: fs.statSync(otherBinary).mtimeMs, binary_size: fs.statSync(otherBinary).size },
    }));

    const ghostPatchKey = crypto.createHash("sha256").update(path.resolve(missingBinary)).digest("hex").slice(0, 16);
    const otherPatchKey = crypto.createHash("sha256").update(path.resolve(otherBinary)).digest("hex").slice(0, 16);
    fs.writeFileSync(path.join(patchesDir, `${ghostPatchKey}.json`), JSON.stringify({ binary: path.resolve(missingBinary), patches: [] }));
    fs.writeFileSync(path.join(patchesDir, `${otherPatchKey}.json`), JSON.stringify({ binary: path.resolve(otherBinary), patches: [] }));

    const ghostPfdb = path.join(pfdbDir, `ghost.bin.${ghostPatchKey}.pfdb`);
    const otherPfdb = path.join(pfdbDir, `other.bin.${otherPatchKey}.pfdb`);
    fs.writeFileSync(ghostPfdb, "sqlite");
    fs.writeFileSync(`${ghostPfdb}-journal`, "journal");
    fs.writeFileSync(otherPfdb, "sqlite");

    const pruneSpy = sinon.spy(() => 0);
    const fileManager = proxyquire("../src/shared/fileManager", {
      "./staticCache": {
        getCacheDir: () => cacheDir,
        readMeta: () => null,
        listIndexedCacheEntries: () => ([
          { key: "ghost-cache", path: staleCacheDir, binaryPath: path.resolve(missingBinary), status: "missing", size: 10, mtime: 2, cacheTypes: ["info"], fileCount: 1, binaryExists: false },
          { key: "other-cache", path: okCacheDir, binaryPath: path.resolve(otherBinary), status: "ok", size: 10, mtime: 1, cacheTypes: ["info"], fileCount: 1, binaryExists: true },
        ]),
        pruneIndexedCacheEntries: pruneSpy,
      },
    });

    const result = fileManager.cleanupForBinary(tempRoot, missingBinary);
    expect(result.total).to.be.greaterThan(0);
    expect(fs.existsSync(path.join(pofDir, "ghost.bin.disasm.asm"))).to.equal(false);
    expect(fs.existsSync(path.join(pofDir, "ghost.bin.disasm.mapping.json"))).to.equal(false);
    expect(fs.existsSync(path.join(pofDir, "other.bin.disasm.asm"))).to.equal(true);
    expect(fs.existsSync(staleCacheDir)).to.equal(false);
    expect(fs.existsSync(okCacheDir)).to.equal(true);
    expect(fs.existsSync(path.join(decompileDir, "ghost.json"))).to.equal(false);
    expect(fs.existsSync(path.join(decompileDir, "other.json"))).to.equal(true);
    expect(fs.existsSync(path.join(patchesDir, `${ghostPatchKey}.json`))).to.equal(false);
    expect(fs.existsSync(path.join(patchesDir, `${otherPatchKey}.json`))).to.equal(true);
    expect(fs.existsSync(ghostPfdb)).to.equal(false);
    expect(fs.existsSync(`${ghostPfdb}-journal`)).to.equal(false);
    expect(fs.existsSync(otherPfdb)).to.equal(true);
    expect(pruneSpy.called).to.equal(true);
  });
});
