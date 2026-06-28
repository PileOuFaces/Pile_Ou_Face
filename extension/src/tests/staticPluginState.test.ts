const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");

describe("staticHandlers plugin discovery", () => {
  afterEach(() => {
    sinon.restore();
  });

  it("posts the summarized plugin state back to the webview", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      callback(
        null,
        JSON.stringify({
          search_paths: ["/workspace/.pile-ou-face/plugins"],
          summary: { active: 1 },
          attached: {
            commands: ["malware.behavior.run"],
            command_sources: {
              "malware.behavior.run": "pof.malware-triage-pro",
            },
          },
          plugins: [
            {
              id: "pof.malware-triage-pro",
              state: "active",
              manifest: {
                name: "Malware Triage Pro",
                version: "1.0.0",
                kind: "analysis-pack",
                distribution: { encrypted: true, bundle_format: "pofplug" },
                licensing: { required: true, mode: "key", status: "locked", message: "Clé requise" },
                ui: { family: "malware" },
                capabilities: {
                  analysis: ["behavior.enrich", "anti_analysis.enrich"],
                },
              },
            },
          ],
        }),
        "",
      );
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadPluginState();

    expect(execFile.calledOnce).to.equal(true);
    expect(execFile.firstCall.args[1]).to.deep.equal([
      "/workspace/backends/plugins/runtime.py",
      "--host-version",
      "0.1.0",
      "--api-version",
      "1",
      "list",
      "--attach",
    ]);
    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubPluginState",
      state: {
        loaded: true,
        pluginCount: 1,
        stateCounts: { active: 1 },
        activePluginIds: ["pof.malware-triage-pro"],
        capabilities: ["anti_analysis.enrich", "behavior.enrich"],
        capabilityMap: {
          "anti_analysis.enrich": true,
          "behavior.enrich": true,
        },
        attachedCommands: ["malware.behavior.run"],
        commandSources: {
          "malware.behavior.run": "pof.malware-triage-pro",
        },
        searchPaths: ["/workspace/.pile-ou-face/plugins"],
        families: {
          malware: true,
        },
        tabRegistrations: [],
        plugins: [
          {
            id: "pof.malware-triage-pro",
            name: "Malware Triage Pro",
            version: "1.0.0",
            kind: "analysis-pack",
            state: "active",
            family: "malware",
            capabilities: ["anti_analysis.enrich", "behavior.enrich"],
            rootPath: "",
            encrypted: true,
            bundleFormat: "pofplug",
            licenseRequired: true,
            licenseMode: "key",
            licenseStatus: "locked",
            licenseMessage: "Clé requise",
            licensePath: "",
            licenseId: "",
            licensee: "",
            licenseVerified: false,
            error: "",
            commands: ["malware.behavior.run"],
          },
        ],
        error: "",
      },
    });
  });

  it("resolves premium family from manifest ui.family field", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      callback(
        null,
        JSON.stringify({
          search_paths: ["/workspace/.pile-ou-face/plugins"],
          summary: { active: 1 },
          attached: {
            commands: ["offensive.func_similarity.run"],
            command_sources: {
              "offensive.func_similarity.run": "pof.offensive-research-pro",
            },
          },
          plugins: [
            {
              id: "pof.offensive-research-pro",
              state: "active",
              manifest: {
                name: "Offensive Research Pro",
                version: "1.0.0",
                kind: "analysis-pack",
                distribution: { encrypted: true, bundle_format: "pofplug" },
                licensing: { required: true, mode: "key", status: "unlocked", message: "" },
                ui: { family: "offensif" },
                capabilities: {
                  analysis: ["func_similarity.run", "bindiff.run"],
                },
              },
            },
          ],
        }),
        "",
      );
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadPluginState();

    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]?.state?.families).to.deep.equal({
      offensif: true,
    });
    expect(postMessage.firstCall.args[0]?.state?.plugins?.[0]?.family).to.equal("offensif");
  });

  it("loads taint through the audit plugin runtime command", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      if (args.includes("invoke") && args.includes("audit.taint.run")) {
        callback(
          null,
          JSON.stringify({
            ok: true,
            command: "audit.taint.run",
            result: {
              flows: [{ sink: "system", source: "argv" }],
              proof_dossiers: [{
                function: "main",
                kind: "TAINT_CONFIRMED",
                confidence: "HIGH",
                evidence: [{ source: "taint_flow", summary: "argv -> system via main" }],
                needs_review: false,
                next_steps: ["Confirmer le callsite dans le pseudo-C."],
                related: { apis: ["system"], callsites: [{ addr: "0x401000" }], taint_flows: [] },
              }],
            },
          }),
          "",
        );
        return;
      }
      callback(new Error(`unexpected args: ${args.join(" ")}`));
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadTaint({ binaryPath: "/tmp/test.bin" });

    expect(execFile.calledOnce).to.equal(true);
    expect(execFile.firstCall.args[1]).to.include.members([
      "/workspace/backends/plugins/runtime.py",
      "invoke",
      "audit.taint.run",
    ]);
    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubTaint",
      result: {
        flows: [{ sink: "system", source: "argv" }],
        proof_dossiers: [{
          function: "main",
          kind: "TAINT_CONFIRMED",
          confidence: "HIGH",
          evidence: [{ source: "taint_flow", summary: "argv -> system via main" }],
          needs_review: false,
          next_steps: ["Confirmer le callsite dans le pseudo-C."],
          related: { apis: ["system"], callsites: [{ addr: "0x401000" }], taint_flows: [] },
        }],
      },
    });
  });

  it("loads function similarity through the offensive plugin runtime command", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      if (args.includes("invoke") && args.includes("offensive.func_similarity.run")) {
        callback(
          null,
          JSON.stringify({
            ok: true,
            command: "offensive.func_similarity.run",
            result: {
              matches: [{
                name: "sub_1000",
                addr: "0x1000",
                match_name: "_SSL_read",
                ref_label: "openssl-starter",
                ref_source: "bundled",
                score: 0.91,
              }],
              references: [{
                id: "abc123",
                label: "openssl-starter",
                source: "bundled",
                function_count: 42,
              }],
              proof_dossiers: [{
                function: "sub_1000",
                kind: "FUNC_SIMILARITY",
                confidence: "HIGH",
                evidence: [{ source: "func_similarity", summary: "Match openssl-starter:_SSL_read à 91%" }],
                needs_review: false,
                next_steps: ["Ouvrir le pseudo-C ou le désassemblage de la fonction cible pour confirmer la logique partagée."],
                related: { references: [{ label: "openssl-starter", score: 0.91 }], callsites: [{ addr: "0x1000" }] },
              }],
              summary: { matches: 1, references: 1, by_confidence: { HIGH: 1, MEDIUM: 0, LOW: 0 } },
            },
          }),
          "",
        );
        return;
      }
      callback(new Error(`unexpected args: ${args.join(" ")}`));
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadFuncSimilarity({ binaryPath: "/tmp/test.bin", threshold: 0.5, top: 2 });

    expect(execFile.calledOnce).to.equal(true);
    expect(execFile.firstCall.args[1]).to.include.members([
      "/workspace/backends/plugins/runtime.py",
      "invoke",
      "offensive.func_similarity.run",
    ]);
    expect(execFile.firstCall.args[1]).to.include(JSON.stringify({
      action: "search_db",
      binaryPath: "/tmp/test.bin",
      threshold: 0.5,
      top: 2,
      workspaceRoot: "/workspace",
    }));
    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0].type).to.equal("hubFuncSimilarity");
    expect(postMessage.firstCall.args[0].result.matches).to.have.length(1);
    expect(postMessage.firstCall.args[0].result.proof_dossiers).to.have.length(1);
  });

  it("indexes a function similarity reference and refreshes the search state", async () => {
    const showOpenDialog = sinon.stub().resolves([
      { fsPath: "/tmp/ref.bin" },
    ]);
    const execFile = sinon.stub();
    execFile.onFirstCall().callsFake((pythonBin, args, options, callback) => {
      callback(
        null,
        JSON.stringify({
          ok: true,
          command: "offensive.func_similarity.run",
          result: {
            indexed: { label: "ref.bin", sha256: "abc123" },
            references: [{ id: "abc123", label: "ref.bin", source: "workspace", function_count: 12 }],
            stats: { workspace_binaries: 1 },
          },
        }),
        "",
      );
    });
    execFile.onSecondCall().callsFake((pythonBin, args, options, callback) => {
      callback(
        null,
        JSON.stringify({
          ok: true,
          command: "offensive.func_similarity.run",
          result: {
            matches: [],
            references: [{ id: "abc123", label: "ref.bin", source: "workspace", function_count: 12 }],
            proof_dossiers: [],
            stats: { workspace_binaries: 1, matches_found: 0 },
            summary: { matches: 0, references: 1, by_confidence: { HIGH: 0, MEDIUM: 0, LOW: 0 } },
          },
        }),
        "",
      );
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      vscode: {
        window: { showOpenDialog },
      },
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubFuncSimilarityIndexReference({ binaryPath: "/tmp/test.bin", threshold: 0.4, top: 3 });

    expect(showOpenDialog.calledOnce).to.equal(true);
    expect(execFile.calledTwice).to.equal(true);
    expect(execFile.firstCall.args[1]).to.include("offensive.func_similarity.run");
    expect(execFile.firstCall.args[1]).to.include(JSON.stringify({
      action: "index_reference",
      referencePath: "/tmp/ref.bin",
      label: "ref.bin",
      workspaceRoot: "/workspace",
    }));
    expect(execFile.secondCall.args[1]).to.include(JSON.stringify({
      action: "search_db",
      binaryPath: "/tmp/test.bin",
      threshold: 0.4,
      top: 3,
      workspaceRoot: "/workspace",
    }));
    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0].type).to.equal("hubFuncSimilarity");
    expect(postMessage.firstCall.args[0].result.operation).to.deep.equal({
      action: "index_reference",
      ok: true,
      indexed: { label: "ref.bin", sha256: "abc123" },
      error: null,
    });
  });

  it("returns a plugin required payload when the audit plugin command is missing", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      callback(
        null,
        JSON.stringify({
          ok: false,
          error: "Commande plugin introuvable: audit.vulns.run",
          command: "audit.vulns.run",
          available_commands: [],
        }),
        "",
      );
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadVulns({ binaryPath: "/tmp/test.bin" });

    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubVulns",
      result: {
        error: "Feature plugin requise: vuln_patterns",
        plugin_command: "",
        plugin_required: "vuln_patterns",
        feature: "vuln_patterns",
        ok: false,
      },
    });
  });

  it("loads malware behavior through the plugin runtime command", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      if (args.includes("invoke") && args.includes("malware.behavior.run")) {
        callback(
          null,
          JSON.stringify({
            ok: true,
            command: "malware.behavior.run",
            result: {
              score: 78,
              indicators: [{
                category: "NETWORK",
                severity: "HIGH",
                confidence: "HIGH",
                evidence: [{ summary: "connect", source: "behavior", confidence: "HIGH" }],
                offset: "0x401000",
                addr: "",
                function: "",
                needs_review: false,
                next_steps: ["Verifier si le signal reseau est reachable depuis un point d'entree utile."],
                related: {},
              }],
              proof_dossiers: [{
                kind: "NETWORK",
                function: "NETWORK signal",
                addr: "",
                confidence: "HIGH",
                severity: "HIGH",
                needs_review: false,
                finding_count: 1,
                evidence: [{ summary: "connect", source: "behavior", confidence: "HIGH" }],
                next_steps: ["Verifier si le signal reseau est reachable depuis un point d'entree utile."],
                related: {
                  behavior: [{
                    category: "NETWORK",
                    severity: "HIGH",
                    confidence: "HIGH",
                    evidence: [{ summary: "connect", source: "behavior", confidence: "HIGH" }],
                    offset: "0x401000",
                    addr: "",
                    function: "",
                    needs_review: false,
                    next_steps: ["Verifier si le signal reseau est reachable depuis un point d'entree utile."],
                    related: {},
                  }],
                },
              }],
              summary: {
                total_indicators: 1,
                categories: ["NETWORK"],
                score: 78,
              },
            },
          }),
          "",
        );
        return;
      }
      callback(new Error(`unexpected args: ${args.join(" ")}`));
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadBehavior({ binaryPath: "/tmp/test.bin" });

    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubBehavior",
      result: {
        score: 78,
        indicators: [{
          category: "NETWORK",
          severity: "HIGH",
          confidence: "HIGH",
          evidence: [{ summary: "connect", source: "behavior", confidence: "HIGH" }],
          offset: "0x401000",
          addr: "",
          function: "",
          needs_review: false,
          next_steps: ["Verifier si le signal reseau est reachable depuis un point d'entree utile."],
          related: {},
        }],
        proof_dossiers: [{
          kind: "NETWORK",
          function: "NETWORK signal",
          addr: "",
          confidence: "HIGH",
          severity: "HIGH",
          needs_review: false,
          finding_count: 1,
          evidence: [{ summary: "connect", source: "behavior", confidence: "HIGH" }],
          next_steps: ["Verifier si le signal reseau est reachable depuis un point d'entree utile."],
          related: {
            behavior: [{
              category: "NETWORK",
              severity: "HIGH",
              confidence: "HIGH",
              evidence: [{ summary: "connect", source: "behavior", confidence: "HIGH" }],
              offset: "0x401000",
              addr: "",
              function: "",
              needs_review: false,
              next_steps: ["Verifier si le signal reseau est reachable depuis un point d'entree utile."],
              related: {},
            }],
          },
        }],
        summary: {
          total_indicators: 1,
          categories: ["NETWORK"],
          score: 78,
        },
      },
    });
  });

  it("loads anti-analysis through the plugin runtime command", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      if (args.includes("invoke") && args.includes("malware.anti_analysis.run")) {
        callback(
          null,
          JSON.stringify({
            ok: true,
            command: "malware.anti_analysis.run",
            result: {
              techniques: [
                {
                  technique: "VM_DETECTION",
                  description: "VMware detecte",
                  bypass: "Patch la comparaison",
                  confidence: "HIGH",
                  addr: "0x401000",
                  evidence: [{ summary: "VMware detecte", source: "anti_analysis", confidence: "HIGH" }],
                  needs_review: false,
                  next_steps: ["Patch la comparaison"],
                  related: {},
                },
              ],
              proof_dossiers: [
                {
                  kind: "VM_DETECTION",
                  function: "VM_DETECTION",
                  addr: "0x401000",
                  confidence: "HIGH",
                  severity: "HIGH",
                  needs_review: false,
                  finding_count: 1,
                  evidence: [{ summary: "VMware detecte", source: "anti_analysis", confidence: "HIGH" }],
                  next_steps: ["Patch la comparaison"],
                  related: {
                    anti_analysis: [
                      {
                        technique: "VM_DETECTION",
                        description: "VMware detecte",
                        bypass: "Patch la comparaison",
                        confidence: "HIGH",
                        addr: "0x401000",
                        evidence: [{ summary: "VMware detecte", source: "anti_analysis", confidence: "HIGH" }],
                        needs_review: false,
                        next_steps: ["Patch la comparaison"],
                        related: {},
                      },
                    ],
                  },
                },
              ],
              summary: {
                total_techniques: 1,
                high_confidence: 1,
              },
              error: null,
            },
          }),
          "",
        );
        return;
      }
      callback(new Error(`unexpected args: ${args.join(" ")}`));
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadAntiAnalysis({ binaryPath: "/tmp/test.bin" });

    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubAntiAnalysisDone",
      result: {
        techniques: [
          {
            technique: "VM_DETECTION",
            description: "VMware detecte",
            bypass: "Patch la comparaison",
            confidence: "HIGH",
            addr: "0x401000",
            evidence: [{ summary: "VMware detecte", source: "anti_analysis", confidence: "HIGH" }],
            needs_review: false,
            next_steps: ["Patch la comparaison"],
            related: {},
          },
        ],
        proof_dossiers: [
          {
            kind: "VM_DETECTION",
            function: "VM_DETECTION",
            addr: "0x401000",
            confidence: "HIGH",
            severity: "HIGH",
            needs_review: false,
            finding_count: 1,
            evidence: [{ summary: "VMware detecte", source: "anti_analysis", confidence: "HIGH" }],
            next_steps: ["Patch la comparaison"],
            related: {
              anti_analysis: [
                {
                  technique: "VM_DETECTION",
                  description: "VMware detecte",
                  bypass: "Patch la comparaison",
                  confidence: "HIGH",
                  addr: "0x401000",
                  evidence: [{ summary: "VMware detecte", source: "anti_analysis", confidence: "HIGH" }],
                  needs_review: false,
                  next_steps: ["Patch la comparaison"],
                  related: {},
                },
              ],
            },
          },
        ],
        summary: {
          total_techniques: 1,
          high_confidence: 1,
        },
        error: null,
      },
    });
  });

  it("loads FLIRT through the plugin runtime command", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      if (args.includes("invoke") && args.includes("offensive.flirt.run")) {
        callback(
          null,
          JSON.stringify({
            ok: true,
            command: "offensive.flirt.run",
            result: {
              matches: [
                {
                  addr: "0x402000",
                  name: "memcpy",
                  lib: "libc",
                  confidence: "MEDIUM",
                  evidence: [{ summary: "Signature memcpy correlee a libc", source: "flirt", confidence: "MEDIUM" }],
                  needs_review: true,
                  next_steps: ["Comparer la signature detectee avec le pseudo-C et les imports voisins."],
                  related: {},
                },
              ],
              proof_dossiers: [
                {
                  kind: "FLIRT",
                  function: "memcpy",
                  addr: "0x402000",
                  confidence: "MEDIUM",
                  severity: "LOW",
                  needs_review: true,
                  finding_count: 1,
                  evidence: [{ summary: "Signature memcpy correlee a libc", source: "flirt", confidence: "MEDIUM" }],
                  next_steps: ["Comparer la signature detectee avec le pseudo-C et les imports voisins."],
                  related: {},
                },
              ],
              summary: {
                total_matches: 1,
                libraries: ["libc"],
              },
              error: null,
            },
          }),
          "",
        );
        return;
      }
      callback(new Error(`unexpected args: ${args.join(" ")}`));
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadFlirt({ binaryPath: "/tmp/test.bin" });

    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubFlirtDone",
      result: {
        matches: [
          {
            addr: "0x402000",
            name: "memcpy",
            lib: "libc",
            confidence: "MEDIUM",
            evidence: [{ summary: "Signature memcpy correlee a libc", source: "flirt", confidence: "MEDIUM" }],
            needs_review: true,
            next_steps: ["Comparer la signature detectee avec le pseudo-C et les imports voisins."],
            related: {},
          },
        ],
        proof_dossiers: [
          {
            kind: "FLIRT",
            function: "memcpy",
            addr: "0x402000",
            confidence: "MEDIUM",
            severity: "LOW",
            needs_review: true,
            finding_count: 1,
            evidence: [{ summary: "Signature memcpy correlee a libc", source: "flirt", confidence: "MEDIUM" }],
            next_steps: ["Comparer la signature detectee avec le pseudo-C et les imports voisins."],
            related: {},
          },
        ],
        summary: {
          total_matches: 1,
          libraries: ["libc"],
        },
        error: null,
      },
    });
  });

  it("returns a plugin required payload when the offensive bindiff command is missing", async () => {
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      callback(
        null,
        JSON.stringify({
          ok: false,
          error: "Commande plugin introuvable: offensive.bindiff.run",
          command: "offensive.bindiff.run",
          available_commands: [],
        }),
        "",
      );
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubLoadBindiff({ binaryA: "/tmp/a.bin", binaryB: "/tmp/b.bin", threshold: 0.6 });

    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubBindiff",
      result: {
        error: "Feature plugin requise: bindiff",
        plugin_command: "",
        plugin_required: "bindiff",
        feature: "bindiff",
        ok: false,
        functions: [],
        stats: {},
      },
    });
  });

  it("installs a plugin bundle through the host installer script", async () => {
    const workspacePluginRoot = "/workspace/.pile-ou-face/plugins";
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      callback(
        null,
        JSON.stringify({
          ok: true,
          plugin_id: "pof.vulnerability-audit-pro",
          installed_to: `${workspacePluginRoot}/pof.vulnerability-audit-pro`,
          source_kind: "bundle",
        }),
        "",
      );
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      vscode: {
        Uri: { file: (value) => ({ fsPath: value }) },
        window: {
          showOpenDialog: sinon.stub().resolves([{ fsPath: "/tmp/vulnerability-audit-pro-0.1.0.pofplug" }]),
        },
      },
      child_process: { execFile },
      fs: {
        existsSync: (target) => target === "/workspace/.pile-ou-face",
      },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubInstallPlugin({});

    expect(
      execFile.calledOnce,
      JSON.stringify(postMessage.firstCall?.args?.[0] || null),
    ).to.equal(true);
    expect(execFile.calledOnce).to.equal(true);
    expect(execFile.firstCall.args[1]).to.deep.equal([
      "/workspace/backends/plugins/install_plugin.py",
      "--source",
      "/tmp/vulnerability-audit-pro-0.1.0.pofplug",
      "--target-root",
      workspacePluginRoot,
      "--workspace",
      "/workspace",
    ]);
    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubPluginInstalled",
      scope: "workspace",
      source: "/tmp/vulnerability-audit-pro-0.1.0.pofplug",
      ok: true,
      plugin_id: "pof.vulnerability-audit-pro",
      installed_to: `${workspacePluginRoot}/pof.vulnerability-audit-pro`,
      source_kind: "bundle",
    });
  });

  it("installs a plugin license through the host installer script", async () => {
    const workspaceLicenseRoot = "/workspace/.pile-ou-face/licenses";
    const showOpenDialog = sinon.stub().resolves([
      { fsPath: "/tmp/vulnerability-audit-pro.license.json" },
    ]);
    const execFile = sinon.stub().callsFake((pythonBin, args, options, callback) => {
      callback(
        null,
        JSON.stringify({
          ok: true,
          plugin_id: "pof.vulnerability-audit-pro",
          installed_to: `${workspaceLicenseRoot}/pof.vulnerability-audit-pro.license.json`,
          target_root: workspaceLicenseRoot,
        }),
        "",
      );
    });

    const staticHandlers = proxyquire("../static/staticHandlers", {
      vscode: {
        Uri: { file: (value) => ({ fsPath: value }) },
        window: { showOpenDialog },
      },
      child_process: { execFile },
      fs: {
        existsSync: (target) => target === "/workspace/.pile-ou-face",
      },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
    });

    const postMessage = sinon.spy();
    const handlers = staticHandlers({
      root: "/workspace",
      panel: { webview: { postMessage } },
      context: {
        globalState: {
          get: () => ({}),
        },
      },
    });

    await handlers.hubInstallPluginLicense({});

    expect(showOpenDialog.calledOnce).to.equal(true);
    expect(showOpenDialog.firstCall.args[0].defaultUri).to.deep.equal({
      fsPath: workspaceLicenseRoot,
    });
    expect(execFile.calledOnce).to.equal(true);
    expect(execFile.firstCall.args[1]).to.deep.equal([
      "/workspace/backends/plugins/install_license.py",
      "--source",
      "/tmp/vulnerability-audit-pro.license.json",
      "--target-root",
      workspaceLicenseRoot,
      "--workspace",
      "/workspace",
    ]);
    expect(postMessage.calledOnce).to.equal(true);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubPluginLicenseInstalled",
      source: "/tmp/vulnerability-audit-pro.license.json",
      ok: true,
      plugin_id: "pof.vulnerability-audit-pro",
      installed_to: `${workspaceLicenseRoot}/pof.vulnerability-audit-pro.license.json`,
      target_root: workspaceLicenseRoot,
    });
  });
});
