const { expect } = require("chai");

const {
  emptyPluginUiState,
  flattenPluginCapabilities,
  summarizePluginRuntimeState,
} = require("../static/pluginState");

describe("plugin state helpers", () => {
  it("flattens plugin capabilities across manifest sections", () => {
    const capabilities = flattenPluginCapabilities({
      capabilities: {
        analysis: ["behavior.enrich", "anti_analysis.enrich"],
        export: ["report.markdown"],
      },
    });

    expect(capabilities).to.deep.equal([
      "anti_analysis.enrich",
      "behavior.enrich",
      "report.markdown",
    ]);
  });

  it("summarizes active plugin families for the static hub", () => {
    const state = summarizePluginRuntimeState({
      attached: {
        commands: ["audit.vulns.run", "malware.behavior.run"],
        command_sources: {
          "audit.vulns.run": "pof.vulnerability-audit-pro",
          "malware.behavior.run": "pof.malware-triage-pro",
        },
      },
      plugins: [
        {
          id: "pof.vulnerability-audit-pro",
          state: "active",
          manifest: {
            name: "Vulnerability Audit Pro",
            version: "2.0.0",
            kind: "analysis-pack",
            ui: { family: "audit" },
            capabilities: {
              analysis: ["taint.enrich", "vuln_patterns.enrich"],
            },
          },
        },
        {
          id: "pof.malware-triage-pro",
          state: "active",
          manifest: {
            name: "Malware Triage Pro",
            version: "1.2.0",
            kind: "analysis-pack",
            ui: { family: "malware" },
            capabilities: {
              analysis: ["behavior.enrich", "anti_analysis.enrich"],
            },
          },
        },
        {
          id: "pof.offensive-research-pro",
          state: "active",
          manifest: {
            name: "Offensive Research Pro",
            version: "0.9.0",
            kind: "analysis-pack",
            ui: { family: "offensif" },
            capabilities: {
              analysis: ["rop_gadgets.run", "bindiff.run"],
            },
          },
        },
        {
          id: "pof.disabled-demo",
          state: "disabled",
          manifest: {
            name: "Disabled Demo",
            version: "0.1.0",
            kind: "analysis-pack",
            capabilities: {
              analysis: ["string_deobfuscate.run"],
            },
          },
        },
      ],
    });

    expect(state.loaded).to.equal(true);
    expect(state.pluginCount).to.equal(4);
    expect(state.searchPaths).to.deep.equal([]);
    expect(state.stateCounts).to.deep.equal({});
    expect(state.attachedCommands).to.deep.equal(["audit.vulns.run", "malware.behavior.run"]);
    expect(state.commandSources["audit.vulns.run"]).to.equal("pof.vulnerability-audit-pro");
    expect(state.activePluginIds).to.deep.equal([
      "pof.malware-triage-pro",
      "pof.offensive-research-pro",
      "pof.vulnerability-audit-pro",
    ]);
    expect(state.families).to.deep.equal({
      audit: true,
      malware: true,
      offensif: true,
    });
    expect(state.capabilityMap["vuln_patterns.enrich"]).to.equal(true);
    expect(state.capabilityMap["behavior.enrich"]).to.equal(true);
    expect(state.capabilityMap["rop_gadgets.run"]).to.equal(true);
    expect(state.capabilityMap["string_deobfuscate.run"]).to.equal(undefined);
    expect(state.plugins.find((plugin) => plugin.id === "pof.disabled-demo")?.state).to.equal("disabled");
    expect(state.plugins.find((plugin) => plugin.id === "pof.vulnerability-audit-pro")?.commands).to.deep.equal(["audit.vulns.run"]);
    expect(state.plugins.find((p) => p.id === "pof.malware-triage-pro")?.family).to.equal("malware");
    expect(state.plugins.find((p) => p.id === "pof.vulnerability-audit-pro")?.family).to.equal("audit");
    expect(state.plugins.find((p) => p.id === "pof.disabled-demo")?.family).to.equal(null);
  });

  it("returns null family when manifest omits ui.family", () => {
    const state = summarizePluginRuntimeState({
      attached: {
        commands: ["malware.behavior.run"],
        command_sources: {
          "malware.behavior.run": "pof.malware-triage-pro",
        },
      },
      summary: { active: 1 },
      plugins: [
        {
          id: "pof.malware-triage-pro",
          state: "active",
          manifest: {
            name: "Malware Triage Pro",
            version: "1.2.0",
            kind: "analysis-pack",
            capabilities: {
              analysis: ["behavior.enrich", "anti_analysis.enrich"],
            },
          },
        },
      ],
    });

    expect(state.families).to.deep.equal({});
    expect(state.plugins[0]?.family).to.equal(null);
    expect(state.plugins[0]?.commands).to.deep.equal(["malware.behavior.run"]);
  });

  it("keeps cross-analysis plugins visible through the croisee family", () => {
    const state = summarizePluginRuntimeState({
      attached: {
        commands: ["croisee.cross_analyze.run"],
        command_sources: {
          "croisee.cross_analyze.run": "pof.cross-analysis-pro",
        },
      },
      summary: { active: 1 },
      plugins: [
        {
          id: "pof.cross-analysis-pro",
          state: "active",
          manifest: {
            name: "Cross-Analysis Pro",
            version: "0.1.0",
            kind: "analysis-pack",
            ui: { family: "croisee" },
            capabilities: {
              analysis: ["croisee.cross_analyze.run"],
            },
          },
        },
      ],
    });

    expect(state.families).to.deep.equal({ croisee: true });
    expect(state.activePluginIds).to.deep.equal(["pof.cross-analysis-pro"]);
    expect(state.plugins[0]?.family).to.equal("croisee");
    expect(state.plugins[0]?.commands).to.deep.equal(["croisee.cross_analyze.run"]);
  });

  it("returns a safe empty state when plugin loading fails", () => {
    const state = emptyPluginUiState("runtime unavailable");

    expect(state.loaded).to.equal(false);
    expect(state.pluginCount).to.equal(0);
    expect(state.searchPaths).to.deep.equal([]);
    expect(state.stateCounts).to.deep.equal({});
    expect(state.attachedCommands).to.deep.equal([]);
    expect(state.commandSources).to.deep.equal({});
    expect(state.families).to.deep.equal({});
    expect(state.error).to.equal("runtime unavailable");
  });
});
