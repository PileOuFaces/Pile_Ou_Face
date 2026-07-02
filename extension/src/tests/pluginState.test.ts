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
        analysis: ["demo.b.enrich", "demo.b.extra"],
        export: ["report.markdown"],
      },
    });

    expect(capabilities).to.deep.equal([
      "demo.b.enrich",
      "demo.b.extra",
      "report.markdown",
    ]);
  });

  it("summarizes active plugin families for the static hub", () => {
    const state = summarizePluginRuntimeState({
      attached: {
        commands: ["demo.a.run", "demo.b.run"],
        command_sources: {
          "demo.a.run": "pof.demo-a",
          "demo.b.run": "pof.demo-b",
        },
      },
      plugins: [
        {
          id: "pof.demo-a",
          state: "active",
          manifest: {
            name: "Demo Plugin A",
            version: "2.0.0",
            kind: "analysis-pack",
            ui: { family: "demo_a" },
            capabilities: {
              analysis: ["demo.a.extra", "demo.a.enrich"],
            },
          },
        },
        {
          id: "pof.demo-b",
          state: "active",
          manifest: {
            name: "Demo Plugin B",
            version: "1.2.0",
            kind: "analysis-pack",
            ui: { family: "demo_family" },
            capabilities: {
              analysis: ["demo.b.enrich", "demo.b.extra"],
            },
          },
        },
        {
          id: "pof.demo-c",
          state: "active",
          manifest: {
            name: "Demo Plugin C",
            version: "0.9.0",
            kind: "analysis-pack",
            ui: { family: "offensif" },
            capabilities: {
              analysis: ["demo.c.extra", "demo.c.run"],
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
              analysis: ["demo.c.text"],
            },
          },
        },
      ],
    });

    expect(state.loaded).to.equal(true);
    expect(state.pluginCount).to.equal(4);
    expect(state.searchPaths).to.deep.equal([]);
    expect(state.stateCounts).to.deep.equal({});
    expect(state.attachedCommands).to.deep.equal(["demo.a.run", "demo.b.run"]);
    expect(state.commandSources["demo.a.run"]).to.equal("pof.demo-a");
    expect(state.activePluginIds).to.deep.equal([
      "pof.demo-a",
      "pof.demo-b",
      "pof.demo-c",
    ]);
    expect(state.families).to.deep.equal({
      demo_a: true,
      demo_family: true,
      offensif: true,
    });
    expect(state.capabilityMap["demo.a.enrich"]).to.equal(true);
    expect(state.capabilityMap["demo.b.enrich"]).to.equal(true);
    expect(state.capabilityMap["demo.c.extra"]).to.equal(true);
    expect(state.capabilityMap["demo.c.text"]).to.equal(undefined);
    expect(state.plugins.find((plugin) => plugin.id === "pof.disabled-demo")?.state).to.equal("disabled");
    expect(state.plugins.find((plugin) => plugin.id === "pof.demo-a")?.commands).to.deep.equal(["demo.a.run"]);
    expect(state.plugins.find((p) => p.id === "pof.demo-b")?.family).to.equal("demo_family");
    expect(state.plugins.find((p) => p.id === "pof.demo-a")?.family).to.equal("demo_a");
    expect(state.plugins.find((p) => p.id === "pof.disabled-demo")?.family).to.equal(null);
  });

  it("returns null family when manifest omits ui.family", () => {
    const state = summarizePluginRuntimeState({
      attached: {
        commands: ["demo.b.run"],
        command_sources: {
          "demo.b.run": "pof.demo-b",
        },
      },
      summary: { active: 1 },
      plugins: [
        {
          id: "pof.demo-b",
          state: "active",
          manifest: {
            name: "Demo Plugin B",
            version: "1.2.0",
            kind: "analysis-pack",
            capabilities: {
              analysis: ["demo.b.enrich", "demo.b.extra"],
            },
          },
        },
      ],
    });

    expect(state.families).to.deep.equal({});
    expect(state.plugins[0]?.family).to.equal(null);
    expect(state.plugins[0]?.commands).to.deep.equal(["demo.b.run"]);
  });

  it("keeps manifest-declared families visible", () => {
    const state = summarizePluginRuntimeState({
      attached: {
        commands: ["demo.d.run"],
        command_sources: {
          "demo.d.run": "pof.demo-d",
        },
      },
      summary: { active: 1 },
      plugins: [
        {
          id: "pof.demo-d",
          state: "active",
          manifest: {
            name: "Demo Plugin D",
            version: "0.1.0",
            kind: "analysis-pack",
            ui: { family: "demo_d" },
            capabilities: {
              analysis: ["demo.d.run"],
            },
          },
        },
      ],
    });

    expect(state.families).to.deep.equal({ demo_d: true });
    expect(state.activePluginIds).to.deep.equal(["pof.demo-d"]);
    expect(state.plugins[0]?.family).to.equal("demo_d");
    expect(state.plugins[0]?.commands).to.deep.equal(["demo.d.run"]);
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
