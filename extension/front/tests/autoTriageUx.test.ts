// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");

describe("auto-triage UX contracts", () => {
  const controllerSource = fs.readFileSync(
    path.resolve(__dirname, "../static/autoTriageController.js"),
    "utf8",
  );
  const progressSource = fs.readFileSync(
    path.resolve(__dirname, "../shared/taskProgressController.js"),
    "utf8",
  );
  const dashboardSource = fs.readFileSync(
    path.resolve(__dirname, "../shared/panel-dashboard.html"),
    "utf8",
  );
  const handlerSource = fs.readFileSync(
    path.resolve(__dirname, "../../src/static/staticHandlers.ts"),
    "utf8",
  );

  it("lets the host resolve the saved default provider when no model was explicitly selected", () => {
    expect(controllerSource).to.include("{ provider: '', model: '' }");
    expect(controllerSource).to.not.include("selected || (typeof ollamaUiState");
  });

  it("shows the configured function, time and token limits", () => {
    expect(progressSource).to.include("max_functions");
    expect(progressSource).to.include("max_seconds");
    expect(progressSource).to.include("max_tokens");
    expect(progressSource).to.include("tokens/réponse max");
    expect(progressSource).to.include("max_total_tokens");
    expect(progressSource).to.include("tokens/run max");
  });

  it("offers a real Markdown export through the native save dialog", () => {
    expect(dashboardSource).to.include("auto-triage-export-report");
    expect(controllerSource).to.include("hubAutoTriageExportReport");
    expect(handlerSource).to.include("showSaveDialog");
    expect(handlerSource).to.include("fs.promises.copyFile(reportPath, destination.fsPath)");
  });

  it("presents auto-triage as a dedicated confirmed workflow", () => {
    expect(dashboardSource).to.include("Automatisation IA");
    expect(dashboardSource).to.include('role="dialog"');
    expect(dashboardSource).to.include("auto-triage-confirm");
    expect(controllerSource).to.include("openPreflight");
    expect(controllerSource).to.include('Resume auto-triage');
    expect(controllerSource).to.include("hubAutoTriagePreflight");
  });

  it("keeps the completed task visible long enough to act on it", () => {
    expect(progressSource).to.include("30000");
  });

  it("consumes the pending preflight request when the dialog closes", () => {
    expect(controllerSource).to.match(/function closePreflight\(\) \{\s+pendingBinaryPath = '';/);
    expect(controllerSource).to.include("pendingBinaryPath === path && modal?.hidden");
  });
});
