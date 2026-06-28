/**
 * Configuration Mocha : mocke le module vscode avant tout chargement.
 * Permet aux tests unitaires de s'exécuter hors Extension Development Host.
 */
const path = require("path");
const Module = require("module");

const mockPath = path.resolve(__dirname, "mocks", "vscode.ts");
const originalResolve = Module._resolveFilename;

Module._resolveFilename = function (request, parent, isMain, options) {
  if (request === "vscode") {
    return mockPath;
  }
  return originalResolve.call(this, request, parent, isMain, options);
};
