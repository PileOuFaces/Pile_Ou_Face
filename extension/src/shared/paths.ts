// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file paths.js
 * @brief Chemins centralisés vers les scripts Python du projet.
 * @details Unifie les chemins pour éviter la duplication et faciliter la maintenance.
 * Voir docs/ARCHITECTURE_AUDIT_PLAN.md.
 */

const path = require('path');

/**
 * @brief Retourne le chemin absolu vers un script Python dans backends/static/.
 */
function backendStatic(root, script) {
  return path.join(root, 'backends', 'static', script);
}

/**
 * @brief Retourne le chemin absolu vers un script Python dans backends/dynamic/.
 */
function backendDynamic(root, ...segments) {
  return path.join(root, 'backends', 'dynamic', ...segments);
}

/** backends/static/disasm/disasm.py — Désassemblage */
function getDisasmScript(root) {
  return backendStatic(root, 'disasm/disasm.py');
}

/** backends/static/binary/symbols.py — Extraction symboles */
function getSymbolsScript(root) {
  return backendStatic(root, 'binary/symbols.py');
}

/** backends/static/search/strings.py — Extraction strings */
function getStringsScript(root) {
  return backendStatic(root, 'search/strings.py');
}

/** backends/static/binary/sections.py — Sections ELF/Mach-O */
function getSectionsScript(root) {
  return backendStatic(root, 'binary/sections.py');
}

/** backends/static/binary/headers.py — Headers binaire */
function getHeadersScript(root) {
  return backendStatic(root, 'binary/headers.py');
}

/** backends/static/binary/build_binary_metadata.py — Modèle metadata binaire normalisé */
function getBinaryMetadataScript(root) {
  return backendStatic(root, 'binary/build_binary_metadata.py');
}

/** backends/static/disasm/cfg.py — Control Flow Graph */
function getCfgScript(root) {
  return backendStatic(root, 'disasm/cfg.py');
}

/** backends/static/disasm/call_graph.py — Graphe d'appels */
function getCallGraphScript(root) {
  return backendStatic(root, 'disasm/call_graph.py');
}

/** backends/static/disasm/discover_functions.py — Découverte de fonctions */
function getDiscoverFunctionsScript(root) {
  return backendStatic(root, 'disasm/discover_functions.py');
}

/** backends/static/search/search.py — Recherche binaire */
function getSearchScript(root) {
  return backendStatic(root, 'search/search.py');
}

/** backends/static/binary/offset_to_vaddr.py — Conversion offset → adresse virtuelle */
function getOffsetToVaddrScript(root) {
  return backendStatic(root, 'binary/offset_to_vaddr.py');
}

/** backends/static/disasm/xrefs.py — Cross-références */
function getXrefsScript(root) {
  return backendStatic(root, 'disasm/xrefs.py');
}

/** backends/static/rules/rules_manager.py — Gestionnaire de règles YARA/CAPA */
function getRulesManagerScript(root) {
  return backendStatic(root, 'rules/rules_manager.py');
}

/** backends/static/disasm/asm_sim.py — Simulation asm statique */
function getAsmStaticScript(root) {
  return backendStatic(root, 'disasm/asm_sim.py');
}

/** backends/dynamic/pipeline/run_pipeline.py — Pipeline dynamique */
function getRunPipelineScript(root) {
  return backendDynamic(root, 'pipeline', 'run_pipeline.py');
}

/** backends/dynamic/pipeline/payload_script_runner.py — Extraction de payloads depuis un script pwntools */
function getPayloadScriptRunnerScript(root) {
  return backendDynamic(root, 'pipeline', 'payload_script_runner.py');
}

/** Chemins de fallback pour exemples (examples/foo.elf, foo.elf, etc.) */
function getExampleCandidates(root, baseName) {
  return [
    path.join(root, 'examples', baseName + '.elf'),
    path.join(root, baseName + '.elf'),
    path.join(root, 'examples', baseName),
    path.join(root, baseName),
  ];
}

module.exports = {
  getDisasmScript,
  getSymbolsScript,
  getStringsScript,
  getSectionsScript,
  getHeadersScript,
  getBinaryMetadataScript,
  getCfgScript,
  getCallGraphScript,
  getDiscoverFunctionsScript,
  getSearchScript,
  getOffsetToVaddrScript,
  getXrefsScript,
  getRulesManagerScript,
  getAsmStaticScript,
  getRunPipelineScript,
  getPayloadScriptRunnerScript,
  getExampleCandidates,
};
