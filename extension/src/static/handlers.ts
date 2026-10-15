// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file handlers.js
 * @brief Registre des handlers de messages webview, organisés par domaine.
 */

const sharedHandlers = require('../shared/sharedHandlers');
const staticHandlers = require('./staticHandlers');
const { createTelemetryHandlers } = require('../shared/telemetry/telemetryMessageHandler');

/**
 * @brief Crée le registre des handlers pour un hub donné.
 * @param {object} config - Configuration du hub (root, panel, pythonExe, etc.)
 * @returns {Object.<string, Function>} Map messageType -> handler(message)
 */
function createHandlers(config) {
  const shared = sharedHandlers(config);
  const static_ = staticHandlers(config);
  const telemetry = createTelemetryHandlers(config.telemetry);
  return { ...shared, ...static_, ...telemetry };
}

module.exports = { createHandlers };
