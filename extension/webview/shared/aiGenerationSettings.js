// SPDX-License-Identifier: AGPL-3.0-only
(function initAiGenerationSettings(global) {
  const DEFAULTS = Object.freeze({
    temperature: 0.7,
    top_p: 0.9,
    max_tokens: 4096,
  });

  function clampNumber(value, fallback, min, max) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(max, Math.max(min, parsed));
  }

  function normalize(settings = {}, fallback = DEFAULTS) {
    return {
      temperature: clampNumber(settings.temperature, fallback.temperature, 0, 2),
      top_p: clampNumber(settings.top_p, fallback.top_p, 0.01, 1),
      max_tokens: Math.round(clampNumber(
        settings.max_tokens,
        fallback.max_tokens,
        1,
        131072,
      )),
    };
  }

  function fromGlobalSettings(settings = {}) {
    return normalize({
      temperature: settings.aiTemperature,
      top_p: settings.aiTopP,
      max_tokens: settings.aiMaxTokens,
    });
  }

  const api = { DEFAULTS, fromGlobalSettings, normalize };
  global.POFAiGenerationSettings = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
