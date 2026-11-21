// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file settingsSchema.ts
 * @brief Schéma des réglages persistés (`pof-settings`) : validation des envois du
 *        webview et migration des réglages déjà enregistrés (POF-P1-002).
 */

const path = require('path');

const SETTINGS_STATE_KEY = 'pof-settings';

const SETTINGS_DEFAULTS = Object.freeze({
  pythonPath: '',
  authServerUrl: '',
  aiTemperature: 0.7,
  aiTopP: 0.9,
  aiMaxTokens: 4096,
  aiPricingRules: [],
  decompilerProvider: 'docker',
  decompilerLocalPaths: {},
  stringsEncoding: 'auto',
  stringsMinLen: 4,
  asmSyntax: 'intel',
  lang: 'fr',
  defaultPanel: 'dashboard',
  codeFontSize: 13,
  interfaceMode: 'advanced',
  enabledStaticFeatures: [],
});

// Bornes alignées sur front/shared/panel-options.html et aiGenerationSettings.js.
const LIMITS = Object.freeze({
  maxPathLength: 4096,
  maxUrlLength: 2048,
  maxIdLength: 128,
  maxModelLength: 256,
  maxPricingRules: 200,
  maxPricePerMillion: 1e6,
  maxLocalPaths: 64,
  maxStaticFeatures: 256,
  aiTemperature: [0, 2],
  aiTopP: [0.01, 1],
  aiMaxTokens: [1, 131072],
  stringsMinLen: [1, 1000],
  codeFontSize: [8, 48],
  bindiffThreshold: [0, 1],
});

// Réglages qui désignent un exécutable : seul le Host peut les fixer (sélection native).
// Le webview peut seulement renvoyer la valeur courante ou la vider.
const HOST_MANAGED_KEYS = new Set(['pythonPath']);

// python, python3, python3.12, python.exe, python3.exe…
const PYTHON_EXECUTABLE_NAME = /^python[0-9.]*(\.exe)?$/i;
const IDENTIFIER = /^[\w.:@/-]+$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const PRICING_RULE_KEYS = new Set(['id', 'model', 'inputPerMillion', 'outputPerMillion', 'effectiveDate', 'currency']);

type Check = { ok: boolean; value?: any; reason?: string };
type Validator = (value: any) => Check;
type Settings = Record<string, any>;

const ok = (value: any): Check => ({ ok: true, value });
const fail = (reason: string): Check => ({ ok: false, reason });
const isPlainObject = (value: any): boolean => !!value && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype;
const hasOwn = (obj: object, key: string): boolean => Object.prototype.hasOwnProperty.call(obj, key);

const oneOf = (...values: string[]): Validator => (value) => (
  values.includes(value) ? ok(value) : fail(`expected one of ${values.join(', ')}`)
);

function numberIn([min, max]: readonly number[], { integer = false } = {}): Validator {
  return (value) => {
    if (typeof value !== 'number' || !Number.isFinite(value)) return fail('expected a finite number');
    if (integer && !Number.isInteger(value)) return fail('expected an integer');
    if (value < min || value > max) return fail(`expected a value between ${min} and ${max}`);
    return ok(value);
  };
}

function boundedString(maxLength: number, { allowEmpty = true } = {}): Validator {
  return (value) => {
    if (typeof value !== 'string') return fail('expected a string');
    if (!allowEmpty && !value.trim()) return fail('expected a non-empty string');
    if (value.length > maxLength) return fail(`expected at most ${maxLength} characters`);
    if (value.includes('\0')) return fail('unexpected NUL character');
    return ok(value);
  };
}

const identifier: Validator = (value) => (
  typeof value === 'string' && value.length <= LIMITS.maxIdLength && IDENTIFIER.test(value)
    ? ok(value)
    : fail('expected an identifier')
);

const optionalIsoDate: Validator = (value) => (
  value === undefined || value === '' || (typeof value === 'string' && ISO_DATE.test(value))
    ? ok(value)
    : fail('effectiveDate must be YYYY-MM-DD')
);

function validatePricingRule(rule: any): Check {
  if (!isPlainObject(rule)) return fail('expected an object');
  const unknown = Object.keys(rule).find((key) => !PRICING_RULE_KEYS.has(key));
  if (unknown) return fail(`unknown key ${unknown}`);
  const price = numberIn([0, LIMITS.maxPricePerMillion]);
  const checks = [
    boundedString(LIMITS.maxIdLength)(rule.id ?? ''),
    boundedString(LIMITS.maxModelLength, { allowEmpty: false })(rule.model),
    price(rule.inputPerMillion ?? 0),
    price(rule.outputPerMillion ?? 0),
    optionalIsoDate(rule.effectiveDate),
    rule.currency === undefined || rule.currency === 'USD' ? ok(rule.currency) : fail('currency must be USD'),
  ];
  return checks.find((check) => !check.ok) || ok({ ...rule });
}

function arrayOf(itemValidator: Validator, maxItems: number): Validator {
  return (value) => {
    if (!Array.isArray(value)) return fail('expected an array');
    if (value.length > maxItems) return fail(`expected at most ${maxItems} items`);
    for (let index = 0; index < value.length; index += 1) {
      const result = itemValidator(value[index]);
      if (!result.ok) return fail(`item ${index}: ${result.reason}`);
    }
    return ok(value.map((item) => (isPlainObject(item) ? { ...item } : item)));
  };
}

function validateLocalPaths(value: any): Check {
  if (!isPlainObject(value)) return fail('expected an object');
  const entries = Object.entries(value);
  if (entries.length > LIMITS.maxLocalPaths) return fail(`expected at most ${LIMITS.maxLocalPaths} entries`);
  for (const [key, localPath] of entries) {
    if (!identifier(key).ok) return fail(`invalid decompiler id ${JSON.stringify(key)}`);
    const result = boundedString(LIMITS.maxPathLength, { allowEmpty: false })(localPath);
    if (!result.ok) return fail(`${key}: ${result.reason}`);
  }
  return ok(Object.fromEntries(entries));
}

/** Nom de fichier plausible pour un interpréteur Python. */
function isPythonExecutableName(filePath: unknown): boolean {
  return typeof filePath === 'string' && PYTHON_EXECUTABLE_NAME.test(path.basename(filePath));
}

/** Forme acceptable d'un pythonPath enregistré : vide, ou chemin absolu vers un exécutable python*. */
function validateStoredPythonPath(value: any): Check {
  const result = boundedString(LIMITS.maxPathLength)(value);
  if (!result.ok || value === '') return result;
  if (!path.isAbsolute(value)) return fail('pythonPath must be an absolute path');
  if (!isPythonExecutableName(value)) return fail('pythonPath must point to a Python executable');
  return ok(value);
}

const SETTINGS_SCHEMA: Readonly<Record<string, Validator>> = Object.freeze({
  pythonPath: validateStoredPythonPath,
  authServerUrl: boundedString(LIMITS.maxUrlLength),
  aiTemperature: numberIn(LIMITS.aiTemperature),
  aiTopP: numberIn(LIMITS.aiTopP),
  aiMaxTokens: numberIn(LIMITS.aiMaxTokens, { integer: true }),
  aiPricingRules: arrayOf(validatePricingRule, LIMITS.maxPricingRules),
  decompilerProvider: oneOf('auto', 'local', 'docker'),
  decompilerLocalPaths: validateLocalPaths,
  stringsEncoding: oneOf('auto', 'utf-8', 'utf-16-le', 'utf-16-be'),
  stringsMinLen: numberIn(LIMITS.stringsMinLen, { integer: true }),
  asmSyntax: oneOf('intel', 'att'),
  lang: oneOf('fr', 'en'),
  defaultPanel: oneOf('dashboard', 'static', 'dynamic', 'outils'),
  codeFontSize: numberIn(LIMITS.codeFontSize, { integer: true }),
  interfaceMode: oneOf('simple', 'advanced'),
  // Plugin tab ids come from plugin manifests: bounded strings rather than a strict pattern.
  enabledStaticFeatures: arrayOf(boundedString(LIMITS.maxIdLength, { allowEmpty: false }), LIMITS.maxStaticFeatures),
  bindiffThreshold: numberIn(LIMITS.bindiffThreshold),
});

/**
 * Migration des réglages existants : les clés inconnues et les valeurs invalides
 * (dont un pythonPath arbitraire) sont retirées ; les défauts s'appliquent alors.
 */
function migrateStoredSettings(raw: unknown): { settings: Settings; dropped: string[] } {
  const settings: Settings = {};
  const dropped: string[] = [];
  if (raw == null) return { settings, dropped };
  if (!isPlainObject(raw)) return { settings, dropped: ['<root>'] };
  for (const [key, value] of Object.entries(raw as Settings)) {
    const result = hasOwn(SETTINGS_SCHEMA, key) ? SETTINGS_SCHEMA[key](value) : fail('unknown key');
    if (result.ok) settings[key] = result.value;
    else dropped.push(key);
  }
  return { settings, dropped };
}

/**
 * Valide un envoi `hubSaveSettings`. L'envoi entier est refusé en cas de clé inconnue,
 * de type ou borne invalide, ou de modification d'un réglage géré par le Host.
 * @param incoming - réglages reçus du webview (non fiables)
 * @param current  - réglages enregistrés (déjà migrés)
 */
function validateSettingsUpdate(incoming: unknown, current: Settings = {}): { ok: boolean; settings?: Settings; errors?: string[] } {
  if (!isPlainObject(incoming)) return { ok: false, errors: ['settings: expected an object'] };
  const errors: string[] = [];
  const accepted: Settings = {};
  for (const [key, value] of Object.entries(incoming as Settings)) {
    if (!hasOwn(SETTINGS_SCHEMA, key)) {
      errors.push(`${key}: unknown key`);
    } else if (HOST_MANAGED_KEYS.has(key) && value !== '' && value !== (current[key] ?? '')) {
      errors.push(`${key}: can only be set by the extension host`);
    } else {
      const result = SETTINGS_SCHEMA[key](value);
      if (result.ok) accepted[key] = result.value;
      else errors.push(`${key}: ${result.reason}`);
    }
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, settings: { ...current, ...accepted } };
}

/** Copie modifiable des défauts (tableaux et objets imbriqués non partagés). */
function cloneSettingsDefaults(): Settings {
  return JSON.parse(JSON.stringify(SETTINGS_DEFAULTS));
}

/** Réglages enregistrés et migrés, sans les défauts. */
function readStoredSettings(store: { get?: (key: string, fallback?: unknown) => any } | null | undefined): Settings {
  return migrateStoredSettings(store?.get?.(SETTINGS_STATE_KEY, {})).settings;
}

/** Réglages enregistrés complétés par les défauts, tels qu'envoyés au webview. */
function readSettingsWithDefaults(store): Settings {
  return { ...cloneSettingsDefaults(), ...readStoredSettings(store) };
}

module.exports = {
  SETTINGS_STATE_KEY,
  SETTINGS_DEFAULTS,
  SETTINGS_LIMITS: LIMITS,
  cloneSettingsDefaults,
  isPythonExecutableName,
  migrateStoredSettings,
  validateSettingsUpdate,
  readStoredSettings,
  readSettingsWithDefaults,
};
