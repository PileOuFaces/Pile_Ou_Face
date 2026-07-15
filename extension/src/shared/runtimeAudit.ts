// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * Runtime usage audit, disabled by default.
 *
 * Enable with POF_AUDIT_TRACE=1. Events are written as JSONL to:
 *   <storageDir>/audit-runtime-usage.jsonl
 */

const fs = require('fs');
const path = require('path');

const AUDIT_FILE = 'audit-runtime-usage.jsonl';
const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);

let _enabled = false;
let _auditPath = '';
let _logChannel = null;
let _patchedCommands = null;

function _isEnabledEnv() {
  return TRUE_VALUES.has(String(process.env.POF_AUDIT_TRACE || '').trim().toLowerCase());
}

function _safeDetails(details = {}) {
  const out = {};
  for (const [key, value] of Object.entries(details || {})) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'string') {
      out[key] = value.length > 240 ? `${value.slice(0, 240)}...` : value;
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      out[key] = value;
    } else if (Array.isArray(value)) {
      out[key] = value.slice(0, 12).map((item) => String(item).slice(0, 120));
    } else {
      out[key] = String(value).slice(0, 240);
    }
  }
  return out;
}

function configureRuntimeAudit({ storageDir = '', logChannel = null, vscode = null, enabled = false } = {}) {
  _enabled = (_isEnabledEnv() || enabled === true) && Boolean(storageDir);
  _logChannel = logChannel || null;
  _auditPath = _enabled ? path.join(storageDir, AUDIT_FILE) : '';
  if (_enabled) {
    try {
      fs.mkdirSync(storageDir, { recursive: true });
      _logChannel?.appendLine?.(`[audit] Runtime usage audit enabled: ${_auditPath}`);
    } catch (err) {
      _enabled = false;
      _auditPath = '';
      _logChannel?.appendLine?.(`[audit] disabled: ${err.message || err}`);
    }
  }
  patchCommandRegistration(vscode);
  return { enabled: _enabled, path: _auditPath };
}

function patchCommandRegistration(vscode) {
  if (!vscode?.commands?.registerCommand || _patchedCommands) return;
  const original = vscode.commands.registerCommand.bind(vscode.commands);
  vscode.commands.registerCommand = (commandId, handler) => {
    const wrapped = (...args) => {
      if (String(commandId || '').toLowerCase().includes('pileouface')) {
        recordRuntimeEvent('command', commandId, { argc: args.length });
      }
      return handler(...args);
    };
    return original(commandId, wrapped);
  };
  _patchedCommands = { vscode, original };
}

function resetRuntimeAudit() {
  if (_patchedCommands?.vscode?.commands) {
    _patchedCommands.vscode.commands.registerCommand = _patchedCommands.original;
  }
  _patchedCommands = null;
  _enabled = false;
  _auditPath = '';
  _logChannel = null;
}

function recordRuntimeEvent(kind, name, details = {}) {
  if (!_enabled || !_auditPath) return;
  const event = {
    ts: new Date().toISOString(),
    kind,
    name: String(name || ''),
    ..._safeDetails(details),
  };
  try {
    fs.appendFileSync(_auditPath, `${JSON.stringify(event)}\n`, 'utf8');
  } catch (err) {
    _logChannel?.appendLine?.(`[audit] write failed: ${err.message || err}`);
  }
}

function getRuntimeAuditState() {
  return { enabled: _enabled, path: _auditPath };
}

module.exports = {
  AUDIT_FILE,
  configureRuntimeAudit,
  getRuntimeAuditState,
  recordRuntimeEvent,
  resetRuntimeAudit,
};
