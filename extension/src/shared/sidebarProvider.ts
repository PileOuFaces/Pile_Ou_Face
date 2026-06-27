// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file sidebarProvider.js
 * @brief TreeDataProvider pour le panneau latéral Pile ou Face (Symboles, Strings, Calculette).
 */

const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const cp = require('child_process');
const { getSymbolsScript, getStringsScript, getSectionsScript } = require('./paths');
const { getExtensionPath } = require('./utils');

class SidebarSymbolsProvider {
  constructor(rootPath, pythonExe) {
    this.rootPath = rootPath;
    this.pythonExe = pythonExe;
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this.symbols = [];
    this.binaryPath = '';
    this._mode = 'static';
  }

  setMode(mode) {
    this._mode = mode;
    this._onDidChangeTreeData.fire();
  }

  refresh(binaryPath) {
    this.binaryPath = binaryPath || this.binaryPath;
    if (!this.binaryPath || !this.rootPath) {
      this.symbols = [];
      this._onDidChangeTreeData.fire();
      return;
    }
    const absPath = path.isAbsolute(this.binaryPath) ? this.binaryPath : path.join(this.rootPath, this.binaryPath);
    if (!fs.existsSync(absPath)) {
      this.symbols = [];
      this._onDidChangeTreeData.fire();
      return;
    }
    try {
      const out = cp.execSync(
        `"${this.pythonExe}" "${getSymbolsScript(this.rootPath)}" --binary "${absPath}"`,
        { encoding: 'utf8', cwd: this.rootPath, maxBuffer: 1024 * 1024, env: { ...process.env, PYTHONPATH: getExtensionPath() || this.rootPath } }
      );
      this.symbols = JSON.parse(out);
    } catch (_) {
      this.symbols = [];
    }
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (element) return [];
    if (this._mode !== 'static') {
      const item = new vscode.TreeItem('Non disponible en mode Dynamic', vscode.TreeItemCollapsibleState.None);
      item.description = 'Ouvrez Static pour analyser un binaire';
      return [item];
    }
    return this.symbols.map((s) => {
      const item = new vscode.TreeItem(`${s.addr} ${s.name}`, vscode.TreeItemCollapsibleState.None);
      item.description = s.type;
      item.tooltip = `${s.name} @ ${s.addr} (${s.type})`;
      item.contextValue = 'symbol';
      item.command = {
        command: 'pileOuFace.goToSymbolInDisasm',
        title: 'Aller à',
        arguments: [s.addr, this.binaryPath],
      };
      return item;
    });
  }
}

class SidebarStringsProvider {
  constructor(rootPath, pythonExe) {
    this.rootPath = rootPath;
    this.pythonExe = pythonExe;
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this.strings = [];
    this.binaryPath = '';
    this._mode = 'static';
  }

  setMode(mode) {
    this._mode = mode;
    this._onDidChangeTreeData.fire();
  }

  refresh(binaryPath) {
    this.binaryPath = binaryPath || this.binaryPath;
    if (!this.binaryPath || !this.rootPath) {
      this.strings = [];
      this._onDidChangeTreeData.fire();
      return;
    }
    const absPath = path.isAbsolute(this.binaryPath) ? this.binaryPath : path.join(this.rootPath, this.binaryPath);
    if (!fs.existsSync(absPath)) {
      this.strings = [];
      this._onDidChangeTreeData.fire();
      return;
    }
    try {
      const out = cp.execSync(
        `"${this.pythonExe}" "${getStringsScript(this.rootPath)}" --binary "${absPath}"`,
        { encoding: 'utf8', cwd: this.rootPath, maxBuffer: 1024 * 1024, env: { ...process.env, PYTHONPATH: getExtensionPath() || this.rootPath } }
      );
      this.strings = JSON.parse(out).slice(0, 100);
    } catch (_) {
      this.strings = [];
    }
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (element) return [];
    if (this._mode !== 'static') {
      const item = new vscode.TreeItem('Non disponible en mode Dynamic', vscode.TreeItemCollapsibleState.None);
      item.description = 'Ouvrez Static pour analyser un binaire';
      return [item];
    }
    return this.strings.map((s) => {
      const val = String(s.value || '').substring(0, 40) + (s.value?.length > 40 ? '…' : '');
      const item = new vscode.TreeItem(val, vscode.TreeItemCollapsibleState.None);
      item.description = s.addr;
      item.tooltip = `${s.addr}: ${s.value} — Clic pour aller au désassemblage`;
      item.contextValue = 'string';
      item.command = {
        command: 'pileOuFace.goToSymbolInDisasm',
        title: 'Aller à',
        arguments: [s.addr, this.binaryPath],
      };
      return item;
    });
  }
}

class SidebarSectionsProvider {
  constructor(rootPath, pythonExe) {
    this.rootPath = rootPath;
    this.pythonExe = pythonExe;
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this.sections = [];
    this.binaryPath = '';
    this._mode = 'static';
  }

  setMode(mode) {
    this._mode = mode;
    this._onDidChangeTreeData.fire();
  }

  refresh(binaryPath) {
    this.binaryPath = binaryPath || this.binaryPath;
    if (!this.binaryPath || !this.rootPath) {
      this.sections = [];
      this._onDidChangeTreeData.fire();
      return;
    }
    const absPath = path.isAbsolute(this.binaryPath) ? this.binaryPath : path.join(this.rootPath, this.binaryPath);
    if (!fs.existsSync(absPath)) {
      this.sections = [];
      this._onDidChangeTreeData.fire();
      return;
    }
    try {
      const out = cp.execSync(
        `"${this.pythonExe}" "${getSectionsScript(this.rootPath)}" --binary "${absPath}"`,
        { encoding: 'utf8', cwd: this.rootPath, maxBuffer: 1024 * 1024, env: { ...process.env, PYTHONPATH: getExtensionPath() || this.rootPath } }
      );
      const data = JSON.parse(out);
      this.sections = Array.isArray(data) ? data : (data.sections || data);
    } catch (_) {
      this.sections = [];
    }
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (element) return [];
    if (this._mode !== 'static') {
      const item = new vscode.TreeItem('Non disponible en mode Dynamic', vscode.TreeItemCollapsibleState.None);
      item.description = 'Ouvrez Static pour analyser un binaire';
      return [item];
    }
    return this.sections.map((s) => {
      const name = s.name || s.section || '';
      const item = new vscode.TreeItem(name, vscode.TreeItemCollapsibleState.None);
      item.description = s.vma_hex || s.vma || '';
      item.tooltip = `${name} @ ${s.vma_hex || s.vma} (${s.size_hex || s.size} bytes)`;
      item.contextValue = 'section';
      item.command = {
        command: 'pileOuFace.disasmSection',
        title: 'Désassembler',
        arguments: [name, this.binaryPath],
      };
      return item;
    });
  }
}

class SidebarCalculatorProvider {
  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (element) return [];
    const item = new vscode.TreeItem('Ouvrir la calculette', vscode.TreeItemCollapsibleState.None);
    item.command = {
      command: 'pileOuFace.calculator',
      title: 'Calculette',
    };
    return [item];
  }
}

module.exports = {
  SidebarSymbolsProvider,
  SidebarStringsProvider,
  SidebarSectionsProvider,
  SidebarCalculatorProvider,
};
