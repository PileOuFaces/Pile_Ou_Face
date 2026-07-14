const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

describe('dynamic diagnostics UI helpers', () => {
  let helpers;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/diagnostics.js');
    const source = fs.readFileSync(modulePath, 'utf8');
    const dataUrl = `data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`;
    helpers = await import(dataUrl);
  });

  it('maps diagnostics to ASM addresses, stack slots, and registers', () => {
    const diagnostic = {
      severity: 'error',
      kind: 'return_address_corrupted',
      step: 19,
      instructionAddress: '0x4011c2',
      responsibleInstructionAddress: '0x4011bf',
      message: 'Return address overwritten by payload',
      slot: {
        kind: 'return_address',
        address: '0x7fffffffde60'
      },
      before: '0x4011d5',
      after: '0x43434343',
      probableSource: 'argv[1]',
      payloadOffset: 76
    };

    const current = helpers.diagnosticsForStep([diagnostic], 19);
    expect(current).to.have.length(1);
    expect(helpers.diagnosticMatchesAddress(diagnostic, '0x4011bf', 'responsibleInstructionAddress')).to.equal(true);
    expect(helpers.diagnosticMatchesAddress(diagnostic, '4011c2', 'instructionAddress')).to.equal(true);
    expect(helpers.diagnosticsForStackSlot([diagnostic], {
      kind: 'return_address',
      address: '0x7fffffffde60'
    })).to.have.length(1);

    const registers = helpers.diagnosticRegisters([diagnostic]);
    expect(registers.has('rip')).to.equal(true);
    expect(registers.has('rbp')).to.equal(true);
  });

  it('orders errors before warnings for the current step card', () => {
    const warning = { severity: 'warning', kind: 'buffer_overflow', step: 2, confidence: 0.95 };
    const error = { severity: 'error', kind: 'invalid_control_flow', step: 2, confidence: 0.7 };

    const current = helpers.diagnosticsForStep([warning, error], 2);

    expect(current[0]).to.equal(error);
    expect(helpers.primaryDiagnostic(current)).to.equal(error);
  });

  it('synthesizes a crash diagnostic from trace.crash for ASM and register highlights', () => {
    const crash = {
      type: 'unmapped_fetch',
      step: 4,
      instructionAddress: '0x401080',
      instructionText: 'ret',
      reason: 'Invalid fetch',
      registers: { rip: '0x41414141', rsp: '0x7fffffffe000' },
    };

    const current = helpers.mergeCrashDiagnostic([], crash, 4);

    expect(current).to.have.length(1);
    expect(current[0].kind).to.equal('fatal_crash');
    expect(helpers.diagnosticMatchesAddress(current[0], '0x401080', 'instructionAddress')).to.equal(true);
    const registers = helpers.diagnosticRegisters(current);
    expect(registers.has('rip')).to.equal(true);
    expect(registers.has('rsp')).to.equal(true);
  });

  it('keeps crash ASM diagnostics available outside the selected step', () => {
    const crash = {
      type: 'unmapped_write',
      step: 80,
      instructionAddress: '0x401090',
      instructionText: 'mov byte ptr [rax], 0',
      reason: 'Invalid write',
    };
    const diagnostic = {
      severity: 'error',
      kind: 'runtime_crash',
      step: 80,
      instructionAddress: '0x401090',
      responsibleInstructionAddress: '0x401080',
      message: 'Crash caused by previous write',
    };

    const persistent = helpers.persistentCrashDiagnostics(crash, [diagnostic]);

    expect(helpers.diagnosticMatchesAddress(persistent[0], '0x401090', 'any')).to.equal(true);
    expect(persistent.some((entry) => helpers.diagnosticMatchesAddress(entry, '0x401080', 'responsibleInstructionAddress'))).to.equal(true);
    expect(helpers.diagnosticsForStep(persistent, 20)).to.deep.equal([]);
  });

  it('benign_termination (hello-world/printf-only) is never reclassified as fatal_crash', () => {
    const crash = {
      classification: 'benign_termination',
      type: 'unmapped_fetch',
      step: 1,
      instructionText: 'ret',
      instructionAddress: '0x401050',
      reason: "Fin d'execution hors zone de code connue, sans preuve de corruption.",
    };

    const diagnostic = helpers.crashDiagnosticForStep(crash, 1);

    expect(diagnostic.kind).to.equal('benign_termination');
    expect(diagnostic.severity).to.equal('info');
    expect(diagnostic.kind).to.not.equal('fatal_crash');
    expect(helpers.diagnosticKindLabel(diagnostic.kind)).to.not.equal('Diagnostic runtime');
  });

  it('emulator_stop is never reclassified as fatal_crash', () => {
    const crash = {
      classification: 'emulator_stop',
      type: 'unmapped_read',
      step: 3,
      instructionText: 'mov eax, [rax]',
      reason: 'Emulator boundary, no corruption evidence.',
    };

    const diagnostic = helpers.crashDiagnosticForStep(crash, 3);

    expect(diagnostic.kind).to.equal('emulator_stop');
    expect(diagnostic.severity).to.equal('info');
  });

  it('a real overflow reaching the return address stays fatal_crash / error', () => {
    const crash = {
      classification: 'fatal_crash',
      type: 'unmapped_fetch',
      step: 1,
      instructionText: 'ret',
      instructionAddress: '0x401050',
      reason: 'Retour vers une adresse non mappee.',
    };

    const diagnostic = helpers.crashDiagnosticForStep(crash, 1);

    expect(diagnostic.kind).to.equal('fatal_crash');
    expect(diagnostic.severity).to.equal('error');
  });
});
