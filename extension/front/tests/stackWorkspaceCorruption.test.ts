const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

// Regression coverage for the "faux overflow" frontend gap: saved_bp /
// return_address must only ever be badged CORROMPU when the backend has
// actually emitted a matching diagnostic (return_address_corrupted /
// saved_bp_corrupted), gated on real crossing-write evidence. Raw per-slot
// flags (recentWrite / changed / pointerKind) may only ever produce
// informative badges (CHANGED / WRITE / suspect), never a corruption verdict.
describe('dynamic stack workspace corruption helpers', () => {
  let helpers;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceCorruption.js');
    helpers = await import(pathToFileURL(modulePath).href);
  });

  // char buffer[24]; strcpy(buffer, payload); -- saved_bp sits immediately
  // after the buffer (no padding), return_address 8 bytes after saved_bp.
  const SAVED_BP_ADDR = '0x7fffffffe020';
  const RET_ADDR = '0x7fffffffe028';

  function controlSlotEntryBase(kind, { flags = [], suspect = false } = {}) {
    const addr = kind === 'saved_bp' ? BigInt(SAVED_BP_ADDR) : BigInt(RET_ADDR);
    // Faithful reproduction of the historical false-positive trigger: a
    // recent-write signal on a slot whose current bytes read back as a
    // classic fuzzing pattern (0x4141...) with an unresolved pointerKind --
    // exactly what the old, un-gated pointer-pattern heuristic treated as
    // "corrupted", with no backend crossing-write evidence involved at all.
    return {
      kind,
      flags,
      start: addr,
      returnAddressIntegrity: helpers.validateReturnAddressIntegrity({
        kind,
        start: addr,
        size: 8,
        observations: suspect
          ? [{
              start: addr,
              size: 8,
              recentWrite: true,
              flags: ['recent_write'],
              pointerKind: 'unknown',
              displayValue: '0x4141414141414141'
            }]
          : []
      })
    };
  }

  function displayEntry(kind, address, entryBase) {
    return {
      key: `${kind}:${address}`,
      kind,
      address,
      badges: helpers.buildEntryBadges(entryBase),
      detailPayload: { rows: [] }
    };
  }

  it('never returns a "corrupted" field from validateReturnAddressIntegrity (informative-only contract)', () => {
    const result = helpers.validateReturnAddressIntegrity({
      kind: 'return_address',
      start: BigInt(RET_ADDR),
      size: 8,
      observations: [{ start: BigInt(RET_ADDR), size: 8, recentWrite: true, flags: ['recent_write'] }]
    });
    expect(result).to.not.have.property('corrupted');
    expect(result.suspect).to.equal(true);
  });

  it('buildEntryBadges never emits CORROMPU for a control slot, even with a write/change signal', () => {
    const savedBpBase = controlSlotEntryBase('saved_bp', { flags: ['changed', 'recent_write'] });
    const retBase = controlSlotEntryBase('return_address', { flags: ['changed', 'recent_write'], suspect: true });

    const savedBpBadges = helpers.buildEntryBadges(savedBpBase);
    const retBadges = helpers.buildEntryBadges(retBase);

    expect(savedBpBadges).to.not.include('CORROMPU');
    expect(savedBpBadges).to.include('CHANGED');
    expect(retBadges).to.not.include('CORROMPU');
    expect(retBadges).to.include('CHANGED');
    expect(retBadges).to.include('RET');
  });

  it('buffers/locals still surface CHANGED and WRITE badges normally', () => {
    const bufferBase = { kind: 'buffer', flags: ['changed'] };
    const localBase = { kind: 'local', flags: ['recent_write'] };
    expect(helpers.buildEntryBadges(bufferBase)).to.deep.equal(['CHANGED']);
    expect(helpers.buildEntryBadges(localBase)).to.deep.equal(['WRITE']);
  });

  it('A*23 on buffer[24]: no backend diagnostics => no CORROMPU on saved_bp/RET', () => {
    const savedBpEntry = displayEntry('saved_bp', SAVED_BP_ADDR, controlSlotEntryBase('saved_bp'));
    const retEntry = displayEntry('return_address', RET_ADDR, controlSlotEntryBase('return_address'));

    const annotated = helpers.annotateEntriesWithDiagnostics([savedBpEntry, retEntry], []);

    annotated.forEach((entry) => {
      expect(entry.badges).to.not.include('CORROMPU');
      expect(entry.diagnosticCorrupted).to.be.undefined;
    });
  });

  it('A*24 on buffer[24]: saved_bp_corrupted only => CORROMPU on saved_bp, not on RET', () => {
    const diagnostics = [
      {
        kind: 'buffer_overflow', severity: 'warning', step: 5,
        slot: { kind: 'buffer', address: '0x7fffffffe008' }
      },
      {
        kind: 'saved_bp_corrupted', severity: 'warning', step: 5,
        slot: { kind: 'saved_bp', address: SAVED_BP_ADDR }
      }
    ];
    const savedBpEntry = displayEntry('saved_bp', SAVED_BP_ADDR, controlSlotEntryBase('saved_bp', { flags: ['changed', 'recent_write'] }));
    const retEntry = displayEntry('return_address', RET_ADDR, controlSlotEntryBase('return_address'));

    const [annotatedSavedBp, annotatedRet] = helpers.annotateEntriesWithDiagnostics([savedBpEntry, retEntry], diagnostics);

    expect(annotatedSavedBp.badges).to.include('CORROMPU');
    expect(annotatedSavedBp.diagnosticCorrupted).to.equal(true);
    expect(annotatedRet.badges).to.not.include('CORROMPU');
    expect(annotatedRet.diagnosticCorrupted).to.be.undefined;
  });

  it('A*31 on buffer[24]: saved_bp fully overwritten, RET intact => CORROMPU on saved_bp only', () => {
    const diagnostics = [
      {
        kind: 'saved_bp_corrupted', severity: 'warning', step: 5,
        slot: { kind: 'saved_bp', address: SAVED_BP_ADDR }
      }
    ];
    const savedBpEntry = displayEntry('saved_bp', SAVED_BP_ADDR, controlSlotEntryBase('saved_bp', { flags: ['changed', 'recent_write'] }));
    const retEntry = displayEntry('return_address', RET_ADDR, controlSlotEntryBase('return_address'));

    const [annotatedSavedBp, annotatedRet] = helpers.annotateEntriesWithDiagnostics([savedBpEntry, retEntry], diagnostics);

    expect(annotatedSavedBp.badges).to.include('CORROMPU');
    expect(annotatedRet.badges).to.not.include('CORROMPU');
  });

  it('A*32 on buffer[24]: saved_bp AND return_address corrupted => CORROMPU on both', () => {
    const diagnostics = [
      {
        kind: 'saved_bp_corrupted', severity: 'warning', step: 5,
        slot: { kind: 'saved_bp', address: SAVED_BP_ADDR }
      },
      {
        kind: 'return_address_corrupted', severity: 'error', step: 5,
        slot: { kind: 'return_address', address: RET_ADDR }
      }
    ];
    const savedBpEntry = displayEntry('saved_bp', SAVED_BP_ADDR, controlSlotEntryBase('saved_bp', { flags: ['changed', 'recent_write'] }));
    const retEntry = displayEntry('return_address', RET_ADDR, controlSlotEntryBase('return_address', { flags: ['changed', 'recent_write'] }));

    const [annotatedSavedBp, annotatedRet] = helpers.annotateEntriesWithDiagnostics([savedBpEntry, retEntry], diagnostics);

    expect(annotatedSavedBp.badges).to.include('CORROMPU');
    expect(annotatedRet.badges).to.include('CORROMPU');
    expect(annotatedRet.diagnosticCorrupted).to.equal(true);
  });

  it('unrelated backend diagnostics present elsewhere never promote an unmatched control slot to CORROMPU', () => {
    const diagnostics = [
      { kind: 'max_steps_reached', severity: 'info', step: 99, slot: null }
    ];
    const savedBpEntry = displayEntry('saved_bp', SAVED_BP_ADDR, controlSlotEntryBase('saved_bp', { flags: ['changed', 'recent_write'] }));

    const [annotated] = helpers.annotateEntriesWithDiagnostics([savedBpEntry], diagnostics);

    expect(annotated.badges).to.not.include('CORROMPU');
  });

  it('benign termination mentioning "aucun overflow" does not add an OVERFLOW badge', () => {
    const retEntry = displayEntry('return_address', RET_ADDR, controlSlotEntryBase('return_address'));
    const [annotated] = helpers.annotateEntriesWithDiagnostics([retEntry], [{
      kind: 'benign_termination',
      severity: 'info',
      message: 'Fin normale sans preuve de corruption (aucun overflow).',
      slot: { kind: 'return_address', address: RET_ADDR }
    }]);

    expect(annotated.badges).to.deep.equal(['RET']);
    expect(annotated.diagnosticCorrupted).to.equal(false);
    expect(annotated.detailPayload.rows).to.deep.include({
      label: 'Diagnostic',
      value: "Fin d'execution normale"
    });
  });
});
