export {
  validateReturnAddressIntegrity,
  buildEntryBadges,
  annotateEntriesWithDiagnostics,
  diagnosticMatchesEntry,
  compareDiagnostics,
  diagnosticSeverityRank,
  diagnosticKindLabel,
  upsertDiagnosticRow,
  hasCorruptionSignal,
  isProtectedKind
} from './stackWorkspaceCore.js';
