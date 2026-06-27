const { expect } = require('chai');

const {
  detectPayloadTargetFromBinarySymbols,
  detectPayloadTargetFromSourceText,
  payloadTargetLabel,
  resolvePayloadTarget,
} = require('../src/shared/dynamicInputTarget');

describe('dynamic input target helpers', () => {
  it('detects stdin for rootme1-style fgets programs', () => {
    const source = `
      int main() {
        char buf[40];
        fgets(buf, 45, stdin);
      }
    `;

    const detected = detectPayloadTargetFromSourceText(source);

    expect(detected.target).to.equal('stdin');
    expect(detected.reason).to.contain('fgets');
    expect(detected.fallback).to.equal(false);
  });

  it('detects argv[1] direct access', () => {
    const detected = detectPayloadTargetFromSourceText(`
      int main(int argc, char **argv) {
        strcpy(buffer, argv[1]);
      }
    `);

    expect(detected.target).to.equal('argv1');
    expect(detected.reason).to.contain('argv[1]');
    expect(detected.fallback).to.equal(false);
  });

  it('detects programs using stdin and argv[1]', () => {
    const detected = detectPayloadTargetFromSourceText(`
      int main(int argc, char **argv) {
        read(0, buf, 32);
        puts(argv[1]);
      }
    `);

    expect(detected.target).to.equal('both');
    expect(detected.fallback).to.equal(false);
  });

  it('falls back to argv[1] when no supported input source is clear', () => {
    const detected = detectPayloadTargetFromSourceText(`
      int main(void) {
        FILE *fp = fopen("input.txt", "r");
        fread(buf, 1, sizeof(buf), fp);
      }
    `);

    expect(detected.target).to.equal('argv1');
    expect(detected.fallback).to.equal(true);
  });

  it('detects stdin from binary imports when no C source is available', () => {
    const detected = detectPayloadTargetFromBinarySymbols([
      { name: 'main', type: 'T' },
      { name: '__isoc23_scanf@GLIBC_2.38', type: 'U' }
    ]);

    expect(detected.target).to.equal('stdin');
    expect(detected.reason).to.contain('scanf import');
    expect(detected.fallback).to.equal(false);
  });

  it('uses binary imports as the auto target when source has no evidence', () => {
    const resolved = resolvePayloadTarget({
      mode: 'auto',
      sourceText: '',
      binarySymbols: [{ name: '__isoc99_scanf', type: 'U' }]
    });

    expect(resolved.target).to.equal('stdin');
    expect(resolved.autoTarget).to.equal('stdin');
    expect(resolved.reason).to.contain('scanf import');
  });

  it('honors manual overrides over auto-detection', () => {
    const resolved = resolvePayloadTarget({
      mode: 'stdin',
      sourceText: 'int main(int argc, char **argv) { puts(argv[1]); }'
    });

    expect(resolved.target).to.equal('stdin');
    expect(resolved.autoTarget).to.equal('argv1');
    expect(payloadTargetLabel(resolved.target)).to.equal('stdin');
  });
});
