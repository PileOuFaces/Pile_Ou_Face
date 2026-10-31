const fs = require('node:fs');
const path = require('node:path');
const { expect } = require('chai');

const workflow = fs.readFileSync(
  path.resolve(__dirname, '../../../.github/workflows/publish.yml'),
  'utf8',
);

function workflowStep(name) {
  const marker = `      - name: ${name}\n`;
  const start = workflow.indexOf(marker);
  if (start < 0) throw new Error(`Workflow step not found: ${name}`);
  const next = workflow.indexOf('\n      - name:', start + marker.length);
  return workflow.slice(start, next < 0 ? workflow.length : next);
}

describe('release publishing workflow gate', () => {
  it('requires an explicit manual publish action for both registries', () => {
    expect(workflow).to.include("      - 'v*.*.*'");
    expect(workflow).to.include('      release_action:');
    expect(workflow).to.include("          - publish\n");
    expect(workflowStep('Publish to Open VSX'))
      .to.include("if: github.event_name == 'workflow_dispatch' && inputs.release_action == 'publish'");

    const marketplaceJob = workflow.slice(
      workflow.indexOf('  publish-marketplace:'),
      workflow.indexOf('\n  openvsx:'),
    );
    expect(marketplaceJob)
      .to.include("if: github.event_name == 'workflow_dispatch' && inputs.release_action == 'publish'");
  });

  it('publishes the single VSIX artifact built for the source SHA', () => {
    expect(workflowStep('Package VSIX'))
      .to.include("github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && inputs.release_action == 'publish')");
    expect(workflowStep('Upload VSIX artifact'))
      .to.include('name: pile-ou-face-openvsx-${{ github.sha }}');
    expect(workflowStep('Download verified VSIX'))
      .to.include('name: pile-ou-face-openvsx-${{ github.sha }}');
    expect(workflowStep('Publish to VS Code Marketplace'))
      .to.include('--packagePath release/pile-ou-face.vsix');
    expect(workflow).to.include('Source commit: \\`${GITHUB_SHA}\\`');
  });
});
