const fs = require('fs');
const path = require('path');
const { expect } = require('chai');

describe('UI journey inventory', () => {
  const extensionRoot = path.resolve(__dirname, '..', '..');
  const inventoryPath = path.join(extensionRoot, 'scripts', 'e2e', 'ui-journey-inventory.json');
  const suitePath = path.join(extensionRoot, 'scripts', 'e2e', 'runtime-audit-suite.js');
  const repositoryRoot = path.resolve(extensionRoot, '..');
  const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
  const suiteSource = fs.readFileSync(suitePath, 'utf8');

  it('uses unique stable identifiers and an explicit coverage decision', () => {
    const ids = inventory.journeys.map((journey) => journey.id);
    expect(new Set(ids).size).to.equal(ids.length);
    expect(inventory.issue).to.equal(247);
    for (const journey of inventory.journeys) {
      expect(journey.id).to.match(/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/);
      expect(['covered', 'gap']).to.include(journey.status);
      if (journey.status === 'gap') expect(journey.reason).to.be.a('string').and.not.empty;
    }
  });

  it('keeps every covered journey attached to a real UI test', () => {
    for (const journey of inventory.journeys.filter((item) => item.status === 'covered')) {
      expect(journey.test, journey.id).to.be.a('string').and.not.empty;
      expect(suiteSource, `${journey.id} references a missing E2E scenario`)
        .to.include(`new Mocha.Test('${journey.test}'`);
      expect(journey.test, `${journey.id} must reference a frontend-driven scenario`)
        .to.match(/UI|webview|interface|binary|annotation|xrefs/i);
    }
  });

  it('keeps contribution guardrails covered by repository templates', () => {
    const ids = inventory.guardrails.map((guardrail) => guardrail.id);
    expect(new Set(ids).size).to.equal(ids.length);

    for (const guardrail of inventory.guardrails) {
      expect(guardrail.status, guardrail.id).to.equal('covered');
      expect(guardrail.evidence, guardrail.id).to.be.a('string').and.not.empty;
      expect(fs.existsSync(path.join(repositoryRoot, guardrail.evidence)), guardrail.id).to.equal(true);
    }

    const pullRequestTemplate = fs.readFileSync(
      path.join(repositoryRoot, '.github', 'PULL_REQUEST_TEMPLATE.md'),
      'utf8',
    );
    expect(pullRequestTemplate).to.include('Parcours utilisateur impacté');
    expect(pullRequestTemplate).to.include('Un scénario E2E UI a été ajouté ou mis à jour');
    expect(pullRequestTemplate).to.include("Aucun E2E UI n'est requis");

    const featureIssueTemplate = fs.readFileSync(
      path.join(repositoryRoot, '.github', 'ISSUE_TEMPLATE', 'feature.yml'),
      'utf8',
    );
    expect(featureIssueTemplate).to.include("id: journey");
    expect(featureIssueTemplate).to.include("id: acceptance");
    expect(featureIssueTemplate).to.include("id: e2e-impact");
  });
});
