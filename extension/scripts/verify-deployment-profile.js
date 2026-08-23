// SPDX-License-Identifier: AGPL-3.0-only
'use strict';

const fs = require('fs');
const path = require('path');
const { buildProductConfig } = require('./deployment-profile');

const root = path.join(__dirname, '..');
const profile = process.argv[2];
const expected = buildProductConfig(profile);
const product = JSON.parse(fs.readFileSync(path.join(root, 'product.json'), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const properties = manifest.contributes?.configuration?.properties || {};
const hasEditableAuthUrl = Object.prototype.hasOwnProperty.call(
  properties,
  'pileOuFace.authServerUrl',
);

for (const field of ['deploymentProfile', 'deploymentId', 'authProviderUrl']) {
  if (product[field] !== expected[field]) {
    throw new Error(`${profile}: unexpected ${field}: ${String(product[field])}`);
  }
}
if (hasEditableAuthUrl !== (profile === 'OSS_DEVELOPMENT')) {
  throw new Error(`${profile}: authServerUrl editability does not match the profile`);
}

process.stdout.write(`${profile}: artifact configuration verified\n`);
