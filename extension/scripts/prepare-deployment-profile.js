// SPDX-License-Identifier: AGPL-3.0-only
'use strict';

const fs = require('fs');
const path = require('path');
const { buildProductConfig, configureManifest } = require('./deployment-profile');

const root = path.join(__dirname, '..');
const profile = process.argv[2];
const checkOnly = process.argv.includes('--check');
const product = buildProductConfig(profile);
const manifestPath = path.join(root, 'package.json');
const manifest = configureManifest(JSON.parse(fs.readFileSync(manifestPath, 'utf8')), profile);

if (!checkOnly) {
  fs.writeFileSync(path.join(root, 'product.json'), `${JSON.stringify(product, null, 2)}\n`);
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

process.stdout.write(`${profile}: ${product.deploymentId} ${product.authProviderUrl || '<offline>'}\n`);
