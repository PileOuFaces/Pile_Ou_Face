import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { buildProductConfig } = require('./deployment-profile');
const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.resolve(process.argv[2] || path.join(extensionRoot, 'product.json'));
const productConfig = buildProductConfig('OFFICIAL_SAAS');

fs.writeFileSync(
  outputPath,
  `${JSON.stringify(productConfig, null, 2)}\n`,
  'utf8',
);

console.log(`Official product configuration written to ${outputPath}`);
