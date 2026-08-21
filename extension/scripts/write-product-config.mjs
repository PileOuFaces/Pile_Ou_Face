import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.resolve(process.argv[2] || path.join(extensionRoot, 'product.json'));
const authProviderUrl = String(process.env.POF_AUTH_PROVIDER_URL || '').trim();
const collabProviderUrl = String(process.env.POF_COLLAB_PROVIDER_URL || '').trim();

if (!authProviderUrl) {
  throw new Error('POF_AUTH_PROVIDER_URL is required for an official build');
}

const parsedAuthUrl = new URL(authProviderUrl);
if (parsedAuthUrl.protocol !== 'https:') {
  throw new Error('POF_AUTH_PROVIDER_URL must use HTTPS');
}

fs.writeFileSync(
  outputPath,
  `${JSON.stringify({ authProviderUrl, collabProviderUrl }, null, 2)}\n`,
  'utf8',
);

console.log(`Official product configuration written to ${outputPath}`);
