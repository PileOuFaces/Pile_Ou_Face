const esbuild = require('esbuild');

const isProduction = process.argv.includes('--production');
const isWatch = process.argv.includes('--watch');

const buildOptions = {
  entryPoints: ['src/extension.ts'],
  bundle: true,
  outfile: 'dist/extension.js',
  external: ['vscode'],
  format: 'cjs',
  platform: 'node',
  target: 'node20',
  minify: isProduction,
  sourcemap: isProduction ? false : 'inline',
  logLevel: 'info',
};

async function main() {
  if (isWatch) {
    const context = await esbuild.context(buildOptions);
    await context.watch();
    return;
  }
  await esbuild.build(buildOptions);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
