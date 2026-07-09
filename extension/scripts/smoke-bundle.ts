import '../src/tests/setup';

const extension = require('../dist/extension.js');

if (
  typeof extension.activate !== 'function'
  || typeof extension.deactivate !== 'function'
) {
  throw new Error('Le bundle extension ne publie pas activate/deactivate.');
}

console.log('Bundle extension chargeable.');
