const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function unsafeHtml(element, safeElement, event) {
  // ruleid: pof.webview.dynamic-inner-html
  element.innerHTML = `<p>${event.data}</p>`;
  // ok: pof.webview.dynamic-inner-html
  safeElement.innerHTML = '';
}

function unsafeCommands(binary, argument) {
  // ruleid: pof.process.interpolated-exec
  childProcess.exec(`${binary} ${argument}`, () => {});
  // ruleid: pof.process.spawn-with-shell
  childProcess.spawn(binary, [argument], { shell: true });
  // ok: pof.process.spawn-with-shell
  childProcess.spawn(binary, [argument], { shell: false });
}

function unsafeNetwork(client) {
  // ruleid: pof.http.plaintext-request
  fetch('http://example.com/api');
  // ok: pof.http.plaintext-request
  client.get('http://127.0.0.1:8080/health');
  // ok: pof.http.plaintext-request
  fetch('https://example.com/api');
}

function unsafePath(event) {
  const message = event.data;
  // ruleid: pof.path.message-to-filesystem
  fs.readFileSync(message.path, 'utf8');
  // ok: pof.path.message-to-filesystem
  fs.readFileSync(path.basename(message.path), 'utf8');
}

function unsafeHash(value) {
  // ruleid: pof.crypto.weak-hash
  return crypto.createHash('sha1').update(value).digest('hex');
}
