// SPDX-License-Identifier: AGPL-3.0-only
// POF-P1-010 : file FIFO bornée qui sérialise les opérations du cache statique.
const { expect } = require('chai');
const { createBoundedSerialQueue, QUEUE_FULL_CODE } = require('../shared/boundedSerialQueue');

const QUEUE_LIMIT = 2;

const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

describe('createBoundedSerialQueue', () => {
  it('rejects a non-positive or non-integer limit', () => {
    for (const limit of [0, -1, 1.5, Number.NaN]) {
      expect(() => createBoundedSerialQueue(limit)).to.throw(RangeError);
    }
  });

  it('runs tasks one at a time in submission order', async () => {
    const queue = createBoundedSerialQueue(10);
    const events = [];
    const gate = deferred();
    const first = queue.push(async () => { events.push('start-1'); await gate.promise; events.push('end-1'); return 1; });
    const second = queue.push(() => { events.push('start-2'); return 2; });
    await Promise.resolve();
    expect(events).to.deep.equal(['start-1']);
    gate.resolve();
    expect(await Promise.all([first, second])).to.deep.equal([1, 2]);
    expect(events).to.deep.equal(['start-1', 'end-1', 'start-2']);
  });

  it('keeps running later tasks after a failure', async () => {
    const queue = createBoundedSerialQueue(10);
    const failing = queue.push(() => { throw new Error('boom'); });
    const next = queue.push(() => 'ok');
    let failure = null;
    await failing.catch((err) => { failure = err; });
    expect(failure?.message).to.equal('boom');
    expect(await next).to.equal('ok');
    expect(queue.size()).to.equal(0);
  });

  it('rejects tasks beyond the limit and accepts again once drained', async () => {
    const queue = createBoundedSerialQueue(QUEUE_LIMIT);
    const gate = deferred();
    const accepted = Array.from({ length: QUEUE_LIMIT }, () => queue.push(() => gate.promise));
    let rejection = null;
    await queue.push(() => 'overflow').catch((err) => { rejection = err; });
    expect(rejection?.code).to.equal(QUEUE_FULL_CODE);
    expect(queue.size()).to.equal(QUEUE_LIMIT);
    gate.resolve('done');
    await Promise.all(accepted);
    expect(queue.size()).to.equal(0);
    expect(await queue.push(() => 'again')).to.equal('again');
  });
});
