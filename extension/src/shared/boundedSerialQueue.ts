// SPDX-License-Identifier: AGPL-3.0-only
/**
 * FIFO queue running one task at a time, with a cap on queued + running tasks.
 * Tasks start in submission order, so a read submitted after a write sees it.
 */

const QUEUE_FULL_CODE = 'POF_QUEUE_FULL';

class QueueFullError extends Error {
  code: string;

  constructor(limit) {
    super(`File d'attente pleine (${limit} tâches en cours ou en attente)`);
    this.name = 'QueueFullError';
    this.code = QUEUE_FULL_CODE;
  }
}

function createBoundedSerialQueue(limit) {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new RangeError(`limit doit être un entier >= 1 (reçu : ${limit})`);
  }
  let tail: Promise<unknown> = Promise.resolve();
  let pending = 0;
  const release = () => { pending -= 1; };

  const push = <T>(task: () => T | Promise<T>): Promise<T> => {
    if (pending >= limit) return Promise.reject(new QueueFullError(limit));
    pending += 1;
    const run = tail.then(task);
    tail = run.then(release, release);
    return run;
  };

  return {
    push,
    size: () => pending,
  };
}

module.exports = { createBoundedSerialQueue, QueueFullError, QUEUE_FULL_CODE };
