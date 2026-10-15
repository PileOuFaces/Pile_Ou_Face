// SPDX-License-Identifier: AGPL-3.0-only

const { expect } = require('chai');
const sinon = require('sinon');
const { createTelemetryHandlers } = require('../shared/telemetry/telemetryMessageHandler');

describe('telemetry message handler', () => {
  it('forwards telemetry messages to the service', async () => {
    const trackEvent = sinon.stub();
    const handlers = createTelemetryHandlers({ trackEvent });

    await handlers['pof.telemetry']({
      eventName: 'panel.opened',
      properties: { panel: 'static' },
    });

    expect(trackEvent.calledOnceWithExactly('panel.opened', { panel: 'static' })).to.equal(true);
  });

  it('is safe when the telemetry service is unavailable', async () => {
    const handlers = createTelemetryHandlers(null);

    await handlers['pof.telemetry']({ eventName: 'panel.opened' });
    await handlers['pof.telemetry'](null);
  });
});
