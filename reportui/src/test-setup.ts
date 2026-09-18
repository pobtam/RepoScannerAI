/**
 * Vitest runs in jsdom.
 *
 * jsdom implements no layout, so two browser APIs the chart library depends on
 * are absent: ResizeObserver and element geometry. They are polyfilled here
 * because their absence is a property of the test environment, not of the
 * interface — and without them a chart throws on mount and the view under test
 * renders nothing, which would look like a failing assertion about the data.
 *
 * Nothing else is stubbed globally. A test that needs a fake response provides
 * it explicitly, so no test can pass because a shared stub happened to answer.
 */
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

if (!('ResizeObserver' in globalThis)) {
  (globalThis as { ResizeObserver?: unknown }).ResizeObserver = ResizeObserverStub;
}

// A non-zero viewport, so a responsive container has something to be
// responsive to.
Object.defineProperty(HTMLElement.prototype, 'clientWidth', { configurable: true, value: 1200 });
Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, value: 800 });

export {};
