import '@testing-library/jest-dom/vitest';
import { toHaveNoViolations } from 'jest-axe';
import { expect, vi } from 'vitest';

/** axe-core assertions: `expect(await axe(container)).toHaveNoViolations()`. */
expect.extend(toHaveNoViolations);

/**
 * React Testing Library only knows how to drive *jest's* fake timers: `waitFor`
 * looks for a global `jest` object, and without one it falls back to waiting on
 * a real `setTimeout` — which, under `vi.useFakeTimers()`, never fires. Every
 * `waitFor` in a fake-timer test would then hang until the test times out.
 *
 * This is the shim RTL documents for Vitest: expose just enough of the jest
 * timer API for RTL to advance our fake clock itself.
 */
(globalThis as unknown as { jest: { advanceTimersByTime: (ms: number) => void } }).jest = {
  advanceTimersByTime: (ms: number) => {
    vi.advanceTimersByTime(ms);
  },
};
