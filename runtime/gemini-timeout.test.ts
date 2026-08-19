import { afterEach, describe, expect, it, vi } from 'vitest';
import { withTimeout } from './gemini-timeout.mjs';

describe('Gemini timeout guard', () => {
  afterEach(() => vi.useRealTimers());

  it('rejects a stalled outbound promise at the configured deadline', async () => {
    vi.useFakeTimers();
    const pending = new Promise(() => {});
    const result = withTimeout(pending, 5, 'Gemini request timed out');

    vi.advanceTimersByTime(5);
    await expect(result).rejects.toThrow('Gemini request timed out');
  });
});
