import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import { STORAGE_KEY, useJob } from './useJob';
import type { Job } from './types';

function job(over: Partial<Job> = {}): Job {
  return { jobId: 'j1', status: 'running', progress: 'Parsing…', ...over };
}

describe('useJob', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    localStorage.clear();
    vi.spyOn(api, 'createUploads').mockResolvedValue({
      jobId: 'j1',
      uploads: [{ filename: 'a.xml', url: 'https://s3/a' }],
    });
    vi.spyOn(api, 'uploadFile').mockResolvedValue(undefined);
    vi.spyOn(api, 'startJob').mockResolvedValue({ jobId: 'j1' });
    vi.spyOn(api, 'cancelJob').mockResolvedValue({ jobId: 'j1', status: 'cancelled' });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const files = [new File(['x'], 'a.xml')];

  it('uploads, starts the job, and persists the id for reconnect', async () => {
    vi.spyOn(api, 'getJob').mockResolvedValue(job());
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });

    expect(api.uploadFile).toHaveBeenCalledWith(
      'https://s3/a',
      files[0],
      expect.any(Function),
      expect.any(AbortSignal),
    );
    expect(api.startJob).toHaveBeenCalledWith('j1', false);
    expect(localStorage.getItem(STORAGE_KEY)).toBe('j1');
  });

  it('does not start the job when an upload fails', async () => {
    // Half the bytes are in S3; starting the pipeline would parse a partial set.
    vi.spyOn(api, 'uploadFile').mockRejectedValue(new Error('Upload failed for a.xml.'));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });

    expect(api.startJob).not.toHaveBeenCalled();
    expect(result.current.state.status).toBe('error');
    expect(result.current.state.error).toMatch(/upload failed/i);
  });

  it('polls every second and logs each new progress message', async () => {
    const getJob = vi
      .spyOn(api, 'getJob')
      .mockResolvedValueOnce(job({ progress: 'Parsing…' }))
      .mockResolvedValueOnce(job({ progress: 'Exporting…' }));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });

    expect(getJob).toHaveBeenCalled();
    const messages = result.current.state.log.map((l) => l.message);
    expect(messages).toContain('Parsing…');
    expect(messages).toContain('Exporting…');
  });

  it('does not log the same progress message twice', async () => {
    vi.spyOn(api, 'getJob').mockResolvedValue(job({ progress: 'Parsing…' }));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });

    const parsing = result.current.state.log.filter((l) => l.message === 'Parsing…');
    expect(parsing).toHaveLength(1);
  });

  it('shows the stall note after 20 unchanged polls', async () => {
    vi.spyOn(api, 'getJob').mockResolvedValue(job({ progress: 'Parsing…' }));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    expect(result.current.state.stalled).toBe(false);

    await act(async () => { await vi.advanceTimersByTimeAsync(20_000); });
    expect(result.current.state.stalled).toBe(true);
  });

  it('declares the backend dead after 10 consecutive failed polls', async () => {
    vi.spyOn(api, 'getJob').mockRejectedValue(new Error('network'));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });

    expect(result.current.state.status).toBe('error');
    expect(result.current.state.error).toMatch(/lost contact/i);
  });

  it('keeps the job id when the backend goes dead, so the job can be reconnected', async () => {
    // Ten 1s polls is well inside a VPN re-key. The copy says "the job may still
    // be running" — deleting the id destroyed the only handle to reconnect to it
    // or fetch its report, permanently orphaning a job that was probably fine.
    vi.spyOn(api, 'getJob').mockRejectedValue(new Error('network'));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });

    expect(result.current.state.status).toBe('error');
    expect(localStorage.getItem(STORAGE_KEY)).toBe('j1');
    expect(result.current.state.jobId).toBe('j1');
    expect(result.current.canReconnect).toBe(true);
  });

  it('reconnect picks the job back up after the blip clears', async () => {
    const getJob = vi.spyOn(api, 'getJob').mockRejectedValue(new Error('network'));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(result.current.state.status).toBe('error');

    getJob.mockResolvedValue(job({ status: 'running', progress: 'Parsing…' }));
    await act(async () => { await result.current.reconnect(); });

    expect(result.current.state.status).toBe('running');
    expect(result.current.state.error).toBeNull();
    expect(result.current.canReconnect).toBe(false);
  });

  it('reconnect onto an already-finished job lands the report', async () => {
    const getJob = vi.spyOn(api, 'getJob').mockRejectedValue(new Error('network'));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });

    getJob.mockResolvedValue(
      job({ status: 'complete', summary: { files: 1, hosts: 1, findings: 2, cat1: 0, cat2: 1, cat3: 1 } }),
    );
    await act(async () => { await result.current.reconnect(); });

    expect(result.current.state.status).toBe('complete');
    expect(result.current.state.summary).not.toBeNull();
  });

  it('a failed cancel is surfaced, not buried in the log', async () => {
    // Polling correctly continues and the UI still says Processing — so unless the
    // failure is stated plainly the operator cannot tell whether the cancel took.
    vi.spyOn(api, 'getJob').mockResolvedValue(job());
    vi.spyOn(api, 'cancelJob').mockRejectedValue(new Error('Cancel rejected (503).'));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await result.current.cancel(); });

    expect(result.current.state.cancelError).toMatch(/could not be cancelled/i);
    expect(result.current.state.cancelError).toMatch(/still running/i);
    // The job is untouched: still processing, still cancellable.
    expect(result.current.state.status).not.toBe('idle');
    expect(result.current.canCancel).toBe(true);
  });

  it('a retried cancel clears the previous failure notice', async () => {
    vi.spyOn(api, 'getJob').mockResolvedValue(job());
    const cancelJob = vi
      .spyOn(api, 'cancelJob')
      .mockRejectedValueOnce(new Error('Cancel rejected (503).'));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await result.current.cancel(); });
    expect(result.current.state.cancelError).not.toBeNull();

    cancelJob.mockResolvedValue({ jobId: 'j1', status: 'cancelled' });
    await act(async () => { await result.current.cancel(); });

    expect(result.current.state.cancelError).toBeNull();
    expect(result.current.state.status).toBe('idle');
  });

  it('a single failed poll does not kill the job', async () => {
    vi.spyOn(api, 'getJob')
      .mockRejectedValueOnce(new Error('blip'))
      .mockResolvedValue(job({ progress: 'Parsing…' }));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });

    expect(result.current.state.status).not.toBe('error');
  });

  it('stops polling and clears storage on a terminal status', async () => {
    vi.spyOn(api, 'getJob').mockResolvedValue(
      job({ status: 'complete', progress: 'Done.', summary: { files: 1, hosts: 1, findings: 2, cat1: 0, cat2: 1, cat3: 1 } }),
    );
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });

    await waitFor(() => expect(result.current.state.status).toBe('complete'));
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();

    const callsAfter = vi.mocked(api.getJob).mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(vi.mocked(api.getJob).mock.calls.length).toBe(callsAfter);
  });

  it('keeps warnings visible on the success card', async () => {
    // The copy tells the operator to verify them, so they must survive the
    // transition out of the progress screen.
    vi.spyOn(api, 'getJob').mockResolvedValue(
      job({ status: 'complete', warnings: ['Benchmark unmatched'] }),
    );
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });

    await waitFor(() => expect(result.current.state.status).toBe('complete'));
    expect(result.current.state.warnings).toEqual(['Benchmark unmatched']);
  });

  it('keeps warnings raised mid-run when the terminal payload omits them', async () => {
    // The final poll need not repeat the warnings it already reported; losing
    // them here would hide them from the success card the operator verifies.
    vi.spyOn(api, 'getJob')
      .mockResolvedValueOnce(job({ progress: 'Parsing…', warnings: ['Benchmark unmatched'] }))
      .mockResolvedValueOnce(job({ status: 'complete', progress: 'Done.' }));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(result.current.state.warnings).toEqual(['Benchmark unmatched']);

    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });

    await waitFor(() => expect(result.current.state.status).toBe('complete'));
    expect(result.current.state.warnings).toEqual(['Benchmark unmatched']);
  });

  it('logs the first progress message of a second job even if it repeats the first', async () => {
    vi.spyOn(api, 'getJob').mockResolvedValue(job({ progress: 'Parsing…' }));
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
    expect(result.current.state.log.filter((l) => l.message === 'Parsing…')).toHaveLength(1);

    // Cancel clears the log but must also clear the remembered progress message,
    // or the next job's identical first message never reaches the log.
    await act(async () => { await result.current.cancel(); });
    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(1000); });

    expect(result.current.state.log.filter((l) => l.message === 'Parsing…')).toHaveLength(1);
    expect(result.current.state.stalled).toBe(false);
  });

  it('does not stack polls on a backend slower than the poll interval', async () => {
    // Each response takes 3s. Without an in-flight guard the interval would launch
    // a poll every second, and the overlapping failures would reach DEAD_POLLS in
    // far fewer than 10 real round-trips.
    vi.spyOn(api, 'getJob').mockImplementation(
      () =>
        new Promise((_resolve, reject) => {
          setTimeout(() => reject(new Error('slow')), 3000);
        }),
    );
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });

    // 15s at one 3s round-trip at a time: at most 5 polls, nowhere near 10 failures.
    expect(vi.mocked(api.getJob).mock.calls.length).toBeLessThanOrEqual(5);
    expect(result.current.state.status).not.toBe('error');
  });

  it('reconnects to a stored in-flight job on mount', async () => {
    localStorage.setItem(STORAGE_KEY, 'j-old');
    vi.spyOn(api, 'getJob').mockResolvedValue(job({ jobId: 'j-old', status: 'running' }));

    const { result } = renderHook(() => useJob());
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });

    await waitFor(() => expect(result.current.state.jobId).toBe('j-old'));
    expect(result.current.state.log.map((l) => l.message)).toContain(
      'Reconnected to running job…',
    );
  });

  it('does not reconnect to a job that already finished', async () => {
    localStorage.setItem(STORAGE_KEY, 'j-old');
    vi.spyOn(api, 'getJob').mockResolvedValue(job({ jobId: 'j-old', status: 'complete' }));

    const { result } = renderHook(() => useJob());
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });

    await waitFor(() => expect(localStorage.getItem(STORAGE_KEY)).toBeNull());
    expect(result.current.state.status).toBe('idle');
  });

  it('cancel reports the status the server actually returns', async () => {
    // The job can finish between the click and StopExecution landing.
    vi.spyOn(api, 'getJob').mockResolvedValue(job());
    vi.spyOn(api, 'cancelJob').mockResolvedValue({ jobId: 'j1', status: 'complete' });
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await result.current.cancel(); });

    expect(result.current.state.status).toBe('complete');
  });

  it('cancel returning cancelled goes back to idle', async () => {
    vi.spyOn(api, 'getJob').mockResolvedValue(job());
    const { result } = renderHook(() => useJob());

    await act(async () => { await result.current.submit(files, false); });
    await act(async () => { await result.current.cancel(); });

    expect(result.current.state.status).toBe('idle');
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('cancel mid-upload never starts the job', async () => {
    // The upload window is minutes long (200 MB over a VPN). A Cancel in that
    // window must stop the submit, not let its async continuation run on and
    // start — and orphan — the very job the operator just called off.
    vi.spyOn(api, 'getJob').mockResolvedValue(job());
    let releaseUpload!: () => void;
    vi.spyOn(api, 'uploadFile').mockReturnValue(
      new Promise<void>((resolve) => {
        releaseUpload = resolve;
      }),
    );
    const { result } = renderHook(() => useJob());

    let submitted!: Promise<void>;
    await act(async () => {
      submitted = result.current.submit(files, false);
      // Let createUploads resolve so the job id — and Cancel — exist.
      await vi.advanceTimersByTimeAsync(0);
    });

    await act(async () => { await result.current.cancel(); });
    await act(async () => {
      releaseUpload();
      await submitted;
    });

    expect(api.startJob).not.toHaveBeenCalled();
    expect(result.current.state.status).toBe('idle');
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('cancel mid-upload aborts the in-flight upload', async () => {
    // Without an abort the bytes keep flowing after Cancel: the operator is told
    // nothing is happening while their VPN is still saturated.
    vi.spyOn(api, 'getJob').mockResolvedValue(job());
    let seen: AbortSignal | undefined;
    vi.spyOn(api, 'uploadFile').mockImplementation(
      (_url, _file, _onProgress, signal) =>
        new Promise<void>((_resolve, reject) => {
          seen = signal;
          signal?.addEventListener('abort', () => reject(new Error('aborted')));
        }),
    );
    const { result } = renderHook(() => useJob());

    let submitted!: Promise<void>;
    await act(async () => {
      submitted = result.current.submit(files, false);
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(seen?.aborted).toBe(false);

    await act(async () => { await result.current.cancel(); });
    await act(async () => { await submitted; });

    expect(seen?.aborted).toBe(true);
    // An aborted upload is not an upload failure — do not cry error at the operator.
    expect(result.current.state.status).toBe('idle');
    expect(result.current.state.error).toBeNull();
  });
});
