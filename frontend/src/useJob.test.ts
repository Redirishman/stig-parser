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

    expect(api.uploadFile).toHaveBeenCalledWith('https://s3/a', files[0], expect.any(Function));
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
});
