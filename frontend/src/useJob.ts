import { useCallback, useEffect, useRef, useState } from 'react';
import * as api from './api';
import { TERMINAL_STATUSES, type AiGate, type Job, type JobStatus, type Summary } from './types';

/** Survives a page reload so a long-running job is not lost to an accidental refresh. */
export const STORAGE_KEY = 'stig.jobId';

const POLL_MS = 1000;
/** Unchanged progress for this many polls (~20s) before we reassure the operator. */
const STALL_POLLS = 20;
/** Consecutive poll failures before we call the backend dead. */
const DEAD_POLLS = 10;

export interface LogLine {
  time: string;
  message: string;
}

export type UiStatus = 'idle' | 'uploading' | JobStatus;

export interface JobState {
  status: UiStatus;
  jobId: string | null;
  log: LogLine[];
  warnings: string[];
  summary: Summary | null;
  ai: AiGate | null;
  aiError: string | null;
  error: string | null;
  stalled: boolean;
  /** filename -> percent complete, while uploading. */
  uploadProgress: Record<string, number>;
}

const INITIAL: JobState = {
  status: 'idle',
  jobId: null,
  log: [],
  warnings: [],
  summary: null,
  ai: null,
  aiError: null,
  error: null,
  stalled: false,
  uploadProgress: {},
};

function stamp(): string {
  return new Date().toLocaleTimeString([], { hour12: false });
}

export function useJob() {
  const [state, setState] = useState<JobState>(INITIAL);

  // Refs, not state: the poll loop reads these every tick and must not re-create
  // itself (or restart the interval) each time one changes.
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastProgress = useRef<string>('');
  const unchanged = useRef(0);
  const failures = useRef(0);
  /** A poll is awaiting a response; the next interval tick must not start another. */
  const inFlight = useRef(false);

  const log = useCallback((message: string) => {
    setState((s) => ({ ...s, log: [...s.log, { time: stamp(), message }] }));
  }, []);

  const stopPolling = useCallback(() => {
    if (timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
  }, []);

  const settle = useCallback(
    (job: {
      status: JobStatus;
      warnings?: string[];
      summary?: Summary;
      ai?: AiGate;
      ai_error?: string;
      error?: string;
    }) => {
      stopPolling();
      localStorage.removeItem(STORAGE_KEY);
      setState((s) => ({
        ...s,
        status: job.status,
        // Warnings must survive onto the success card — the copy tells the
        // operator to verify them before using the report.
        warnings: job.warnings ?? s.warnings,
        summary: job.summary ?? s.summary,
        ai: job.ai ?? s.ai,
        aiError: job.ai_error ?? s.aiError,
        error: job.error ?? s.error,
        stalled: false,
      }));
    },
    [stopPolling],
  );

  const poll = useCallback(
    async (jobId: string) => {
      // A backend that answers in more than POLL_MS would otherwise have two or
      // more polls in flight at once, each incrementing the same counters — the
      // stall note and the "Lost contact" verdict would then fire after fewer
      // real round-trips than they claim to wait for.
      if (inFlight.current) return;
      inFlight.current = true;
      try {
        const job = await api.getJob(jobId);
        failures.current = 0;

        if (job.progress && job.progress !== lastProgress.current) {
          lastProgress.current = job.progress;
          // This poll is the first of the run that reported this message, so the
          // run of consecutive polls carrying it starts at one, not zero.
          unchanged.current = 1;
          log(job.progress);
          setState((s) => ({ ...s, stalled: false }));
        } else {
          unchanged.current += 1;
          if (unchanged.current >= STALL_POLLS) {
            setState((s) => (s.stalled ? s : { ...s, stalled: true }));
          }
        }

        // settle owns the warnings on a terminal payload. Running the diff below
        // first would overwrite them with the terminal payload's own (possibly
        // absent) list, so settle's fallback to the previous state would find an
        // already-emptied list and the earlier warnings would be lost.
        if (TERMINAL_STATUSES.includes(job.status)) {
          settle(job);
          return;
        }

        // Only re-render warnings when they actually changed: this list is in an
        // aria-live region, and rebuilding it every second spams screen readers.
        setState((s) =>
          JSON.stringify(job.warnings ?? []) === JSON.stringify(s.warnings)
            ? s
            : { ...s, warnings: job.warnings ?? [] },
        );
      } catch {
        failures.current += 1;
        if (failures.current >= DEAD_POLLS) {
          stopPolling();
          localStorage.removeItem(STORAGE_KEY);
          setState((s) => ({
            ...s,
            status: 'error',
            error: 'Lost contact with the server. The job may still be running.',
          }));
        }
      } finally {
        inFlight.current = false;
      }
    },
    [log, settle, stopPolling],
  );

  const startPolling = useCallback(
    (jobId: string) => {
      stopPolling();
      failures.current = 0;
      unchanged.current = 0;
      inFlight.current = false;
      // The new job's first progress message may be the same string the previous
      // job ended on. Carrying it over would make that message look unchanged —
      // it would never reach the activity log, and the stall counter would start
      // climbing on a job that has only just begun.
      lastProgress.current = '';
      timer.current = setInterval(() => void poll(jobId), POLL_MS);
    },
    [poll, stopPolling],
  );

  const submit = useCallback(
    async (files: File[], ai: boolean) => {
      setState({ ...INITIAL, status: 'uploading' });
      try {
        const { jobId, uploads } = await api.createUploads(files.map((f) => f.name));
        setState((s) => ({ ...s, jobId }));
        localStorage.setItem(STORAGE_KEY, jobId);
        log('Uploading files…');

        for (const target of uploads) {
          const file = files.find((f) => f.name === target.filename);
          if (!file) continue;
          await api.uploadFile(target.url, file, (percent) =>
            setState((s) => ({
              ...s,
              uploadProgress: { ...s.uploadProgress, [target.filename]: percent },
            })),
          );
        }

        log('Upload complete. Queued for processing…');
        await api.startJob(jobId, ai);
        setState((s) => ({ ...s, status: 'queued' }));
        startPolling(jobId);
      } catch (err) {
        // An upload that failed means the pipeline would parse a partial set —
        // so the job is never started. Clear the id: nothing is running.
        localStorage.removeItem(STORAGE_KEY);
        setState((s) => ({
          ...s,
          // Drop the id too: nothing is running, so leaving it set would keep the
          // Cancel action live against a job the server was never told to start.
          jobId: null,
          status: 'error',
          error: err instanceof Error ? err.message : 'Upload failed.',
        }));
      }
    },
    [log, startPolling],
  );

  const cancel = useCallback(async () => {
    const jobId = state.jobId;
    if (!jobId) return;
    log('Cancelling…');
    try {
      const { status } = await api.cancelJob(jobId);
      stopPolling();
      localStorage.removeItem(STORAGE_KEY);

      if (status === 'cancelled') {
        // Back to the upload form, file selections intact (the old softReset).
        setState({ ...INITIAL, status: 'idle' });
      } else {
        // The job finished before StopExecution landed. Report the status the
        // server actually returned rather than claiming a cancel that did not
        // occur — the operator acts on this. The record is fetched only to fill
        // in the summary/warnings the result card needs; its status does not
        // override what cancel told us.
        let record: Job | null = null;
        try {
          record = await api.getJob(jobId);
        } catch {
          /* details unavailable — still report the real status */
        }
        settle({ ...(record ?? {}), status });
      }
    } catch (err) {
      log(err instanceof Error ? err.message : 'Cancel failed.');
    }
  }, [state.jobId, log, settle, stopPolling]);

  const reset = useCallback(() => {
    stopPolling();
    localStorage.removeItem(STORAGE_KEY);
    lastProgress.current = '';
    setState(INITIAL);
  }, [stopPolling]);

  // Reconnect: a refresh during a long parse must not lose sight of a job that
  // is still running (and still billing).
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return;

    void (async () => {
      try {
        const job = await api.getJob(stored);
        if (TERMINAL_STATUSES.includes(job.status)) {
          localStorage.removeItem(STORAGE_KEY);
          return;
        }
        setState((s) => ({ ...s, jobId: stored, status: job.status }));
        log('Reconnected to running job…');
        startPolling(stored);
      } catch {
        // The job is gone (retention expired, or a bad id). Do not strand the
        // operator on a screen polling something that no longer exists.
        localStorage.removeItem(STORAGE_KEY);
      }
    })();
    // Mount only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  // submit() flips the status to `uploading` — which renders the Cancel button —
  // before createUploads() has come back with the id that cancel() needs. Against
  // a real API over a VPN that round-trip is not instant, and in that window a
  // Cancel that calls cancel() would silently no-op: a dead control. The button
  // is therefore disabled until the id exists. A disabled control that becomes
  // enabled is honest; a live control that does nothing is not.
  const canCancel = state.jobId !== null;

  return { state, submit, cancel, reset, canCancel };
}
