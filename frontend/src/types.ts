/** Job lifecycle states, as returned by GET /jobs/{id}. */
export type JobStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'complete'
  | 'error'
  | 'cancelled';

/** A job in one of these states is finished; polling stops. */
export const TERMINAL_STATUSES: readonly JobStatus[] = [
  'complete',
  'error',
  'cancelled',
];

/**
 * Why AI did or did not run. The API never reports a silent gate: if enrichment
 * did not happen, this says which gate stopped it (spec §4.1).
 */
export type AiGate =
  | 'requested'
  | 'disabled-by-request'
  | 'disabled-globally'
  | 'failed'
  | 'done';

export interface Config {
  aiAvailable: boolean;
  aiReason: AiGate | null;
  maxUploadBytes: number;
  allowedExtensions: string[];
}

export interface Summary {
  files: number;
  hosts: number;
  findings: number;
  cat1: number;
  cat2: number;
  cat3: number;
}

export interface Job {
  jobId: string;
  status: JobStatus;
  progress?: string;
  warnings?: string[];
  summary?: Summary;
  ai?: AiGate;
  ai_error?: string;
  error?: string;
}

export interface UploadTarget {
  filename: string;
  url: string;
}

export interface UploadsResponse {
  jobId: string;
  uploads: UploadTarget[];
}

/** An API call that failed, carrying the status so callers can branch on it. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}
