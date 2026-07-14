import {
  ApiError,
  UploadAbortedError,
  type Config,
  type Job,
  type JobStatus,
  type UploadsResponse,
} from './types';

/**
 * Base url of the private API, injected at build time. Empty in dev and in
 * tests, where requests are relative and get mocked or proxied.
 */
const BASE: string = import.meta.env.VITE_API_BASE ?? '';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // Content-Type ONLY when there is a body to describe. On a bodyless GET it is a
  // lie about the request and, worse, it makes the request non-simple: against a
  // cross-origin API Gateway the 1s status poll would drag a CORS preflight behind
  // every tick (2 req/sec), and fail outright with 403 if OPTIONS is not wired.
  const headers: Record<string, string> = {
    ...(init?.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    ...((init?.headers as Record<string, string> | undefined) ?? {}),
  };

  const res = await fetch(`${BASE}${path}`, { ...init, headers });

  if (!res.ok) {
    // Prefer the server's curated message — it is written for the operator.
    // Fall back to the status only when there is nothing to read.
    let message = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
    } catch {
      /* no JSON body — keep the fallback */
    }
    throw new ApiError(res.status, message);
  }
  return (await res.json()) as T;
}

export function getConfig(): Promise<Config> {
  return request<Config>('/config');
}

export function createUploads(filenames: string[]): Promise<UploadsResponse> {
  return request<UploadsResponse>('/uploads', {
    method: 'POST',
    body: JSON.stringify({ filenames }),
  });
}

export function startJob(jobId: string, ai: boolean): Promise<{ jobId: string }> {
  return request('/jobs', { method: 'POST', body: JSON.stringify({ jobId, ai }) });
}

export function getJob(jobId: string): Promise<Job> {
  return request<Job>(`/jobs/${encodeURIComponent(jobId)}`);
}

export function getResultUrl(jobId: string): Promise<{ url: string }> {
  return request(`/jobs/${encodeURIComponent(jobId)}/result`);
}

/**
 * The status is the job's real lifecycle state, not a free string: the caller
 * puts it straight into the UI state, so a widened `string` here would let an
 * unknown value through unchecked and render a status the app cannot handle.
 */
export function cancelJob(jobId: string): Promise<{ jobId: string; status: JobStatus }> {
  return request(`/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' });
}

/**
 * PUT a file straight to S3 with its presigned url.
 *
 * XMLHttpRequest rather than fetch: fetch still cannot report upload progress,
 * and a 200 MB scan over a VPN with no progress bar looks like a hang.
 *
 * The bytes never pass through a Lambda — that is what keeps a large upload
 * clear of API Gateway's 29-second ceiling.
 *
 * `signal` makes the transfer abortable. A 200 MB scan over a VPN occupies this
 * call for minutes; a Cancel in that window has to actually stop the bytes, not
 * merely stop watching them.
 */
export function uploadFile(
  url: string,
  file: File,
  onProgress: (percent: number) => void,
  signal?: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new UploadAbortedError());
      return;
    }

    const xhr = new XMLHttpRequest();
    xhr.open('PUT', url);

    const abort = () => xhr.abort();
    signal?.addEventListener('abort', abort);
    const cleanup = () => signal?.removeEventListener('abort', abort);

    xhr.upload.onprogress = (e: ProgressEvent) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
    };

    xhr.onload = () => {
      cleanup();
      if (xhr.status >= 200 && xhr.status < 300) {
        onProgress(100);
        resolve();
      } else {
        // A presigned url lives 15 minutes; a slow upload can outlive one.
        reject(new ApiError(xhr.status, `Upload failed for ${file.name} (${xhr.status}).`));
      }
    };
    xhr.onerror = () => {
      cleanup();
      reject(new ApiError(0, `Upload failed for ${file.name}.`));
    };
    // xhr.abort() fires this, not onerror. A deliberate abort is not a failure:
    // its own type keeps the caller from reporting "Upload failed" for a Cancel.
    xhr.onabort = () => {
      cleanup();
      reject(new UploadAbortedError());
    };

    xhr.send(file);
  });
}
