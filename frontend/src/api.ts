import { ApiError, type Config, type Job, type UploadsResponse } from './types';

/**
 * Base url of the private API, injected at build time. Empty in dev and in
 * tests, where requests are relative and get mocked or proxied.
 */
const BASE: string = import.meta.env.VITE_API_BASE ?? '';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });

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

export function cancelJob(jobId: string): Promise<{ jobId: string; status: string }> {
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
 */
export function uploadFile(
  url: string,
  file: File,
  onProgress: (percent: number) => void,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', url);

    xhr.upload.onprogress = (e: ProgressEvent) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
    };

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        onProgress(100);
        resolve();
      } else {
        // A presigned url lives 15 minutes; a slow upload can outlive one.
        reject(new ApiError(xhr.status, `Upload failed for ${file.name} (${xhr.status}).`));
      }
    };
    xhr.onerror = () => reject(new ApiError(0, `Upload failed for ${file.name}.`));

    xhr.send(file);
  });
}
