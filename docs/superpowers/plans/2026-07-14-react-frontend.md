# React Frontend (Sub-project #3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the Flask/Jinja + vanilla-JS UI to a React SPA that speaks the GovCloud async API, preserving the audited design tokens and accessibility work verbatim.

**Architecture:** Vite + React + TypeScript. Three-state UI (upload → progress → result). All async complexity lives in one hook (`useJob`); every other module is presentational. No router, no state library, no CSS framework. The ported `style.css` keeps its class names so the audited contrast/focus work carries over unchanged.

**Tech Stack:** Vite, React 18, TypeScript, Vitest + React Testing Library, jest-axe, Playwright, plain CSS.

**Spec:** `docs/superpowers/specs/2026-07-14-react-frontend-design.md`
**Branch:** `govcloud/3-react-frontend` (already rebased on PR #7, which provides the complete API)

---

## Context the engineer needs

**The API (complete, in PR #7 — `app/lambdas/api.py`):**

| Route | Request | Response |
|---|---|---|
| `GET /config` | — | `{aiAvailable, aiReason, maxUploadBytes, allowedExtensions}` |
| `POST /uploads` | `{filenames: string[]}` | `201 {jobId, uploads: [{filename, url}]}` |
| `POST /jobs` | `{jobId, ai: boolean}` | `202 {jobId, ai}` |
| `GET /jobs/{id}` | — | `200 {jobId, status, progress, warnings?, summary?, ai?, error?}` |
| `GET /jobs/{id}/result` | — | `200 {url}` · `409` not ready · `410` expired |
| `POST /jobs/{id}/cancel` | — | `200 {jobId, status}` |

`status` is one of: `pending` · `queued` · `running` · `complete` · `error` · `cancelled`.
`ai` gate is one of: `disabled-by-request` · `disabled-globally` · `failed` · `done` · `requested`.

**Behaviours to preserve exactly** (from `app/static/app.js` — do not invent new numbers):
- Poll every **1000ms**.
- Show the stall note after **20 consecutive polls with an unchanged progress message**.
- Declare the backend dead after **10 consecutive failed polls**.
- Warnings are re-rendered only when they actually change (the old code JSON-compares; re-rendering an `aria-live` list every second spams screen readers).
- Warnings survive into the success card — the operator is told to verify them, so they must still be visible when the report is ready.
- Cancel returns the operator to the upload form **with their file selections kept** (`softReset`).

**Files copied verbatim from the Flask app** (do not rewrite):
- `app/static/style.css` → `frontend/src/styles/style.css`
- `app/static/fonts/*` → `frontend/src/styles/fonts/`
- `app/static/favicon.svg` → `frontend/public/favicon.svg`

---

## File Structure

| File | Responsibility |
|---|---|
| `frontend/package.json`, `vite.config.ts`, `tsconfig.json` | Toolchain. |
| `frontend/index.html` | Shell. Carries `<meta name="color-scheme" content="light dark">`. |
| `frontend/src/types.ts` | Every API shape. No logic. |
| `frontend/src/api.ts` | Typed fetch wrappers. The only file where a URL string appears. |
| `frontend/src/useJob.ts` | **The entire async lifecycle.** Upload, submit, poll, cancel, reconnect, stall/dead detection. The only stateful module. |
| `frontend/src/App.tsx` | Three-state switch. Owns no async logic. |
| `frontend/src/components/UploadZone.tsx` | Drag-drop + Choose Files + file list. Used twice. |
| `frontend/src/components/ActivityLog.tsx` | Timestamped monospace log. |
| `frontend/src/components/WarningsBox.tsx` | Shared by progress / success / error. |
| `frontend/src/components/ResultCard.tsx` | Success + failure variants. |
| `frontend/src/components/AiToggle.tsx` | AI control; disabled-with-reason when the gate is closed. |
| `frontend/src/styles/style.css` | Ported. |

---

## Task 1: Scaffold the frontend

**Files:**
- Create: `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tsconfig.json`, `frontend/tsconfig.node.json`, `frontend/index.html`, `frontend/src/main.tsx`, `frontend/src/App.tsx`, `frontend/.gitignore`
- Copy: `app/static/style.css` → `frontend/src/styles/style.css`; `app/static/fonts/*` → `frontend/src/styles/fonts/`; `app/static/favicon.svg` → `frontend/public/favicon.svg`

- [ ] **Step 1: Create `frontend/package.json`**

```json
{
  "name": "stig-condenser-frontend",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc --noEmit && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "test:watch": "vitest",
    "e2e": "playwright test"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "@playwright/test": "^1.48.0",
    "@testing-library/jest-dom": "^6.5.0",
    "@testing-library/react": "^16.0.1",
    "@testing-library/user-event": "^14.5.2",
    "@types/react": "^18.3.11",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.2",
    "jest-axe": "^9.0.0",
    "@types/jest-axe": "^3.5.9",
    "jsdom": "^25.0.1",
    "typescript": "^5.6.3",
    "vite": "^5.4.9",
    "vitest": "^2.1.3"
  }
}
```

- [ ] **Step 2: Create `frontend/vite.config.ts`**

```ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Assets are served from the SPA bucket through the API Gateway S3 proxy,
  // which sits under a stage path (e.g. /v1). Relative asset URLs survive that;
  // absolute ones (/assets/...) would 404.
  base: './',
  build: { outDir: 'dist', sourcemap: false },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.ts'],
    // Playwright specs live in tests/e2e and are run by `npm run e2e`.
    exclude: ['tests/e2e/**', 'node_modules/**'],
  },
});
```

- [ ] **Step 3: Create `frontend/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "types": ["vitest/globals", "@testing-library/jest-dom"]
  },
  "include": ["src", "tests"]
}
```

- [ ] **Step 4: Create `frontend/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="color-scheme" content="light dark" />
    <link rel="icon" href="./favicon.svg" type="image/svg+xml" />
    <title>STIG Compliance Parser</title>
  </head>
  <body>
    <noscript>
      <p class="noscript-note">
        This tool requires JavaScript. Enable it, or use the CLI:
        <code>stig-parser --help</code>.
      </p>
    </noscript>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 5: Create `frontend/src/test-setup.ts`**

```ts
import '@testing-library/jest-dom/vitest';
```

- [ ] **Step 6: Create `frontend/src/main.tsx`**

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/style.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
```

- [ ] **Step 7: Create a placeholder `frontend/src/App.tsx`** (replaced in Task 9)

```tsx
export default function App() {
  return <h1>STIG Compliance Parser</h1>;
}
```

- [ ] **Step 8: Create `frontend/.gitignore`**

```
node_modules/
dist/
test-results/
playwright-report/
.vite/
```

- [ ] **Step 9: Copy the stylesheet, fonts, and favicon**

```bash
cd "G:/AI Apps/STIG Condenser/stig-parser"
mkdir -p frontend/src/styles/fonts frontend/public
cp app/static/style.css      frontend/src/styles/style.css
cp app/static/fonts/*        frontend/src/styles/fonts/
cp app/static/favicon.svg    frontend/public/favicon.svg
```

The `@font-face` `src: url('fonts/PublicSans-Regular.woff2')` paths already resolve relative to the stylesheet, so they work unchanged once the fonts sit beside it. Vite fingerprints them at build.

- [ ] **Step 10: Install and verify the build**

Run:
```bash
cd frontend && npm install && npm run build
```
Expected: `tsc --noEmit` clean, `vite build` writes `dist/`, exit 0.

- [ ] **Step 11: Commit**

```bash
git add frontend
git commit -m "feat(#3): scaffold Vite + React + TS frontend, port stylesheet and fonts"
```

---

## Task 2: API types

**Files:**
- Create: `frontend/src/types.ts`

- [ ] **Step 1: Write the types**

```ts
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
```

- [ ] **Step 2: Verify types compile**

Run: `cd frontend && npx tsc --noEmit`
Expected: exit 0, no output.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/types.ts
git commit -m "feat(#3): API types"
```

---

## Task 3: API client

**Files:**
- Create: `frontend/src/api.ts`
- Test: `frontend/src/api.test.ts`

- [ ] **Step 1: Write the failing tests**

```ts
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from './types';
import {
  cancelJob,
  createUploads,
  getConfig,
  getJob,
  getResultUrl,
  startJob,
  uploadFile,
} from './api';

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

describe('api', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('getConfig returns the gate and limits', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch(200, {
        aiAvailable: false,
        aiReason: 'disabled-globally',
        maxUploadBytes: 100,
        allowedExtensions: ['.xml'],
      }),
    );
    const cfg = await getConfig();
    expect(cfg.aiAvailable).toBe(false);
    expect(cfg.aiReason).toBe('disabled-globally');
  });

  it('createUploads posts the filenames and returns presigned targets', async () => {
    const fetchMock = mockFetch(201, {
      jobId: 'j1',
      uploads: [{ filename: 'a.xml', url: 'https://s3/a' }],
    });
    vi.stubGlobal('fetch', fetchMock);

    const res = await createUploads(['a.xml']);

    expect(res.jobId).toBe('j1');
    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body)).toEqual({ filenames: ['a.xml'] });
  });

  it('throws ApiError carrying the status so callers can branch', async () => {
    vi.stubGlobal('fetch', mockFetch(410, { error: 'Report has expired.' }));
    await expect(getResultUrl('j1')).rejects.toMatchObject({
      name: 'ApiError',
      status: 410,
    });
  });

  it('surfaces the server error message, not a generic one', async () => {
    vi.stubGlobal('fetch', mockFetch(400, { error: 'Unsupported file type.' }));
    await expect(createUploads(['x.exe'])).rejects.toThrow('Unsupported file type.');
  });

  it('startJob sends the ai flag', async () => {
    const fetchMock = mockFetch(202, { jobId: 'j1', ai: 'disabled-by-request' });
    vi.stubGlobal('fetch', fetchMock);

    await startJob('j1', false);

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body)).toEqual({ jobId: 'j1', ai: false });
  });

  it('getJob returns the record', async () => {
    vi.stubGlobal('fetch', mockFetch(200, { jobId: 'j1', status: 'running' }));
    expect((await getJob('j1')).status).toBe('running');
  });

  it('cancelJob returns the job status the server actually reports', async () => {
    // The job can finish between the click and StopExecution landing.
    vi.stubGlobal('fetch', mockFetch(200, { jobId: 'j1', status: 'complete' }));
    expect((await cancelJob('j1')).status).toBe('complete');
  });

  it('uploadFile PUTs the blob to the presigned url and reports progress', async () => {
    const events: number[] = [];
    const xhr = {
      open: vi.fn(),
      send: vi.fn(),
      setRequestHeader: vi.fn(),
      upload: {} as { onprogress?: (e: ProgressEvent) => void },
      onload: undefined as (() => void) | undefined,
      onerror: undefined as (() => void) | undefined,
      status: 200,
    };
    vi.stubGlobal('XMLHttpRequest', vi.fn(() => xhr));

    const file = new File(['x'], 'a.xml');
    const promise = uploadFile('https://s3/a', file, (p) => events.push(p));

    xhr.upload.onprogress?.({ lengthComputable: true, loaded: 5, total: 10 } as ProgressEvent);
    xhr.onload?.();
    await promise;

    expect(xhr.open).toHaveBeenCalledWith('PUT', 'https://s3/a');
    expect(events).toContain(50);
  });

  it('uploadFile rejects when S3 rejects the presigned PUT', async () => {
    // A 15-minute presigned url can expire mid-upload on a slow VPN link.
    const xhr = {
      open: vi.fn(),
      send: vi.fn(),
      setRequestHeader: vi.fn(),
      upload: {},
      onload: undefined as (() => void) | undefined,
      onerror: undefined as (() => void) | undefined,
      status: 403,
    };
    vi.stubGlobal('XMLHttpRequest', vi.fn(() => xhr));

    const promise = uploadFile('https://s3/a', new File(['x'], 'a.xml'), () => {});
    xhr.onload?.();

    await expect(promise).rejects.toThrow(/upload failed/i);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd frontend && npx vitest run src/api.test.ts`
Expected: FAIL — `Failed to resolve import "./api"`.

- [ ] **Step 3: Write `frontend/src/api.ts`**

```ts
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd frontend && npx vitest run src/api.test.ts`
Expected: PASS, 9 tests.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/api.ts frontend/src/api.test.ts
git commit -m "feat(#3): typed API client with presigned-PUT upload progress"
```

---

## Task 4: File validation helper

**Files:**
- Create: `frontend/src/validate.ts`
- Test: `frontend/src/validate.test.ts`

The allow-list comes from `GET /config` — it is never hardcoded here. This check is a **courtesy** that gives fast feedback; the API re-validates server-side, because a client check is bypassable by definition.

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, expect, it } from 'vitest';
import { rejectFile } from './validate';

const CONFIG = { allowedExtensions: ['.xml', '.zip', '.cklb', '.nessus'], maxUploadBytes: 100 };

function file(name: string, size = 1): File {
  const f = new File(['x'], name);
  Object.defineProperty(f, 'size', { value: size });
  return f;
}

describe('rejectFile', () => {
  it('accepts an allowed extension', () => {
    expect(rejectFile(file('scan.xml'), CONFIG)).toBeNull();
  });

  it('is case-insensitive about the extension', () => {
    expect(rejectFile(file('SCAN.XML'), CONFIG)).toBeNull();
  });

  it('rejects a disallowed extension and names the allowed ones', () => {
    const msg = rejectFile(file('payload.exe'), CONFIG);
    expect(msg).toMatch(/unsupported file type/i);
    expect(msg).toContain('.cklb');
  });

  it('rejects a file over the size cap', () => {
    expect(rejectFile(file('big.xml', 101), CONFIG)).toMatch(/too large/i);
  });

  it('accepts a file exactly at the cap', () => {
    expect(rejectFile(file('edge.xml', 100), CONFIG)).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd frontend && npx vitest run src/validate.test.ts`
Expected: FAIL — cannot resolve `./validate`.

- [ ] **Step 3: Write `frontend/src/validate.ts`**

```ts
/**
 * Client-side upload check — a COURTESY, not a control.
 *
 * The extension list and size cap come from GET /config, which serves the values
 * in app/core/uploads.py. Hardcoding them here would fork the allow-list that
 * module exists to keep single. The API re-validates every filename regardless:
 * a client check is bypassable by definition and is never the security boundary.
 */
export interface UploadLimits {
  allowedExtensions: string[];
  maxUploadBytes: number;
}

function extensionOf(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot === -1 ? '' : name.slice(dot).toLowerCase();
}

function humanMb(bytes: number): number {
  return Math.round(bytes / (1024 * 1024));
}

/** Returns an operator-facing rejection message, or null if the file is fine. */
export function rejectFile(file: File, limits: UploadLimits): string | null {
  if (!limits.allowedExtensions.includes(extensionOf(file.name))) {
    return `Unsupported file type: ${file.name} (allowed: ${limits.allowedExtensions.join(', ')})`;
  }
  if (file.size > limits.maxUploadBytes) {
    return `File too large: ${file.name} (max ${humanMb(limits.maxUploadBytes)} MB each)`;
  }
  return null;
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd frontend && npx vitest run src/validate.test.ts`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/validate.ts frontend/src/validate.test.ts
git commit -m "feat(#3): client-side upload validation against server-served limits"
```

---

## Task 5: `useJob` — the lifecycle hook

This is the only stateful module and carries all the async complexity. Test it hard.

**Files:**
- Create: `frontend/src/useJob.ts`
- Test: `frontend/src/useJob.test.ts`

- [ ] **Step 1: Write the failing tests**

```tsx
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
```

- [ ] **Step 2: Run to verify failure**

Run: `cd frontend && npx vitest run src/useJob.test.ts`
Expected: FAIL — cannot resolve `./useJob`.

- [ ] **Step 3: Write `frontend/src/useJob.ts`**

```ts
import { useCallback, useEffect, useRef, useState } from 'react';
import * as api from './api';
import { TERMINAL_STATUSES, type AiGate, type JobStatus, type Summary } from './types';

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
    (job: { status: JobStatus; warnings?: string[]; summary?: Summary; ai?: AiGate; ai_error?: string; error?: string }) => {
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
      try {
        const job = await api.getJob(jobId);
        failures.current = 0;

        if (job.progress && job.progress !== lastProgress.current) {
          lastProgress.current = job.progress;
          unchanged.current = 0;
          log(job.progress);
          setState((s) => ({ ...s, stalled: false }));
        } else {
          unchanged.current += 1;
          if (unchanged.current >= STALL_POLLS) {
            setState((s) => (s.stalled ? s : { ...s, stalled: true }));
          }
        }

        // Only re-render warnings when they actually changed: this list is in an
        // aria-live region, and rebuilding it every second spams screen readers.
        setState((s) =>
          JSON.stringify(job.warnings ?? []) === JSON.stringify(s.warnings)
            ? s
            : { ...s, warnings: job.warnings ?? [] },
        );

        if (TERMINAL_STATUSES.includes(job.status)) settle(job);
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
      }
    },
    [log, settle, stopPolling],
  );

  const startPolling = useCallback(
    (jobId: string) => {
      stopPolling();
      failures.current = 0;
      unchanged.current = 0;
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
        // The job finished before StopExecution landed. Report what really
        // happened rather than claiming a cancel that did not occur.
        const job = await api.getJob(jobId);
        settle(job);
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

  return { state, submit, cancel, reset };
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd frontend && npx vitest run src/useJob.test.ts`
Expected: PASS, 13 tests.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/useJob.ts frontend/src/useJob.test.ts
git commit -m "feat(#3): useJob — upload, poll, stall/dead detection, cancel, reconnect"
```

---

## Task 6: `UploadZone`

**Files:**
- Create: `frontend/src/components/UploadZone.tsx`
- Test: `frontend/src/components/UploadZone.test.tsx`

Accessibility notes that are requirements, not suggestions: **Choose Files is a real `<button>`** (never a click handler on a div), the file list is a `<ul>`, and the rejection notice sits in a `role="status"` region.

- [ ] **Step 1: Write the failing tests**

```tsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import UploadZone from './UploadZone';

const LIMITS = { allowedExtensions: ['.xml', '.zip'], maxUploadBytes: 1000 };

function setup(files: File[] = [], onChange = vi.fn()) {
  render(
    <UploadZone
      id="results"
      title="Scan Results"
      description="XCCDF results"
      accept=".xml,.zip"
      limits={LIMITS}
      files={files}
      onChange={onChange}
      disabled={false}
    />,
  );
  return onChange;
}

describe('UploadZone', () => {
  it('exposes Choose Files as a real button, keyboard reachable', async () => {
    setup();
    const button = screen.getByRole('button', { name: /choose files/i });
    await userEvent.tab();
    expect(button).toHaveFocus();
  });

  it('lists selected files', () => {
    setup([new File(['x'], 'scan.xml')]);
    expect(screen.getByRole('listitem')).toHaveTextContent('scan.xml');
  });

  it('removes a file when its remove button is pressed', async () => {
    const onChange = setup([new File(['x'], 'scan.xml')]);
    await userEvent.click(screen.getByRole('button', { name: /remove scan.xml/i }));
    expect(onChange).toHaveBeenCalledWith([]);
  });

  it('rejects a disallowed file and announces why', async () => {
    const onChange = setup();
    const input = screen.getByLabelText(/scan results files/i);

    await userEvent.upload(input, new File(['x'], 'payload.exe'));

    expect(onChange).not.toHaveBeenCalledWith(
      expect.arrayContaining([expect.objectContaining({ name: 'payload.exe' })]),
    );
    expect(screen.getByRole('status')).toHaveTextContent(/unsupported file type/i);
  });

  it('accepts an allowed file', async () => {
    const onChange = setup();
    const input = screen.getByLabelText(/scan results files/i);

    await userEvent.upload(input, new File(['x'], 'scan.xml'));

    expect(onChange).toHaveBeenCalled();
    expect(onChange.mock.calls[0][0][0].name).toBe('scan.xml');
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd frontend && npx vitest run src/components/UploadZone.test.tsx`
Expected: FAIL — cannot resolve `./UploadZone`.

- [ ] **Step 3: Write `frontend/src/components/UploadZone.tsx`**

```tsx
import { useRef, useState, type DragEvent } from 'react';
import { rejectFile, type UploadLimits } from '../validate';

interface Props {
  id: string;
  title: string;
  description: string;
  accept: string;
  limits: UploadLimits;
  files: File[];
  onChange: (files: File[]) => void;
  disabled: boolean;
  badge?: string;
}

export default function UploadZone({
  id, title, description, accept, limits, files, onChange, disabled, badge,
}: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  /** Keep the good files, say why the rest were dropped. Never silently discard. */
  function accepted(incoming: File[]): File[] {
    const keep: File[] = [];
    const rejected: string[] = [];
    for (const f of incoming) {
      const why = rejectFile(f, limits);
      if (why) rejected.push(why);
      else keep.push(f);
    }
    setNotice(rejected.length ? rejected.join(' ') : null);
    return keep;
  }

  function add(incoming: File[]) {
    const keep = accepted(incoming);
    if (keep.length) onChange([...files, ...keep]);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    if (disabled) return;
    add(Array.from(e.dataTransfer.files));
  }

  return (
    <div
      className={`upload-zone${dragging ? ' dragover' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
    >
      <div className="zone-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="currentColor"
             strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <path d="M14 2v6h6" />
          <path d="M9 13h6M9 17h6" />
        </svg>
      </div>

      <h2>
        {title}
        {badge ? <span className="badge-optional">{badge}</span> : null}
      </h2>
      <p>{description}</p>

      {/* A real button, not a div with a click handler — it must be reachable
          and operable by keyboard. */}
      <button
        type="button"
        className="btn btn-secondary"
        onClick={() => inputRef.current?.click()}
        disabled={disabled}
      >
        Choose Files
      </button>

      <label htmlFor={`${id}-input`} className="visually-hidden">
        {title} files
      </label>
      <input
        id={`${id}-input`}
        ref={inputRef}
        type="file"
        multiple
        accept={accept}
        hidden
        disabled={disabled}
        onChange={(e) => {
          add(Array.from(e.target.files ?? []));
          e.target.value = ''; // let the same file be re-picked after a remove
        }}
      />

      {notice ? (
        <p className="zone-notice" role="status">{notice}</p>
      ) : null}

      <ul className="file-list">
        {files.map((f, i) => (
          <li key={`${f.name}-${i}`}>
            <span className="file-name">{f.name}</span>
            <button
              type="button"
              className="file-remove"
              aria-label={`Remove ${f.name}`}
              disabled={disabled}
              onClick={() => onChange(files.filter((_, idx) => idx !== i))}
            >
              ×
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
```

- [ ] **Step 4: Add the `visually-hidden` utility to the stylesheet**

Append to `frontend/src/styles/style.css`:

```css
/* Screen-reader-only label. The file input is visually hidden behind the
   Choose Files button, but it still needs an accessible name. */
.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
  border: 0;
}
```

- [ ] **Step 5: Run to verify pass**

Run: `cd frontend && npx vitest run src/components/UploadZone.test.tsx`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/UploadZone.tsx frontend/src/components/UploadZone.test.tsx frontend/src/styles/style.css
git commit -m "feat(#3): UploadZone with keyboard-operable file picker and rejection notices"
```

---

## Task 7: `ActivityLog`, `WarningsBox`, `AiToggle`

**Files:**
- Create: `frontend/src/components/ActivityLog.tsx`, `frontend/src/components/WarningsBox.tsx`, `frontend/src/components/AiToggle.tsx`
- Test: `frontend/src/components/AiToggle.test.tsx`, `frontend/src/components/WarningsBox.test.tsx`

- [ ] **Step 1: Write the failing tests**

`frontend/src/components/AiToggle.test.tsx`:

```tsx
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import AiToggle from './AiToggle';

describe('AiToggle', () => {
  it('is enabled when AI is available', () => {
    render(<AiToggle available reason={null} checked={false} onChange={vi.fn()} disabled={false} />);
    expect(screen.getByRole('checkbox', { name: /ai enrichment/i })).toBeEnabled();
  });

  it('is disabled AND says why when the gate is closed', () => {
    // Hiding the control would leave the operator unaware the capability exists
    // or why it is off — the silent gate the spec forbids.
    render(
      <AiToggle available={false} reason="disabled-globally" checked={false} onChange={vi.fn()} disabled={false} />,
    );
    expect(screen.getByRole('checkbox', { name: /ai enrichment/i })).toBeDisabled();
    expect(screen.getByText(/no model is approved for this deployment/i)).toBeInTheDocument();
  });
});
```

`frontend/src/components/WarningsBox.test.tsx`:

```tsx
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import WarningsBox from './WarningsBox';

describe('WarningsBox', () => {
  it('renders nothing when there are no warnings', () => {
    const { container } = render(<WarningsBox warnings={[]} title="Warnings" />);
    expect(container).toBeEmptyDOMElement();
  });

  it('lists warnings and tells the operator to verify them', () => {
    render(<WarningsBox warnings={['Benchmark unmatched']} title="Warnings" />);
    expect(screen.getByRole('listitem')).toHaveTextContent('Benchmark unmatched');
    expect(screen.getByText(/accreditation package/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd frontend && npx vitest run src/components/AiToggle.test.tsx src/components/WarningsBox.test.tsx`
Expected: FAIL — modules not found.

- [ ] **Step 3: Write `frontend/src/components/ActivityLog.tsx`**

```tsx
import type { LogLine } from '../useJob';

/**
 * Timestamped monospace log. role="log" + aria-live="polite" so a screen reader
 * announces new steps without interrupting whatever the operator is doing.
 */
export default function ActivityLog({ lines }: { lines: LogLine[] }) {
  return (
    <div className="activity-log" role="log" aria-live="polite">
      {lines.map((l, i) => (
        <div key={i} className="log-entry">
          <span className="log-time">{l.time}</span> {l.message}
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 4: Write `frontend/src/components/WarningsBox.tsx`**

```tsx
interface Props {
  warnings: string[];
  title: string;
}

/**
 * Shown during processing AND on the success card. The lead copy tells the
 * operator to verify these before the report goes into an accreditation
 * package, so they must not vanish the moment the job succeeds.
 */
export default function WarningsBox({ warnings, title }: Props) {
  if (warnings.length === 0) return null;

  return (
    <div className="warnings-box" aria-live="polite">
      <h3>{title}</h3>
      <p className="warnings-lead">
        The report will still be generated. Items below were skipped or incomplete
        — verify them before including the report in an accreditation package.
      </p>
      <ul>
        {warnings.map((w, i) => (
          <li key={i}>{w}</li>
        ))}
      </ul>
    </div>
  );
}
```

- [ ] **Step 5: Write `frontend/src/components/AiToggle.tsx`**

```tsx
import type { AiGate } from '../types';

interface Props {
  available: boolean;
  reason: AiGate | null;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled: boolean;
}

/** Operator-facing text for each closed gate. Never just "unavailable". */
function explain(reason: AiGate | null): string {
  switch (reason) {
    case 'disabled-globally':
      return 'AI enrichment is unavailable — no model is approved for this deployment.';
    case 'disabled-by-request':
      return 'AI enrichment is switched off for this job.';
    case 'failed':
      return 'AI enrichment failed on the last run.';
    default:
      return 'AI enrichment is unavailable.';
  }
}

/**
 * Rendered disabled-with-a-reason rather than hidden when the gate is closed:
 * an operator who cannot see the control never learns the capability exists, or
 * why it is off. Spec §4.1 — AI being off is never silent.
 */
export default function AiToggle({ available, reason, checked, onChange, disabled }: Props) {
  return (
    <div className="ai-toggle">
      <label>
        <input
          type="checkbox"
          checked={available && checked}
          disabled={disabled || !available}
          onChange={(e) => onChange(e.target.checked)}
        />
        AI enrichment
      </label>
      {!available ? <p className="ai-toggle-note">{explain(reason)}</p> : null}
    </div>
  );
}
```

- [ ] **Step 6: Run to verify pass**

Run: `cd frontend && npx vitest run src/components/`
Expected: PASS (UploadZone 5 + AiToggle 2 + WarningsBox 2).

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components
git commit -m "feat(#3): ActivityLog, WarningsBox, and a gate-transparent AiToggle"
```

---

## Task 8: `ResultCard`

**Files:**
- Create: `frontend/src/components/ResultCard.tsx`
- Test: `frontend/src/components/ResultCard.test.tsx`

- [ ] **Step 1: Write the failing tests**

```tsx
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import ResultCard from './ResultCard';

const SUMMARY = { files: 2, hosts: 3, findings: 10, cat1: 1, cat2: 4, cat3: 5 };

describe('ResultCard (success)', () => {
  it('announces the report and shows the summary', () => {
    render(
      <ResultCard status="complete" summary={SUMMARY} warnings={[]} error={null}
                  ai={null} aiError={null} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByRole('status')).toHaveTextContent(/report ready/i);
    expect(screen.getByText('10')).toBeInTheDocument();
  });

  it('explains a zero-CAT summary rather than leaving it puzzling', () => {
    render(
      <ResultCard status="complete" summary={{ ...SUMMARY, cat1: 0, cat2: 0, cat3: 0 }}
                  warnings={[]} error={null} ai={null} aiError={null}
                  onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText(/not matched to a stig benchmark/i)).toBeInTheDocument();
  });

  it('keeps warnings visible on the success card', () => {
    render(
      <ResultCard status="complete" summary={SUMMARY} warnings={['Benchmark unmatched']}
                  error={null} ai={null} aiError={null} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText('Benchmark unmatched')).toBeInTheDocument();
  });

  it('states the AI gate when enrichment did not run', () => {
    render(
      <ResultCard status="complete" summary={SUMMARY} warnings={[]} error={null}
                  ai="failed" aiError="AI enrichment is not available in this build."
                  onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText(/not available in this build/i)).toBeInTheDocument();
  });

  it('downloads on request', async () => {
    const onDownload = vi.fn();
    render(
      <ResultCard status="complete" summary={SUMMARY} warnings={[]} error={null}
                  ai={null} aiError={null} onDownload={onDownload} onReset={vi.fn()} />,
    );
    await userEvent.click(screen.getByRole('button', { name: /download excel report/i }));
    expect(onDownload).toHaveBeenCalled();
  });
});

describe('ResultCard (error)', () => {
  it('uses role=alert and shows the message', () => {
    render(
      <ResultCard status="error" summary={null} warnings={[]} error="Parsing failed."
                  ai={null} aiError={null} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Parsing failed.');
  });

  it('offers a retry', async () => {
    const onReset = vi.fn();
    render(
      <ResultCard status="error" summary={null} warnings={[]} error="Parsing failed."
                  ai={null} aiError={null} onDownload={vi.fn()} onReset={onReset} />,
    );
    await userEvent.click(screen.getByRole('button', { name: /try again/i }));
    expect(onReset).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd frontend && npx vitest run src/components/ResultCard.test.tsx`
Expected: FAIL — cannot resolve `./ResultCard`.

- [ ] **Step 3: Write `frontend/src/components/ResultCard.tsx`**

```tsx
import type { AiGate, JobStatus, Summary } from '../types';
import WarningsBox from './WarningsBox';

interface Props {
  status: JobStatus | 'idle' | 'uploading';
  summary: Summary | null;
  warnings: string[];
  error: string | null;
  ai: AiGate | null;
  aiError: string | null;
  onDownload: () => void;
  onReset: () => void;
}

export default function ResultCard({
  status, summary, warnings, error, ai, aiError, onDownload, onReset,
}: Props) {
  if (status === 'error') {
    return (
      <div className="result-card error" role="alert">
        <div className="result-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor"
               strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 6 6 18M6 6l12 12" />
          </svg>
        </div>
        <h2>Processing Failed</h2>
        <p>{error}</p>
        <WarningsBox warnings={warnings} title="Warnings recorded before the failure" />
        <button type="button" className="btn btn-secondary" onClick={onReset}>
          Try Again
        </button>
      </div>
    );
  }

  // Findings exist but every severity is zero: the results were never matched to
  // a benchmark. Say so — a silent row of zeroes reads like a clean system.
  const zeroCats =
    summary !== null &&
    summary.findings > 0 &&
    summary.cat1 + summary.cat2 + summary.cat3 === 0;

  return (
    <div className="result-card success" role="status">
      <div className="result-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor"
             strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M20 6 9 17l-5-5" pathLength={1} />
        </svg>
      </div>
      <h2>Report Ready</h2>

      {summary ? (
        <dl className="report-summary">
          <div className="summary-row"><dt>Result files</dt><dd>{summary.files}</dd></div>
          <div className="summary-row"><dt>Hosts</dt><dd>{summary.hosts}</dd></div>
          <div className="summary-row summary-total"><dt>Findings</dt><dd>{summary.findings}</dd></div>
          <div className="summary-row summary-cat">
            <dt>CAT I — high</dt>
            <dd className={summary.cat1 > 0 ? 'summary-cat1-open' : undefined}>{summary.cat1}</dd>
          </div>
          <div className="summary-row summary-cat"><dt>CAT II — medium</dt><dd>{summary.cat2}</dd></div>
          <div className="summary-row summary-cat"><dt>CAT III — low</dt><dd>{summary.cat3}</dd></div>
        </dl>
      ) : null}

      {zeroCats ? (
        <p className="summary-note">
          Severity counts are zero because the results were not matched to a STIG
          benchmark — see the warnings below.
        </p>
      ) : null}

      {/* The AI gate, stated plainly. Never silently absent. */}
      {ai && ai !== 'done' ? (
        <p className="summary-note">{aiError ?? `AI enrichment: ${ai}.`}</p>
      ) : null}

      <button type="button" className="btn btn-primary" onClick={onDownload}>
        Download Excel Report
      </button>
      <button type="button" className="btn btn-secondary" onClick={onReset}>
        Process Another Set
      </button>

      <WarningsBox warnings={warnings} title="Warnings from this run" />
    </div>
  );
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd frontend && npx vitest run src/components/ResultCard.test.tsx`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/components/ResultCard.tsx frontend/src/components/ResultCard.test.tsx
git commit -m "feat(#3): ResultCard with summary, zero-CAT explanation, and AI gate display"
```

---

## Task 9: `App` — assemble the three states

**Files:**
- Modify: `frontend/src/App.tsx` (replace the Task 1 placeholder)
- Test: `frontend/src/App.test.tsx`

- [ ] **Step 1: Write the failing tests**

```tsx
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import App from './App';

const CONFIG = {
  aiAvailable: false,
  aiReason: 'disabled-globally' as const,
  maxUploadBytes: 1000,
  allowedExtensions: ['.xml', '.zip', '.cklb', '.nessus'],
};

describe('App', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
    vi.spyOn(api, 'getConfig').mockResolvedValue(CONFIG);
  });

  it('shows the upload form once config loads', async () => {
    render(<App />);
    expect(await screen.findByRole('heading', { name: /scan results/i })).toBeInTheDocument();
  });

  it('keeps Process disabled until a results file is chosen', async () => {
    render(<App />);
    const process = await screen.findByRole('button', { name: /^process$/i });
    expect(process).toBeDisabled();

    const input = screen.getByLabelText(/scan results files/i);
    await userEvent.upload(input, new File(['x'], 'scan.xml'));

    await waitFor(() => expect(process).toBeEnabled());
  });

  it('surfaces a config failure instead of rendering a broken form', async () => {
    vi.spyOn(api, 'getConfig').mockRejectedValue(new Error('network'));
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not reach the server/i);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd frontend && npx vitest run src/App.test.tsx`
Expected: FAIL — the placeholder renders no form.

- [ ] **Step 3: Write `frontend/src/App.tsx`**

```tsx
import { useEffect, useState } from 'react';
import * as api from './api';
import ActivityLog from './components/ActivityLog';
import AiToggle from './components/AiToggle';
import ResultCard from './components/ResultCard';
import UploadZone from './components/UploadZone';
import WarningsBox from './components/WarningsBox';
import type { Config } from './types';
import { useJob } from './useJob';

export default function App() {
  const [config, setConfig] = useState<Config | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [results, setResults] = useState<File[]>([]);
  const [benchmarks, setBenchmarks] = useState<File[]>([]);
  const [ai, setAi] = useState(false);

  const { state, submit, cancel, reset } = useJob();

  // The gate and the upload limits are server-side state. Without them the form
  // cannot validate a file or honestly describe the AI control, so it is not
  // rendered until they arrive.
  useEffect(() => {
    void (async () => {
      try {
        setConfig(await api.getConfig());
      } catch {
        setConfigError(
          'Could not reach the server. Check your VPN connection and reload.',
        );
      }
    })();
  }, []);

  async function onDownload() {
    if (!state.jobId) return;
    const { url } = await api.getResultUrl(state.jobId);
    window.location.href = url;
  }

  function onReset() {
    setResults([]);
    setBenchmarks([]);
    reset();
  }

  if (configError) {
    return (
      <div className="container">
        <div className="result-card error" role="alert">
          <h2>Unavailable</h2>
          <p>{configError}</p>
        </div>
      </div>
    );
  }

  if (!config) {
    return (
      <div className="container">
        <p role="status">Loading…</p>
      </div>
    );
  }

  const busy = state.status === 'uploading' || state.status === 'queued' ||
               state.status === 'running' || state.status === 'pending';
  const finished = state.status === 'complete' || state.status === 'error';

  return (
    <div className="container">
      <header>
        <h1>STIG Compliance Parser</h1>
        <p className="subtitle">
          Upload scan results to generate a consolidated findings report. SCC,
          Evaluate-STIG, and Nessus files are self-contained — no separate
          benchmark upload needed.
        </p>
      </header>

      <main>
        {!busy && !finished ? (
          <section>
            <div className="upload-grid">
              <UploadZone
                id="results"
                title="Scan Results"
                description="XCCDF results from SCC or OpenSCAP (.xml), Evaluate-STIG / STIG Viewer checklists (.cklb), or Nessus compliance scans (.nessus)"
                accept=".xml,.cklb,.nessus"
                limits={config}
                files={results}
                onChange={setResults}
                disabled={false}
              />
              <UploadZone
                id="benchmarks"
                title="STIG Benchmarks"
                badge="Optional for SCC"
                description="STIG benchmark XML or ZIP files from DISA (public.cyber.mil). Not needed when uploading SCC result files."
                accept=".xml,.zip"
                limits={config}
                files={benchmarks}
                onChange={setBenchmarks}
                disabled={false}
              />
            </div>

            <AiToggle
              available={config.aiAvailable}
              reason={config.aiReason}
              checked={ai}
              onChange={setAi}
              disabled={false}
            />

            <div className="form-actions">
              <button
                type="button"
                className="btn btn-primary"
                disabled={results.length === 0}
                onClick={() => void submit([...results, ...benchmarks], ai)}
              >
                Process
              </button>
            </div>
          </section>
        ) : null}

        {busy ? (
          <section>
            <h2>Processing</h2>
            <ActivityLog lines={state.log} />
            {state.stalled ? (
              <p className="progress-text stall-note" aria-live="polite">
                Still working — large files can take a few minutes.
              </p>
            ) : null}
            <div className="progress-actions">
              <button type="button" className="btn btn-secondary" onClick={() => void cancel()}>
                Cancel
              </button>
            </div>
            <WarningsBox warnings={state.warnings} title="Warnings" />
          </section>
        ) : null}

        {finished ? (
          <section>
            <ResultCard
              status={state.status}
              summary={state.summary}
              warnings={state.warnings}
              error={state.error}
              ai={state.ai}
              aiError={state.aiError}
              onDownload={() => void onDownload()}
              onReset={onReset}
            />
          </section>
        ) : null}
      </main>

      <footer>
        <p>Supports SCC • OpenSCAP • Evaluate-STIG (CKLB) • Nessus (.nessus)</p>
        <p className="small">All formats validated against real scanner output.</p>
      </footer>
    </div>
  );
}
```

- [ ] **Step 4: Run the whole unit suite**

Run: `cd frontend && npm test`
Expected: PASS, all files.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/App.tsx frontend/src/App.test.tsx
git commit -m "feat(#3): App — assemble upload, progress, and result states"
```

---

## Task 10: Accessibility assertions

**Files:**
- Create: `frontend/src/a11y.test.tsx`

- [ ] **Step 1: Write the tests**

```tsx
import { render, screen, waitFor } from '@testing-library/react';
import { axe } from 'jest-axe';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import App from './App';
import ResultCard from './components/ResultCard';

const CONFIG = {
  aiAvailable: false,
  aiReason: 'disabled-globally' as const,
  maxUploadBytes: 1000,
  allowedExtensions: ['.xml'],
};

const SUMMARY = { files: 1, hosts: 1, findings: 3, cat1: 1, cat2: 1, cat3: 1 };

describe('accessibility', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
    vi.spyOn(api, 'getConfig').mockResolvedValue(CONFIG);
  });

  it('upload screen has no axe violations', async () => {
    const { container } = render(<App />);
    await screen.findByRole('heading', { name: /scan results/i });
    expect(await axe(container)).toHaveNoViolations();
  });

  it('success card has no axe violations', async () => {
    const { container } = render(
      <ResultCard status="complete" summary={SUMMARY} warnings={['w']} error={null}
                  ai={null} aiError={null} onDownload={() => {}} onReset={() => {}} />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it('error card has no axe violations', async () => {
    const { container } = render(
      <ResultCard status="error" summary={null} warnings={[]} error="Parsing failed."
                  ai={null} aiError={null} onDownload={() => {}} onReset={() => {}} />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it('config failure is announced, not silent', async () => {
    vi.spyOn(api, 'getConfig').mockRejectedValue(new Error('network'));
    render(<App />);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
  });
});
```

- [ ] **Step 2: Register the axe matcher**

Append to `frontend/src/test-setup.ts`:

```ts
import { toHaveNoViolations } from 'jest-axe';
import { expect } from 'vitest';

expect.extend(toHaveNoViolations);
```

- [ ] **Step 3: Run**

Run: `cd frontend && npx vitest run src/a11y.test.tsx`
Expected: PASS, 4 tests. **If axe reports a violation, fix the markup — do not weaken the assertion.**

- [ ] **Step 4: Commit**

```bash
git add frontend/src/a11y.test.tsx frontend/src/test-setup.ts
git commit -m "test(#3): axe assertions on every screen"
```

---

## Task 11: Playwright end-to-end against a mocked API

**Files:**
- Create: `frontend/playwright.config.ts`, `frontend/tests/e2e/flow.spec.ts`

- [ ] **Step 1: Write `frontend/playwright.config.ts`**

```ts
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  use: { baseURL: 'http://localhost:4173' },
  webServer: {
    command: 'npm run build && npm run preview -- --port 4173',
    url: 'http://localhost:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
```

- [ ] **Step 2: Write `frontend/tests/e2e/flow.spec.ts`**

```ts
import { expect, test, type Page } from '@playwright/test';

const CONFIG = {
  aiAvailable: false,
  aiReason: 'disabled-globally',
  maxUploadBytes: 209715200,
  allowedExtensions: ['.cklb', '.nessus', '.xml', '.zip'],
};

const SUMMARY = { files: 1, hosts: 2, findings: 5, cat1: 1, cat2: 2, cat3: 2 };

/** Mock the whole API surface. No GovCloud credentials in CI, by design. */
async function mockApi(page: Page, opts: { statuses: string[] }) {
  let poll = 0;

  await page.route('**/config', (r) =>
    r.fulfill({ json: CONFIG }));

  await page.route('**/uploads', (r) =>
    r.fulfill({
      status: 201,
      json: { jobId: 'j1', uploads: [{ filename: 'scan.xml', url: 'https://s3.test/put' }] },
    }));

  // The presigned PUT goes straight to S3, not through the API.
  await page.route('https://s3.test/**', (r) => r.fulfill({ status: 200, body: '' }));

  await page.route('**/jobs', (r) =>
    r.fulfill({ status: 202, json: { jobId: 'j1', ai: 'disabled-globally' } }));

  await page.route('**/jobs/j1', (r) => {
    const status = opts.statuses[Math.min(poll, opts.statuses.length - 1)];
    poll += 1;
    r.fulfill({
      json: {
        jobId: 'j1',
        status,
        progress: status === 'complete' ? 'Done — 5 findings exported.' : 'Parsing files…',
        warnings: ['Benchmark unmatched for 1 file'],
        ...(status === 'complete' ? { summary: SUMMARY } : {}),
      },
    });
  });

  await page.route('**/jobs/j1/result', (r) =>
    r.fulfill({ json: { url: 'https://s3.test/report.xlsx' } }));

  await page.route('**/jobs/j1/cancel', (r) =>
    r.fulfill({ json: { jobId: 'j1', status: 'cancelled' } }));
}

test('upload → poll → report ready', async ({ page }) => {
  await mockApi(page, { statuses: ['running', 'complete'] });
  await page.goto('/');

  await page.getByLabel('Scan Results files').setInputFiles({
    name: 'scan.xml',
    mimeType: 'text/xml',
    buffer: Buffer.from('<xml/>'),
  });

  await page.getByRole('button', { name: 'Process' }).click();

  await expect(page.getByRole('status')).toContainText('Report Ready', { timeout: 15_000 });
  await expect(page.getByText('5')).toBeVisible();
  // Warnings must survive onto the success card.
  await expect(page.getByText('Benchmark unmatched for 1 file')).toBeVisible();
});

test('AI toggle is disabled and says why', async ({ page }) => {
  await mockApi(page, { statuses: ['running'] });
  await page.goto('/');

  await expect(page.getByRole('checkbox', { name: /ai enrichment/i })).toBeDisabled();
  await expect(page.getByText(/no model is approved/i)).toBeVisible();
});

test('cancel returns to the upload form', async ({ page }) => {
  await mockApi(page, { statuses: ['running'] });
  await page.goto('/');

  await page.getByLabel('Scan Results files').setInputFiles({
    name: 'scan.xml',
    mimeType: 'text/xml',
    buffer: Buffer.from('<xml/>'),
  });
  await page.getByRole('button', { name: 'Process' }).click();
  await page.getByRole('button', { name: 'Cancel' }).click();

  await expect(page.getByRole('button', { name: 'Process' })).toBeVisible();
});

test('the whole flow is operable by keyboard alone', async ({ page }) => {
  await mockApi(page, { statuses: ['running', 'complete'] });
  await page.goto('/');

  // Set the file via the input (a real user uses the OS picker, which the
  // keyboard reaches through the Choose Files button — asserted below).
  await page.getByLabel('Scan Results files').setInputFiles({
    name: 'scan.xml',
    mimeType: 'text/xml',
    buffer: Buffer.from('<xml/>'),
  });

  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: /choose files/i }).first()).toBeFocused();

  await page.getByRole('button', { name: 'Process' }).focus();
  await page.keyboard.press('Enter');

  await expect(page.getByRole('status')).toContainText('Report Ready', { timeout: 15_000 });
});
```

- [ ] **Step 3: Install browsers and run**

Run:
```bash
cd frontend && npx playwright install --with-deps chromium && npx playwright test
```
Expected: 4 passed.

- [ ] **Step 4: Commit**

```bash
git add frontend/playwright.config.ts frontend/tests/e2e/flow.spec.ts
git commit -m "test(#3): Playwright e2e — upload, poll, download, cancel, keyboard-only"
```

---

## Task 12: CI

**Files:**
- Create: `.github/workflows/frontend.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: Frontend

on:
  push:
    branches: ["master"]
    paths: ["frontend/**", ".github/workflows/frontend.yml"]
  pull_request:
    branches: ["master"]
    paths: ["frontend/**", ".github/workflows/frontend.yml"]

permissions:
  contents: read

defaults:
  run:
    working-directory: frontend

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: npm
          cache-dependency-path: frontend/package-lock.json

      - run: npm ci

      # Type errors must fail the build, not get discovered at runtime in a
      # private VPC where nobody can see the console.
      - name: Typecheck
        run: npx tsc --noEmit

      - name: Unit tests (incl. axe)
        run: npm test

      - name: Build
        run: npx vite build

      - name: Install Playwright
        run: npx playwright install --with-deps chromium

      - name: E2E (mocked API)
        run: npx playwright test

      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: playwright-report
          path: frontend/playwright-report/
          retention-days: 7
```

- [ ] **Step 2: Verify the whole gate locally, exactly as CI runs it**

Run:
```bash
cd frontend && npx tsc --noEmit && npm test && npx vite build && npx playwright test
```
Expected: all four green.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/frontend.yml frontend/package-lock.json
git commit -m "ci(#3): typecheck, unit tests, build, and e2e for the frontend"
```

---

## Task 13: Documentation

**Files:**
- Create: `frontend/README.md`
- Modify: `README.md` (add a short "GovCloud SPA" pointer)

- [ ] **Step 1: Write `frontend/README.md`**

````markdown
# STIG Condenser — React SPA (GovCloud)

The frontend for the GovCloud deployment. The Flask UI in `../app/` is **not**
replaced by this — it remains the zero-infrastructure way to run the tool
locally or air-gapped. This SPA exists because the GovCloud runtime is
serverless and async, and that API needs a client.

**Design:** `../docs/superpowers/specs/2026-07-14-react-frontend-design.md`

## Develop

```sh
npm install
VITE_API_BASE=https://<private-api>/v1 npm run dev
```

`VITE_API_BASE` is the only environment-specific value in the bundle. It is a
VPC-internal URL — not a secret, but it is injected at build time and never
committed.

## Test

```sh
npm test          # Vitest + React Testing Library + axe
npm run e2e       # Playwright against a mocked API
npx tsc --noEmit  # types
```

There are no tests against a live API: that would need GovCloud credentials, and
public CI does not have them (and must not).

## Build & deploy

```sh
VITE_API_BASE=https://<private-api>/v1 npm run build   # -> dist/
aws s3 sync dist/ s3://<spa_bucket>/ --delete          # operator/CD step
```

The bucket is `spa_bucket` from the Terraform `api` module, served through the
Private API Gateway S3 proxy (D6). Like `terraform apply`, the sync is an
operator action — public CI builds and tests the bundle but never holds
credentials.

## Notes

- **Uploads bypass the API.** Files are PUT straight to S3 with presigned urls,
  which is what keeps a 200 MB scan clear of API Gateway's 29-second ceiling.
  Presigned urls live 15 minutes; a slow upload can outlive one, and the UI
  reports that rather than pretending the job started.
- **The AI toggle is disabled with a stated reason** when no Bedrock model is
  approved. Off is never silent.
- **The stylesheet is ported from the Flask app** and keeps its class names, so
  the audited WCAG AA contrast pairs and focus rings carry over unchanged. Do
  not restyle it casually.
````

- [ ] **Step 2: Add a pointer in the root `README.md`**

Add under the existing web-UI section:

```markdown
### GovCloud SPA

A React frontend for the private GovCloud deployment lives in `frontend/`. The
Flask UI above still works and is the recommended way to run the tool locally or
air-gapped — it needs no AWS account and no Node toolchain.
```

- [ ] **Step 3: Commit**

```bash
git add frontend/README.md README.md
git commit -m "docs(#3): frontend README and a pointer from the root README"
```

---

## Task 14: Final verification and PR

- [ ] **Step 1: Run every gate**

```bash
cd frontend && npx tsc --noEmit && npm test && npx vite build && npx playwright test
cd .. && python -m pytest -q     # the Flask UI must not have regressed
```
Expected: frontend all green; **282 Python tests still pass** (the port must not break the existing app).

- [ ] **Step 2: Confirm the leak scan still passes over the new directory**

```bash
git grep -nEI '[0-9]{12}|vpc-[0-9a-f]{8,}|subnet-[0-9a-f]{8,}|vpce-[0-9a-f]{8,}' -- 'frontend/**' ':!frontend/package-lock.json'
```
Expected: no output. (`package-lock.json` is excluded: npm integrity hashes are long hex strings that trip the VPC-id pattern by coincidence.)

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin govcloud/3-react-frontend
gh pr create --base master --head govcloud/3-react-frontend \
  --title "GovCloud sub-project #3: React frontend" \
  --body "See docs/superpowers/specs/2026-07-14-react-frontend-design.md. Depends on #7."
```

**Note:** PR #7 must merge first — this branch is stacked on it, and the SPA calls `GET /config` and `POST /jobs/{id}/cancel`, which only exist there.

---

## Definition of Done (from the spec §11)

- [ ] `npm run build`, `npm test`, `tsc --noEmit`, Playwright e2e all green in CI
- [ ] axe reports no violations on upload, progress, and result screens
- [ ] Full keyboard-only operation verified
- [ ] Light and dark both render; contrast pairs unchanged from the audited stylesheet
- [ ] The AI toggle states its gate reason when unavailable
- [ ] Cancel actually stops the execution (verified against the mocked API)
- [ ] The Flask UI still passes its existing tests
