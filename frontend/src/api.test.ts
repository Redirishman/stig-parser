import { beforeEach, describe, expect, it, vi } from 'vitest';
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

  it('does not put Content-Type on a bodyless GET', async () => {
    // Content-Type makes a GET a non-simple request: against a cross-origin API
    // Gateway every 1s poll would drag a CORS preflight behind it (2 req/sec), and
    // 403 outright if OPTIONS is not wired.
    const fetchMock = mockFetch(200, { jobId: 'j1', status: 'running' });
    vi.stubGlobal('fetch', fetchMock);

    await getJob('j1');

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers ?? {}).not.toHaveProperty('Content-Type');
  });

  it('still sends Content-Type on a request that has a body', async () => {
    const fetchMock = mockFetch(201, { jobId: 'j1', uploads: [] });
    vi.stubGlobal('fetch', fetchMock);

    await createUploads(['a.xml']);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers).toMatchObject({ 'Content-Type': 'application/json' });
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
