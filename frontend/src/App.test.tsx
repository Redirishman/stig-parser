import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import App from './App';
import { ApiError, type Job, type UploadsResponse } from './types';

const CONFIG = {
  aiAvailable: false,
  aiReason: 'disabled-globally' as const,
  maxUploadBytes: 1000,
  allowedExtensions: ['.xml', '.zip', '.cklb', '.nessus'],
};

const SUMMARY = { files: 1, hosts: 1, findings: 3, cat1: 1, cat2: 1, cat3: 1 };

/** Drive the app from the upload form to whatever terminal status the job ends in. */
async function runToTerminal(job: Job) {
  vi.spyOn(api, 'createUploads').mockResolvedValue({
    jobId: 'j1',
    uploads: [{ filename: 'scan.xml', url: 'https://s3/put' }],
  });
  vi.spyOn(api, 'uploadFile').mockResolvedValue(undefined);
  vi.spyOn(api, 'startJob').mockResolvedValue({ jobId: 'j1' });
  vi.spyOn(api, 'getJob').mockResolvedValue(job);

  render(<App />);
  const input = await screen.findByLabelText(/scan results files/i);
  await userEvent.upload(input, new File(['x'], 'scan.xml'));
  await userEvent.click(screen.getByRole('button', { name: /^process$/i }));
}

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

  it('does not offer Cancel as a live control before the job id exists', async () => {
    // The race: submit() sets the status to `uploading` — which renders Cancel —
    // before createUploads() resolves with the jobId that cancel() needs. Over a
    // VPN that round-trip is slow enough for an operator to click, and cancel()
    // with no jobId no-ops. Cancel must be visibly unavailable until the id lands.
    let release!: (res: UploadsResponse) => void;
    vi.spyOn(api, 'createUploads').mockReturnValue(
      new Promise<UploadsResponse>((resolve) => {
        release = resolve;
      }),
    );
    vi.spyOn(api, 'startJob').mockResolvedValue({ jobId: 'j1' });
    vi.spyOn(api, 'getJob').mockResolvedValue({ jobId: 'j1', status: 'running' });

    render(<App />);
    const input = await screen.findByLabelText(/scan results files/i);
    await userEvent.upload(input, new File(['x'], 'scan.xml'));
    await userEvent.click(screen.getByRole('button', { name: /^process$/i }));

    const cancelButton = await screen.findByRole('button', { name: /^cancel$/i });
    expect(cancelButton).toBeDisabled();

    // Once the id arrives the control becomes real.
    await act(async () => {
      release({ jobId: 'j1', uploads: [] });
    });
    await waitFor(() => expect(cancelButton).toBeEnabled());
  });

  it('surfaces a config failure instead of rendering a broken form', async () => {
    vi.spyOn(api, 'getConfig').mockRejectedValue(new Error('network'));
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not reach the server/i);
  });
});

describe('App download failures', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
    vi.spyOn(api, 'getConfig').mockResolvedValue(CONFIG);
  });

  it('says the report expired on a 410 rather than doing nothing', async () => {
    // The retention window closed. "Nothing happened" would leave the operator
    // clicking a button on a card that still says Report Ready.
    vi.spyOn(api, 'getResultUrl').mockRejectedValue(
      new ApiError(410, 'Report expired.'),
    );
    await runToTerminal({ jobId: 'j1', status: 'complete', summary: SUMMARY });

    await userEvent.click(
      await screen.findByRole('button', { name: /download excel report/i }),
    );

    expect(await screen.findByRole('alert')).toHaveTextContent(/expired/i);
  });

  it('surfaces a generic download failure instead of swallowing it', async () => {
    vi.spyOn(api, 'getResultUrl').mockRejectedValue(new ApiError(500, 'Server error.'));
    await runToTerminal({ jobId: 'j1', status: 'complete', summary: SUMMARY });

    await userEvent.click(
      await screen.findByRole('button', { name: /download excel report/i }),
    );

    expect(await screen.findByRole('alert')).toHaveTextContent(/server error/i);
  });
});
