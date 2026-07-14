import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from './api';
import App from './App';
import ResultCard from './components/ResultCard';
import type { UploadsResponse } from './types';

const CONFIG = {
  aiAvailable: false,
  aiReason: 'disabled-globally' as const,
  maxUploadBytes: 1000,
  allowedExtensions: ['.xml'],
};

const SUMMARY = { files: 1, hosts: 1, findings: 3, cat1: 1, cat2: 1, cat3: 1 };

/** Get App from the upload form into the processing screen and stop there. */
async function toProcessing(uploads: Promise<UploadsResponse> | UploadsResponse) {
  vi.spyOn(api, 'createUploads').mockReturnValue(Promise.resolve(uploads));
  vi.spyOn(api, 'startJob').mockResolvedValue({ jobId: 'j1' });

  const view = render(<App />);
  const input = await screen.findByLabelText(/scan results files/i);
  await userEvent.upload(input, new File(['x'], 'scan.xml'));
  await userEvent.click(screen.getByRole('button', { name: /^process$/i }));
  return view;
}

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

  it('processing screen has no axe violations while uploading', async () => {
    // The screen the earlier axe pass never covered — and the one carrying every
    // live region in the app: the activity log, the stall note, the cancel-failure
    // alert, the warnings box, and the per-file progress bars.
    vi.spyOn(api, 'uploadFile').mockReturnValue(new Promise<void>(() => {}));
    vi.spyOn(api, 'getJob').mockResolvedValue({ jobId: 'j1', status: 'running' });

    const { container } = await toProcessing({
      jobId: 'j1',
      uploads: [{ filename: 'scan.xml', url: 'https://s3/put' }],
    });

    await screen.findByRole('progressbar', { name: /scan\.xml/i });
    expect(await axe(container)).toHaveNoViolations();
  });

  it('processing screen has no axe violations once the job is running', async () => {
    vi.spyOn(api, 'uploadFile').mockResolvedValue(undefined);
    vi.spyOn(api, 'getJob').mockResolvedValue({
      jobId: 'j1',
      status: 'running',
      progress: 'Parsing files…',
      warnings: ['Benchmark unmatched for 1 file'],
    });

    const { container } = await toProcessing({
      jobId: 'j1',
      uploads: [{ filename: 'scan.xml', url: 'https://s3/put' }],
    });

    await screen.findByText(/benchmark unmatched/i, undefined, { timeout: 5000 });
    expect(await axe(container)).toHaveNoViolations();
  });

  it('success card has no axe violations', async () => {
    const { container } = render(
      <ResultCard status="complete" summary={SUMMARY} warnings={['w']} error={null}
                  ai={null} aiError={null} onDownload={() => {}} onReset={() => {}} />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it('cancelled card has no axe violations', async () => {
    const { container } = render(
      <ResultCard status="cancelled" summary={null} warnings={['w']} error={null}
                  ai={null} aiError={null} onDownload={() => {}} onReset={() => {}} />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it('error card has no axe violations', async () => {
    const { container } = render(
      <ResultCard status="error" summary={null} warnings={[]} error="Parsing failed."
                  ai={null} aiError={null} onReconnect={() => {}}
                  onDownload={() => {}} onReset={() => {}} />,
    );
    expect(await axe(container)).toHaveNoViolations();
  });

  it('the empty warnings live region is present before any warning arrives', async () => {
    // An aria-live region must pre-exist the mutation to be announced. This is the
    // structural half of that guarantee, asserted where it is actually rendered.
    vi.spyOn(api, 'uploadFile').mockResolvedValue(undefined);
    vi.spyOn(api, 'getJob').mockResolvedValue({ jobId: 'j1', status: 'running' });

    const { container } = await toProcessing({
      jobId: 'j1',
      uploads: [{ filename: 'scan.xml', url: 'https://s3/put' }],
    });

    await waitFor(() =>
      expect(container.querySelector('.warnings-live')).toBeEmptyDOMElement(),
    );
  });
});
