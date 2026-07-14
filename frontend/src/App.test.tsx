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
