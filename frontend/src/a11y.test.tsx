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
