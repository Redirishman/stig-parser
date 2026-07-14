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

describe('ResultCard (cancelled)', () => {
  it('never renders the success card for a cancelled job', () => {
    // The success branch was guarded only by `status !== 'error'`, and the prop
    // type admits 'cancelled' — so a cancelled job could render "Report Ready"
    // with a live download button for a report that does not exist.
    render(
      <ResultCard status="cancelled" summary={SUMMARY} warnings={[]} error={null}
                  ai={null} aiError={null} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.queryByText(/report ready/i)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: /download excel report/i }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent(/cancelled/i);
  });

  it('offers a way back', async () => {
    const onReset = vi.fn();
    render(
      <ResultCard status="cancelled" summary={null} warnings={[]} error={null}
                  ai={null} aiError={null} onDownload={vi.fn()} onReset={onReset} />,
    );
    await userEvent.click(screen.getByRole('button', { name: /start over/i }));
    expect(onReset).toHaveBeenCalled();
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
