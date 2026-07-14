import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import ResultCard from './ResultCard';

const SUMMARY = { files: 2, hosts: 3, findings: 10, cat1: 1, cat2: 4, cat3: 5 };

// Read from disk, not `import '…style.css'`: vitest stubs css imports out, and a
// stub would make the dead-selector assertion below vacuous. Comments are dropped
// so a class named in prose is never mistaken for a live rule.
const CSS = readFileSync(join(process.cwd(), 'src/styles/style.css'), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '');

/** Every selector in style.css that mentions the CAT I highlight class. */
const CAT1_SELECTORS = [...CSS.matchAll(/([^{}]*\bsummary-cat1-open\b[^{}]*)\{/g)].map(
  (m) => m[1].trim(),
);

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

  it('explains a zero-findings result rather than passing it off as a clean system', () => {
    // The most alarming outcome the parser can produce: nothing was extracted at
    // all. Unexplained it is pixel-identical to a genuinely compliant estate.
    render(
      <ResultCard status="complete"
                  summary={{ files: 2, hosts: 3, findings: 0, cat1: 0, cat2: 0, cat3: 0 }}
                  warnings={[]} error={null} ai={null} aiError={null}
                  onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText(/no findings were extracted/i)).toBeInTheDocument();
    // Distinct from the zero-CAT case, which has a different cause.
    expect(screen.queryByText(/not matched to a stig benchmark/i)).not.toBeInTheDocument();
  });

  it('states the AI gate when enrichment did not run', () => {
    render(
      <ResultCard status="complete" summary={SUMMARY} warnings={[]} error={null}
                  ai="failed" aiError="AI enrichment is not available in this build."
                  onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText(/not available in this build/i)).toBeInTheDocument();
  });

  it('states the AI gate even when the server omits it', () => {
    // `{ai && ai !== 'done' ? … : null}` rendered nothing at all for an absent
    // gate — the exact silence the spec forbids.
    render(
      <ResultCard status="complete" summary={SUMMARY} warnings={[]} error={null}
                  ai={null} aiError={null} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText(/ai enrichment/i)).toBeInTheDocument();
  });

  it('says AI ran when it ran', () => {
    render(
      <ResultCard status="complete" summary={SUMMARY} warnings={[]} error={null}
                  ai="done" aiError={null} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByText(/ai enrichment ran/i)).toBeInTheDocument();
  });

  it('never leaks the raw gate enum onto the accreditation artifact', () => {
    render(
      <ResultCard status="complete" summary={SUMMARY} warnings={[]} error={null}
                  ai="disabled-by-request" aiError={null}
                  onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.queryByText(/disabled-by-request/)).not.toBeInTheDocument();
    expect(screen.getByText(/switched off for this job/i)).toBeInTheDocument();
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

describe('ResultCard (CAT I highlight)', () => {
  function catOneDd(cat1: number): HTMLElement {
    const { container } = render(
      <ResultCard status="complete" summary={{ ...SUMMARY, cat1 }} warnings={[]} error={null}
                  ai={null} aiError={null} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    const rows = [...container.querySelectorAll('.summary-row')];
    const row = rows.find((r) => /CAT I —/.test(r.querySelector('dt')?.textContent ?? ''));
    return row!.querySelector('dd') as HTMLElement;
  }

  it('marks the CAT I count when high-severity findings are open', () => {
    expect(catOneDd(3)).toHaveClass('summary-cat1-open');
  });

  it('does not mark the CAT I count when it is zero', () => {
    expect(catOneDd(0)).not.toHaveClass('summary-cat1-open');
  });

  it('the stylesheet rule for the highlight actually selects that element', () => {
    // The class was on the <dd>; the CSS selected a <dd> *inside* it
    // (`.summary-cat1-open dd`), so it matched nothing. Open CAT I findings — the
    // one bit of colour that says "this system has high findings" — rendered in
    // the same neutral ink as a zero.
    const dd = catOneDd(3);
    expect(CAT1_SELECTORS.length).toBeGreaterThan(0);
    expect(CAT1_SELECTORS.some((sel) => dd.matches(sel))).toBe(true);
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

  it('still gives a reason when the server supplied none', () => {
    // `<p>{error}</p>` with a null error rendered "Processing Failed" over an
    // empty paragraph: a failure with no stated cause.
    render(
      <ResultCard status="error" summary={null} warnings={[]} error={null}
                  ai={null} aiError={null} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(/did not report a reason/i);
  });

  it('offers a reconnect when contact with a running job was lost', () => {
    // The message says the job may still be running, so the operator must have a
    // way back to it.
    render(
      <ResultCard status="error" summary={null} warnings={[]}
                  error="Lost contact with the server." ai={null} aiError={null}
                  onReconnect={vi.fn()} onDownload={vi.fn()} onReset={vi.fn()} />,
    );
    expect(screen.getByRole('button', { name: /reconnect/i })).toBeInTheDocument();
  });
});
