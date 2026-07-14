import type { RefObject } from 'react';
import { explainAiGate } from '../aiGate';
import type { AiGate, Summary } from '../types';
// The one source of truth for what the UI can be showing. A local
// `JobStatus | 'idle' | 'uploading'` copy of it would drift.
import type { UiStatus } from '../useJob';
import WarningsBox from './WarningsBox';

interface Props {
  /**
   * The card's heading, so App can move focus to it when this card replaces the
   * processing screen. Without it the operator's focus falls to <body> on every
   * transition (WCAG 2.4.3) — silently, at the top of the document.
   */
  headingRef?: RefObject<HTMLHeadingElement>;
  status: UiStatus;
  summary: Summary | null;
  warnings: string[];
  error: string | null;
  ai: AiGate | null;
  aiError: string | null;
  /** Why the last Download click did not produce a file. */
  downloadError?: string | null;
  /** Present only when the job id survived a lost connection: offer it back. */
  onReconnect?: () => void;
  onDownload: () => void;
  onReset: () => void;
}

export default function ResultCard({
  headingRef, status, summary, warnings, error, ai, aiError, downloadError, onReconnect,
  onDownload, onReset,
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
        <h2 tabIndex={-1} ref={headingRef}>Processing Failed</h2>
        {/* A null error used to render an empty paragraph: "Processing Failed",
            no reason, nothing to act on. */}
        <p>
          {error ??
            'The server did not report a reason. Check the activity log, then try again.'}
        </p>
        <WarningsBox warnings={warnings} title="Warnings recorded before the failure" />
        {/* Contact was lost but the job id was kept — the operator can go back to
            the job rather than re-uploading and re-running it. */}
        {onReconnect ? (
          <button type="button" className="btn btn-primary" onClick={onReconnect}>
            Reconnect
          </button>
        ) : null}
        <button type="button" className="btn btn-secondary" onClick={onReset}>
          Try Again
        </button>
      </div>
    );
  }

  if (status === 'cancelled') {
    return (
      <div className="result-card cancelled" role="status">
        <div className="result-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor"
               strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="9" />
            <path d="M8 12h8" />
          </svg>
        </div>
        <h2 tabIndex={-1} ref={headingRef}>Job Cancelled</h2>
        <p>
          This job was stopped before it finished. No report was generated — the
          scan files were not fully processed.
        </p>
        <WarningsBox warnings={warnings} title="Warnings recorded before the cancel" />
        <button type="button" className="btn btn-secondary" onClick={onReset}>
          Start Over
        </button>
      </div>
    );
  }

  // Every remaining non-terminal status is a caller error, not a result. Rendering
  // the success card for one would announce "Report Ready" for a report that was
  // never written — the exact lie this card must never tell.
  if (status !== 'complete') return null;

  // Nothing came out of the scan at all — the most alarming outcome the parser can
  // report, and the one that looks exactly like a perfectly compliant estate. A
  // clean system and a failed parse must not be pixel-identical.
  const zeroFindings = summary !== null && summary.findings === 0;

  // Findings exist but every severity is zero: a different cause (the results were
  // never matched to a benchmark), so it gets its own words. A silent row of
  // zeroes reads like a clean system.
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
      <h2 tabIndex={-1} ref={headingRef}>Report Ready</h2>

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

      {zeroFindings ? (
        <p className="summary-note">
          No findings were extracted from these scan results. This is not
          necessarily a compliant system — an unrecognised, empty, or wrong-format
          scan file produces the same zeroes. Confirm the result-file and host
          counts above match what you uploaded, and check any warnings below,
          before treating this as a clean result.
        </p>
      ) : null}

      {zeroCats ? (
        <p className="summary-note">
          Severity counts are zero because the results were not matched to a STIG
          benchmark — see the warnings below.
        </p>
      ) : null}

      {/* The AI gate, in prose, on every report — including when the server said
          nothing about it. An absent gate was rendering as nothing at all: the
          exact silence spec §4.1 forbids. The raw enum never appears here; this
          card is the artifact that feeds accreditation paperwork. */}
      <p className="ai-status-note">
        {explainAiGate(ai)}
        {aiError && ai !== 'done' ? ` ${aiError}` : ''}
      </p>

      {/* role=alert, not a console line: a download that produced no file has to
          say so where the operator is looking. */}
      {downloadError ? (
        <p className="download-error" role="alert">{downloadError}</p>
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
