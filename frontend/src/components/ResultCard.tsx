import type { AiGate, JobStatus, Summary } from '../types';
import WarningsBox from './WarningsBox';

interface Props {
  status: JobStatus | 'idle' | 'uploading';
  summary: Summary | null;
  warnings: string[];
  error: string | null;
  ai: AiGate | null;
  aiError: string | null;
  /** Why the last Download click did not produce a file. */
  downloadError?: string | null;
  onDownload: () => void;
  onReset: () => void;
}

export default function ResultCard({
  status, summary, warnings, error, ai, aiError, downloadError, onDownload, onReset,
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
