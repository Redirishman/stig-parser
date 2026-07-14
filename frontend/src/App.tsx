import { useEffect, useState } from 'react';
import * as api from './api';
import ActivityLog from './components/ActivityLog';
import AiToggle from './components/AiToggle';
import ResultCard from './components/ResultCard';
import UploadZone from './components/UploadZone';
import WarningsBox from './components/WarningsBox';
import { ApiError, type Config } from './types';
import { useJob } from './useJob';

export default function App() {
  const [config, setConfig] = useState<Config | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [results, setResults] = useState<File[]>([]);
  const [benchmarks, setBenchmarks] = useState<File[]>([]);
  const [ai, setAi] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const { state, submit, cancel, reset, canCancel } = useJob();

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

  // An unhandled rejection here used to mean the operator clicked Download and
  // nothing happened at all — on a card that still said "Report Ready". Every
  // outcome now says something true, in the UI, not the console.
  async function onDownload() {
    if (!state.jobId) return;
    setDownloadError(null);
    try {
      const { url } = await api.getResultUrl(state.jobId);
      window.location.href = url;
    } catch (err) {
      // 409: the object is not on S3 yet. Not an error — the operator is early,
      // and the job is still finishing. Saying nothing is the correct behaviour.
      if (err instanceof ApiError && err.status === 409) return;
      // 410: the retention window closed and the report was deleted. This is not
      // a transient "download failed" — retrying will never work, and the
      // operator needs to know to re-run the scan, not to click again.
      if (err instanceof ApiError && err.status === 410) {
        setDownloadError(
          'This report has expired. Reports are deleted after the retention ' +
            'window closes. Process the scan files again to generate a new one.',
        );
        return;
      }
      setDownloadError(
        err instanceof Error ? err.message : 'Could not download the report.',
      );
    }
  }

  function onReset() {
    setResults([]);
    setBenchmarks([]);
    setDownloadError(null);
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
  // 'cancelled' belongs here, not nowhere. Left out of both sets it fell through
  // to the upload form: no message, no log, no explanation — the operator could
  // not tell whether their job had been cancelled, had completed, or had failed.
  const finished = state.status === 'complete' || state.status === 'error' ||
                   state.status === 'cancelled';

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
              {/* Disabled until the job id lands: the upload round-trip renders
                  this button before there is anything to cancel, and a live
                  button that silently does nothing is worse than a dead one the
                  operator can see is not ready yet. */}
              <button
                type="button"
                className="btn btn-secondary"
                disabled={!canCancel}
                onClick={() => void cancel()}
              >
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
              downloadError={downloadError}
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
