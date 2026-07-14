import { useEffect, useState } from 'react';
import * as api from './api';
import ActivityLog from './components/ActivityLog';
import AiToggle from './components/AiToggle';
import ResultCard from './components/ResultCard';
import UploadZone from './components/UploadZone';
import WarningsBox from './components/WarningsBox';
import type { Config } from './types';
import { useJob } from './useJob';

export default function App() {
  const [config, setConfig] = useState<Config | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [results, setResults] = useState<File[]>([]);
  const [benchmarks, setBenchmarks] = useState<File[]>([]);
  const [ai, setAi] = useState(false);

  const { state, submit, cancel, reset } = useJob();

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

  async function onDownload() {
    if (!state.jobId) return;
    const { url } = await api.getResultUrl(state.jobId);
    window.location.href = url;
  }

  function onReset() {
    setResults([]);
    setBenchmarks([]);
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
  const finished = state.status === 'complete' || state.status === 'error';

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
              <button type="button" className="btn btn-secondary" onClick={() => void cancel()}>
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
