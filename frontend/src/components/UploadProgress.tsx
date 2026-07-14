interface Props {
  /** filename -> percent complete. */
  progress: Record<string, number>;
}

/**
 * Per-file upload progress (spec §5).
 *
 * api.uploadFile() pays for XMLHttpRequest over fetch purely to emit these
 * numbers — "a 200 MB scan over a VPN with no progress bar looks like a hang".
 * They were stored in state and rendered nowhere, so the hang was exactly what
 * the operator got.
 *
 * An explicit role=progressbar rather than <progress>: the percent has to be
 * announced (aria-valuenow/valuetext), and the operator gets the number in text
 * as well as in the bar — a bar alone is not a readable status.
 */
export default function UploadProgress({ progress }: Props) {
  const files = Object.entries(progress);
  if (files.length === 0) return null;

  return (
    <div className="upload-progress">
      <h3>Uploading</h3>
      <ul>
        {files.map(([name, percent]) => (
          <li key={name}>
            <span className="upload-progress-name">{name}</span>
            <div
              className="upload-progress-track"
              role="progressbar"
              aria-label={`Uploading ${name}`}
              aria-valuenow={percent}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuetext={`${percent}%`}
            >
              <div className="upload-progress-fill" style={{ width: `${percent}%` }} />
            </div>
            <span className="upload-progress-percent">{percent}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
