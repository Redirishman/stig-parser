import { useRef, useState, type DragEvent } from 'react';
import { rejectFile, type UploadLimits } from '../validate';

interface Props {
  id: string;
  title: string;
  description: string;
  accept: string;
  limits: UploadLimits;
  files: File[];
  onChange: (files: File[]) => void;
  disabled: boolean;
  badge?: string;
}

export default function UploadZone({
  id, title, description, accept, limits, files, onChange, disabled, badge,
}: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  /** Keep the good files, say why the rest were dropped. Never silently discard. */
  function accepted(incoming: File[]): File[] {
    const keep: File[] = [];
    const rejected: string[] = [];
    for (const f of incoming) {
      const why = rejectFile(f, limits);
      if (why) rejected.push(why);
      else keep.push(f);
    }
    setNotice(rejected.length ? rejected.join(' ') : null);
    return keep;
  }

  function add(incoming: File[]) {
    const keep = accepted(incoming);
    if (keep.length) onChange([...files, ...keep]);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    if (disabled) return;
    add(Array.from(e.dataTransfer.files));
  }

  return (
    <div
      className={`upload-zone${dragging ? ' dragover' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
    >
      <div className="zone-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="currentColor"
             strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <path d="M14 2v6h6" />
          <path d="M9 13h6M9 17h6" />
        </svg>
      </div>

      <h2>
        {title}
        {badge ? <span className="badge-optional">{badge}</span> : null}
      </h2>
      <p>{description}</p>

      {/* A real button, not a div with a click handler — it must be reachable
          and operable by keyboard. */}
      <button
        type="button"
        className="btn btn-secondary"
        onClick={() => inputRef.current?.click()}
        disabled={disabled}
      >
        Choose Files
      </button>

      <label htmlFor={`${id}-input`} className="visually-hidden">
        {title} files
      </label>
      {/* `accept` is a convenience only: it pre-filters the OS file picker so the
          operator sees the right file types. It is NOT validation — drag-and-drop
          bypasses it entirely, and a picker filter can be overridden. rejectFile()
          is the real gate on every path, and it always says why a file was dropped. */}
      <input
        id={`${id}-input`}
        ref={inputRef}
        type="file"
        multiple
        accept={accept}
        hidden
        disabled={disabled}
        onChange={(e) => {
          add(Array.from(e.target.files ?? []));
          e.target.value = ''; // let the same file be re-picked after a remove
        }}
      />

      {notice ? (
        <p className="zone-notice" role="status">{notice}</p>
      ) : null}

      <ul className="file-list">
        {files.map((f, i) => (
          <li key={`${f.name}-${i}`}>
            <span className="file-name">{f.name}</span>
            <button
              type="button"
              className="file-remove"
              aria-label={`Remove ${f.name}`}
              disabled={disabled}
              onClick={() => onChange(files.filter((_, idx) => idx !== i))}
            >
              ×
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
