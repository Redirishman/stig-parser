import type { LogLine } from '../useJob';

/**
 * Timestamped monospace log. role="log" + aria-live="polite" so a screen reader
 * announces new steps without interrupting whatever the operator is doing.
 */
export default function ActivityLog({ lines }: { lines: LogLine[] }) {
  return (
    <div className="activity-log" role="log" aria-live="polite">
      {lines.map((l, i) => (
        <div key={i} className="log-entry">
          <span className="log-time">{l.time}</span> {l.message}
        </div>
      ))}
    </div>
  );
}
