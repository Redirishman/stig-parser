import type { AiGate } from '../types';

interface Props {
  available: boolean;
  reason: AiGate | null;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled: boolean;
}

/** Operator-facing text for each closed gate. Never just "unavailable". */
function explain(reason: AiGate | null): string {
  switch (reason) {
    case 'disabled-globally':
      return 'AI enrichment is unavailable — no model is approved for this deployment.';
    case 'disabled-by-request':
      return 'AI enrichment is switched off for this job.';
    case 'failed':
      return 'AI enrichment failed on the last run.';
    default:
      return 'AI enrichment is unavailable.';
  }
}

/**
 * Rendered disabled-with-a-reason rather than hidden when the gate is closed:
 * an operator who cannot see the control never learns the capability exists, or
 * why it is off. Spec §4.1 — AI being off is never silent.
 */
export default function AiToggle({ available, reason, checked, onChange, disabled }: Props) {
  return (
    <div className="ai-toggle">
      <label>
        <input
          type="checkbox"
          checked={available && checked}
          disabled={disabled || !available}
          onChange={(e) => onChange(e.target.checked)}
        />
        AI enrichment
      </label>
      {!available ? <p className="ai-toggle-note">{explain(reason)}</p> : null}
    </div>
  );
}
