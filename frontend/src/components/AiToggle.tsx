import { explainAiGate } from '../aiGate';
import type { AiGate } from '../types';

interface Props {
  available: boolean;
  reason: AiGate | null;
  checked: boolean;
  onChange: (value: boolean) => void;
}

/**
 * Rendered disabled-with-a-reason rather than hidden when the gate is closed:
 * an operator who cannot see the control never learns the capability exists, or
 * why it is off. Spec §4.1 — AI being off is never silent.
 */
export default function AiToggle({ available, reason, checked, onChange }: Props) {
  return (
    <div className="ai-toggle">
      <label>
        <input
          type="checkbox"
          checked={available && checked}
          disabled={!available}
          onChange={(e) => onChange(e.target.checked)}
        />
        AI enrichment
      </label>
      {!available ? <p className="ai-toggle-note">{explainAiGate(reason)}</p> : null}
    </div>
  );
}
