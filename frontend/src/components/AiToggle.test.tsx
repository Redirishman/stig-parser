import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import AiToggle from './AiToggle';

describe('AiToggle', () => {
  it('is enabled when AI is available', () => {
    render(<AiToggle available reason={null} checked={false} onChange={vi.fn()} disabled={false} />);
    expect(screen.getByRole('checkbox', { name: /ai enrichment/i })).toBeEnabled();
  });

  it('is disabled AND says why when the gate is closed', () => {
    // Hiding the control would leave the operator unaware the capability exists
    // or why it is off — the silent gate the spec forbids.
    render(
      <AiToggle available={false} reason="disabled-globally" checked={false} onChange={vi.fn()} disabled={false} />,
    );
    expect(screen.getByRole('checkbox', { name: /ai enrichment/i })).toBeDisabled();
    expect(screen.getByText(/no model is approved for this deployment/i)).toBeInTheDocument();
  });
});
