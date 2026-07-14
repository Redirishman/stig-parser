import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import WarningsBox from './WarningsBox';

describe('WarningsBox', () => {
  it('mounts its live region empty, so the first warning is actually announced', () => {
    // An aria-live region inserted into the DOM already populated is unreliably
    // announced — the region has to pre-exist for the mutation to be spoken. The
    // component returned null when empty and carried aria-live on the populated
    // element, so the FIRST warning — the one the operator is told to verify
    // before the report goes into an accreditation package — was the one most
    // likely never announced.
    const { container, rerender } = render(<WarningsBox warnings={[]} title="Warnings" />);

    const live = container.querySelector('[aria-live]');
    expect(live).not.toBeNull();
    expect(live).toBeEmptyDOMElement();

    rerender(<WarningsBox warnings={['Benchmark unmatched']} title="Warnings" />);

    // Same node, now populated: a mutation inside a region that was already there.
    expect(container.querySelector('[aria-live]')).toBe(live);
    expect(live).toHaveTextContent('Benchmark unmatched');
  });

  it('shows no warning furniture when there are no warnings', () => {
    render(<WarningsBox warnings={[]} title="Warnings" />);
    expect(screen.queryByRole('heading', { name: /warnings/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('listitem')).not.toBeInTheDocument();
  });

  it('lists warnings and tells the operator to verify them', () => {
    render(<WarningsBox warnings={['Benchmark unmatched']} title="Warnings" />);
    expect(screen.getByRole('listitem')).toHaveTextContent('Benchmark unmatched');
    expect(screen.getByText(/accreditation package/i)).toBeInTheDocument();
  });
});
