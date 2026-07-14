import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import WarningsBox from './WarningsBox';

describe('WarningsBox', () => {
  it('renders nothing when there are no warnings', () => {
    const { container } = render(<WarningsBox warnings={[]} title="Warnings" />);
    expect(container).toBeEmptyDOMElement();
  });

  it('lists warnings and tells the operator to verify them', () => {
    render(<WarningsBox warnings={['Benchmark unmatched']} title="Warnings" />);
    expect(screen.getByRole('listitem')).toHaveTextContent('Benchmark unmatched');
    expect(screen.getByText(/accreditation package/i)).toBeInTheDocument();
  });
});
