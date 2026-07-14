import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import UploadProgress from './UploadProgress';

describe('UploadProgress', () => {
  it('renders nothing when no upload is in flight', () => {
    const { container } = render(<UploadProgress progress={{}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows a labelled progress bar per file', () => {
    // api.ts pays the cost of XMLHttpRequest purely to obtain these numbers —
    // "a 200 MB scan over a VPN with no progress bar looks like a hang". They
    // are worth nothing unless the operator can actually see them.
    render(<UploadProgress progress={{ 'scan.xml': 42, 'bench.zip': 0 }} />);

    const scan = screen.getByRole('progressbar', { name: /scan\.xml/i });
    expect(scan).toHaveAttribute('aria-valuenow', '42');
    expect(screen.getByRole('progressbar', { name: /bench\.zip/i })).toHaveAttribute(
      'aria-valuenow',
      '0',
    );
    expect(screen.getByText('42%')).toBeInTheDocument();
  });
});
