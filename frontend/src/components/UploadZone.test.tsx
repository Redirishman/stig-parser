import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import UploadZone from './UploadZone';

const LIMITS = { allowedExtensions: ['.xml', '.zip'], maxUploadBytes: 1000 };

function setup(files: File[] = [], onChange = vi.fn()) {
  render(
    <UploadZone
      id="results"
      title="Scan Results"
      description="XCCDF results"
      accept=".xml,.zip"
      limits={LIMITS}
      files={files}
      onChange={onChange}
    />,
  );
  return onChange;
}

describe('UploadZone', () => {
  it('exposes Choose Files as a real button, keyboard reachable', async () => {
    setup();
    const button = screen.getByRole('button', { name: /choose files/i });
    await userEvent.tab();
    expect(button).toHaveFocus();
  });

  it('lists selected files', () => {
    setup([new File(['x'], 'scan.xml')]);
    expect(screen.getByRole('listitem')).toHaveTextContent('scan.xml');
  });

  it('removes a file when its remove button is pressed', async () => {
    const onChange = setup([new File(['x'], 'scan.xml')]);
    await userEvent.click(screen.getByRole('button', { name: /remove scan.xml/i }));
    expect(onChange).toHaveBeenCalledWith([]);
  });

  it('rejects a disallowed file and announces why', async () => {
    const onChange = setup();
    const input = screen.getByLabelText(/scan results files/i);

    // applyAccept: false — userEvent emulates the OS picker's `accept` filter and
    // would drop payload.exe before it ever reached the component. A real drag-drop
    // performs no such filtering, so bad files DO reach us. This test exercises that
    // path: the one where rejectFile() is the only thing standing between a junk file
    // and the API.
    await userEvent.upload(input, new File(['x'], 'payload.exe'), { applyAccept: false });

    expect(onChange).not.toHaveBeenCalledWith(
      expect.arrayContaining([expect.objectContaining({ name: 'payload.exe' })]),
    );
    expect(screen.getByRole('status')).toHaveTextContent(/unsupported file type/i);
  });

  it('rejects a disallowed file dropped onto the zone', () => {
    // The native `accept` attribute cannot protect this path — drag-and-drop ignores
    // it — so rejectFile() must catch it here too.
    const onChange = setup();
    const zone = screen.getByRole('heading', { name: /scan results/i }).closest('.upload-zone');
    const bad = new File(['x'], 'payload.exe');

    fireEvent.drop(zone!, { dataTransfer: { files: [bad], types: ['Files'] } });

    expect(onChange).not.toHaveBeenCalledWith(
      expect.arrayContaining([expect.objectContaining({ name: 'payload.exe' })]),
    );
    expect(screen.getByRole('status')).toHaveTextContent(/unsupported file type/i);
  });

  it('accepts an allowed file', async () => {
    const onChange = setup();
    const input = screen.getByLabelText(/scan results files/i);

    await userEvent.upload(input, new File(['x'], 'scan.xml'));

    expect(onChange).toHaveBeenCalled();
    expect(onChange.mock.calls[0][0][0].name).toBe('scan.xml');
  });
});
