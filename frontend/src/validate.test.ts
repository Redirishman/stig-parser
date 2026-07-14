import { describe, expect, it } from 'vitest';
import { rejectFile } from './validate';

const CONFIG = { allowedExtensions: ['.xml', '.zip', '.cklb', '.nessus'], maxUploadBytes: 100 };

function file(name: string, size = 1): File {
  const f = new File(['x'], name);
  Object.defineProperty(f, 'size', { value: size });
  return f;
}

describe('rejectFile', () => {
  it('accepts an allowed extension', () => {
    expect(rejectFile(file('scan.xml'), CONFIG)).toBeNull();
  });

  it('is case-insensitive about the extension', () => {
    expect(rejectFile(file('SCAN.XML'), CONFIG)).toBeNull();
  });

  it('rejects a disallowed extension and names the allowed ones', () => {
    const msg = rejectFile(file('payload.exe'), CONFIG);
    expect(msg).toMatch(/unsupported file type/i);
    expect(msg).toContain('.cklb');
  });

  it('rejects a file over the size cap', () => {
    expect(rejectFile(file('big.xml', 101), CONFIG)).toMatch(/too large/i);
  });

  it('accepts a file exactly at the cap', () => {
    expect(rejectFile(file('edge.xml', 100), CONFIG)).toBeNull();
  });
});
