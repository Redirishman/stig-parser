/**
 * Client-side upload check — a COURTESY, not a control.
 *
 * The extension list and size cap come from GET /config, which serves the values
 * in app/core/uploads.py. Hardcoding them here would fork the allow-list that
 * module exists to keep single. The API re-validates every filename regardless:
 * a client check is bypassable by definition and is never the security boundary.
 */
export interface UploadLimits {
  allowedExtensions: string[];
  maxUploadBytes: number;
}

function extensionOf(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot === -1 ? '' : name.slice(dot).toLowerCase();
}

function humanMb(bytes: number): number {
  return Math.round(bytes / (1024 * 1024));
}

/** Returns an operator-facing rejection message, or null if the file is fine. */
export function rejectFile(file: File, limits: UploadLimits): string | null {
  if (!limits.allowedExtensions.includes(extensionOf(file.name))) {
    return `Unsupported file type: ${file.name} (allowed: ${limits.allowedExtensions.join(', ')})`;
  }
  if (file.size > limits.maxUploadBytes) {
    return `File too large: ${file.name} (max ${humanMb(limits.maxUploadBytes)} MB each)`;
  }
  return null;
}
