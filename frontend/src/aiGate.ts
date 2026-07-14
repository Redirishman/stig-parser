import type { AiGate } from './types';

/**
 * Operator-facing prose for every AI gate, including the absent one.
 *
 * Shared by the pre-run control (AiToggle) and the post-run card (ResultCard) so
 * the two cannot drift into telling the operator different stories about the same
 * gate — and so neither ever prints the raw enum. `disabled-by-request` is an
 * internal identifier; it has no business on an artifact that feeds accreditation
 * paperwork.
 *
 * There is no "unavailable, no further comment" branch. A gate the server did not
 * name is still a gate the operator has to account for, so the fallback says
 * exactly that rather than shrugging.
 */
export function explainAiGate(reason: AiGate | null | undefined): string {
  switch (reason) {
    case 'done':
      return 'AI enrichment ran on this report.';
    case 'requested':
      return 'AI enrichment was requested but did not run.';
    case 'disabled-by-request':
      return 'AI enrichment was switched off for this job.';
    case 'disabled-globally':
      return 'AI enrichment is unavailable — no model is approved for this deployment.';
    case 'failed':
      return 'AI enrichment failed on the last run.';
    default:
      return 'AI enrichment is unavailable — the server did not report a reason. ' +
        'Treat the report as un-enriched.';
  }
}
