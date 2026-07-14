interface Props {
  warnings: string[];
  title: string;
}

/**
 * Shown during processing AND on the success card. The lead copy tells the
 * operator to verify these before the report goes into an accreditation
 * package, so they must not vanish the moment the job succeeds.
 *
 * The aria-live container is rendered ALWAYS, empty, and the warnings are
 * populated into it. A live region inserted into the DOM already populated is
 * unreliably announced — the region has to pre-exist for the mutation to be
 * spoken. Returning null when empty (and putting aria-live on the populated
 * element) meant the first warning to arrive — precisely the one the operator is
 * told to verify — was the one most likely never announced at all.
 */
export default function WarningsBox({ warnings, title }: Props) {
  return (
    <div className="warnings-live" aria-live="polite">
      {warnings.length > 0 ? (
        <div className="warnings-box">
          <h3>{title}</h3>
          <p className="warnings-lead">
            The report will still be generated. Items below were skipped or incomplete
            — verify them before including the report in an accreditation package.
          </p>
          <ul>
            {warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
