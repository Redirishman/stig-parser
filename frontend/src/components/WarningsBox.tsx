interface Props {
  warnings: string[];
  title: string;
}

/**
 * Shown during processing AND on the success card. The lead copy tells the
 * operator to verify these before the report goes into an accreditation
 * package, so they must not vanish the moment the job succeeds.
 */
export default function WarningsBox({ warnings, title }: Props) {
  if (warnings.length === 0) return null;

  return (
    <div className="warnings-box" aria-live="polite">
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
  );
}
