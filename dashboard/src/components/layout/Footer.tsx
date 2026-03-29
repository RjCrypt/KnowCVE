export default function Footer() {
  return (
    <footer className="mt-auto border-t border-l-border dark:border-border">
      <div className="mx-auto flex max-w-7xl flex-col sm:flex-row items-center justify-between gap-2 px-4 py-4 sm:px-6">
        <p className="text-xs text-l-sub dark:text-gray-500 font-mono">
          Know<span className="text-acid">CVE</span> — open source
          vulnerability intelligence
        </p>
        <p className="text-xs text-l-sub dark:text-gray-500">
          Data:{" "}
          <a
            href="https://nvd.nist.gov"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-acid transition-colors"
          >
            NVD
          </a>{" "}
          ·{" "}
          <a
            href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-acid transition-colors"
          >
            CISA KEV
          </a>{" "}
          ·{" "}
          <a
            href="https://www.first.org/epss"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-acid transition-colors"
          >
            EPSS
          </a>{" "}
          ·{" "}
          <a
            href="https://github.com/advisories"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-acid transition-colors"
          >
            GitHub Advisory
          </a>
        </p>
      </div>
    </footer>
  );
}
