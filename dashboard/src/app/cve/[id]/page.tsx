"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  ShieldAlert,
  GitBranch,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Tag,
  Cpu,
  AlertTriangle,
  Link as LinkIcon,
} from "lucide-react";
import { getCVE } from "@/lib/api";
import type { ProcessedCVE } from "@/types/cve";
import {
  cn,
  priorityColor,
  cvssColor,
  epssPercent,
  formatDate,
} from "@/lib/utils";
import AttackChainDiagram from "./AttackChainDiagram";
import Footer from "@/components/layout/Footer";

/* ── Accordion section ─────────────────────────── */

function AccordionSection({
  icon,
  title,
  content,
  defaultOpen = false,
}: {
  icon: React.ReactNode;
  title: string;
  content: string;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);

  if (!content) return null;

  return (
    <div className="card overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-4 py-3 text-left transition-colors hover:bg-l-panel dark:hover:bg-panel"
      >
        <div className="flex items-center gap-2 font-display font-semibold text-sm text-l-text dark:text-gray-200">
          {icon}
          {title}
        </div>
        {open ? (
          <ChevronUp className="h-4 w-4 text-l-sub dark:text-gray-500" />
        ) : (
          <ChevronDown className="h-4 w-4 text-l-sub dark:text-gray-500" />
        )}
      </button>
      {open && (
        <div className="px-4 pb-4 text-sm text-l-sub dark:text-gray-400 leading-relaxed whitespace-pre-wrap animate-fade-in">
          {content}
        </div>
      )}
    </div>
  );
}

/* ── Skeleton ──────────────────────────────────── */

function DetailSkeleton() {
  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 py-8 animate-fade-in">
      <div className="skeleton h-5 w-24 mb-6" />
      <div className="skeleton h-10 w-72 mb-4" />
      <div className="skeleton h-4 w-48 mb-6" />
      <div className="skeleton h-3 w-full mb-4" />
      <div className="skeleton h-32 w-full mb-4" />
      <div className="skeleton h-32 w-full mb-4" />
      <div className="skeleton h-32 w-full" />
    </div>
  );
}

/* ── Main page ─────────────────────────────────── */

export default function CVEDetailPage() {
  const params = useParams();
  const router = useRouter();
  const cveId = params.id as string;

  const [cve, setCve] = useState<ProcessedCVE | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!cveId) return;
    setLoading(true);
    getCVE(cveId)
      .then((data) => {
        setCve(data);
        setError(null);
      })
      .catch((e) => setError(e.message || "CVE not found"))
      .finally(() => setLoading(false));
  }, [cveId]);

  if (loading) return <DetailSkeleton />;

  if (error || !cve) {
    return (
      <div className="mx-auto max-w-4xl px-4 sm:px-6 py-16 text-center">
        <AlertTriangle className="h-12 w-12 mx-auto text-amber mb-4" />
        <h2 className="font-display font-bold text-xl text-l-text dark:text-gray-200 mb-2">
          CVE Not Found
        </h2>
        <p className="text-sm text-l-sub dark:text-gray-500 font-mono mb-6">
          {error || `${cveId} is not in the cache. Only recently polled CVEs are available.`}
        </p>
        <button onClick={() => router.push("/")} className="btn-primary text-xs">
          ← Back to feed
        </button>
      </div>
    );
  }

  const colors = priorityColor(cve.priority_label);
  const ai = cve.ai_explanation;

  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 py-8 animate-fade-in">
      {/* Back */}
      <button
        onClick={() => router.push("/")}
        className="btn-ghost flex items-center gap-1.5 text-sm mb-6 -ml-3"
      >
        <ArrowLeft className="h-4 w-4" /> Back to feed
      </button>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 mb-4">
        <h1 className="font-mono font-bold text-2xl sm:text-3xl text-acid">
          {cve.cve_id}
        </h1>
        <div className="flex items-center gap-2 flex-wrap">
          <span
            className={cn(
              "badge text-sm py-1 px-3",
              colors.bg,
              colors.border,
              colors.text
            )}
          >
            {cve.priority_score}/100 {cve.priority_label}
          </span>
          <span
            className={cn(
              "badge text-sm py-1 px-3 bg-l-panel dark:bg-panel border-l-border dark:border-border",
              cvssColor(cve.cvss_score)
            )}
          >
            CVSS {cve.cvss_score.toFixed(1)}
          </span>
          <span className="text-xs font-mono text-l-sub dark:text-gray-500">
            {formatDate(cve.published_date)}
          </span>
        </div>
      </div>

      {/* Flags row */}
      <div className="flex flex-wrap items-center gap-2 mb-4">
        {cve.enrichment.in_kev && (
          <span className="badge bg-red-500/15 border-red-500/30 text-red-400">
            <ShieldAlert className="h-3.5 w-3.5" /> CISA KEV — Actively
            Exploited
          </span>
        )}
        {cve.enrichment.has_poc && (
          <span className="badge bg-amber-500/15 border-amber-500/30 text-amber-400">
            <GitBranch className="h-3.5 w-3.5" /> {cve.enrichment.poc_urls.length} Public PoC
          </span>
        )}
        {cve.enrichment.epss_score > 0 && (
          <span className="badge bg-l-panel dark:bg-panel border-l-border dark:border-border text-l-sub dark:text-gray-400">
            EPSS {epssPercent(cve.enrichment.epss_score)} (top{" "}
            {((1 - cve.enrichment.epss_percentile) * 100).toFixed(1)}%)
          </span>
        )}
      </div>

      {/* Priority bar */}
      <div className="mb-6">
        <div className="h-2 w-full rounded-full bg-l-panel dark:bg-panel overflow-hidden">
          <div
            className={cn(
              "h-full rounded-full transition-all duration-1000",
              colors.bar
            )}
            style={{ width: `${cve.priority_score}%` }}
          />
        </div>
        <div className="flex justify-between mt-1 text-[10px] font-mono text-l-sub dark:text-gray-500">
          <span>0</span>
          <span>{cve.priority_score}/100</span>
          <span>100</span>
        </div>
      </div>

      {/* Description */}
      <div className="card p-4 mb-4">
        <p className="text-sm text-l-sub dark:text-gray-400 leading-relaxed">
          {cve.description}
        </p>
      </div>

      {/* AI Explanation */}
      {ai && (
        <div className="space-y-3 mb-6">
          <h3 className="font-display font-semibold text-sm text-l-sub dark:text-gray-500 uppercase tracking-wider">
            AI Analysis
          </h3>
          <AccordionSection
            icon={<span>📝</span>}
            title="Summary"
            content={ai.summary}
            defaultOpen
          />
          <AccordionSection
            icon={<span>🔬</span>}
            title="Technical Detail"
            content={ai.technical_detail}
          />
          <AccordionSection
            icon={<span>💥</span>}
            title="Impact"
            content={ai.impact}
          />
          <AccordionSection
            icon={<span>🛡</span>}
            title="Remediation"
            content={ai.remediation}
          />
        </div>
      )}

      {/* Attack chain diagram */}
      {ai && (
        <div className="mb-6">
          <h3 className="font-display font-semibold text-sm text-l-sub dark:text-gray-500 uppercase tracking-wider mb-3">
            Attack Chain
          </h3>
          <AttackChainDiagram
            tags={ai.tags}
            technicalDetail={ai.technical_detail}
            weaknesses={cve.weaknesses}
          />
        </div>
      )}

      {/* Tags + Affected Tech */}
      <div className="flex flex-col sm:flex-row gap-4 mb-6">
        {ai && ai.tags.length > 0 && (
          <div className="flex-1">
            <div className="flex items-center gap-1.5 mb-2">
              <Tag className="h-3.5 w-3.5 text-l-sub dark:text-gray-500" />
              <span className="text-[10px] font-mono uppercase tracking-wider text-l-sub dark:text-gray-500">
                Tags
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {ai.tags.map((tag) => (
                <span
                  key={tag}
                  className="text-xs font-mono px-2 py-1 rounded-md bg-acid/10 text-acid border border-acid/20"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
        {ai && ai.affected_tech.length > 0 && (
          <div className="flex-1">
            <div className="flex items-center gap-1.5 mb-2">
              <Cpu className="h-3.5 w-3.5 text-l-sub dark:text-gray-500" />
              <span className="text-[10px] font-mono uppercase tracking-wider text-l-sub dark:text-gray-500">
                Affected Tech
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {ai.affected_tech.map((tech) => (
                <span
                  key={tech}
                  className="text-xs font-mono px-2 py-1 rounded-md bg-amber/10 text-amber border border-amber/20"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Weaknesses */}
      {cve.weaknesses.length > 0 && (
        <div className="card p-4 mb-4">
          <h3 className="text-[10px] font-mono uppercase tracking-wider text-l-sub dark:text-gray-500 mb-2">
            CWE Weaknesses
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {cve.weaknesses.map((w) => (
              <a
                key={w}
                href={`https://cwe.mitre.org/data/definitions/${w.replace("CWE-", "")}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono px-2 py-1 rounded-md bg-l-panel dark:bg-panel text-info border border-l-border dark:border-border hover:border-info/50 transition-colors"
              >
                {w} ↗
              </a>
            ))}
          </div>
        </div>
      )}

      {/* PoC URLs */}
      {cve.enrichment.poc_urls.length > 0 && (
        <div className="card p-4 mb-4">
          <h3 className="text-[10px] font-mono uppercase tracking-wider text-l-sub dark:text-gray-500 mb-2">
            Proof of Concept
          </h3>
          <div className="space-y-1.5">
            {cve.enrichment.poc_urls.map((url) => (
              <a
                key={url}
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-xs font-mono text-acid hover:text-acid-dim transition-colors truncate"
              >
                <GitBranch className="h-3 w-3 shrink-0" />
                {url}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* References */}
      {cve.references.length > 0 && (
        <div className="card p-4 mb-4">
          <div className="flex items-center gap-1.5 mb-2">
            <LinkIcon className="h-3.5 w-3.5 text-l-sub dark:text-gray-500" />
            <span className="text-[10px] font-mono uppercase tracking-wider text-l-sub dark:text-gray-500">
              References
            </span>
          </div>
          <div className="space-y-1.5">
            {cve.references.map((ref) => (
              <a
                key={ref}
                href={ref}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-xs text-info hover:text-acid transition-colors truncate"
              >
                <ExternalLink className="h-3 w-3 shrink-0" />
                {ref}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* NVD link */}
      <a
        href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
        target="_blank"
        rel="noopener noreferrer"
        className="btn-primary inline-flex items-center gap-2 text-xs"
      >
        View on NVD <ExternalLink className="h-3.5 w-3.5" />
      </a>

      <div className="mt-12" />
      <Footer />
    </div>
  );
}
