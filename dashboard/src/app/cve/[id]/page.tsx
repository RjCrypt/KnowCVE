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
  Terminal,
  Crosshair,
  Skull,
  Microscope,
  Swords,
} from "lucide-react";
import Link from "next/link";
import { getCVE, getWatchlist } from "@/lib/api";
import type { ProcessedCVE } from "@/types/cve";
import {
  cn,
  priorityColor,
  cvssColor,
  epssPercent,
  formatDate,
} from "@/lib/utils";
import { useAuth } from "@/lib/auth-context";
import AuthGate from "@/components/AuthGate";
import BookmarkButton from "@/components/BookmarkButton";
import OffensiveResearchToggle from "@/components/OffensiveResearchToggle";
import AttackChainDiagram from "./AttackChainDiagram";
import CVEAssistantPanel from "./CVEAssistantPanel";
import SeenInWildSection from "@/components/SeenInWildSection";
import ResearcherNotesSection from "@/components/ResearcherNotesSection";
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

/* ── Helper: extract first N sentences ─────────── */

function firstSentences(text: string, count: number): string {
  const sentences = text.match(/[^.!?]+[.!?]+/g);
  if (!sentences) return text;
  return sentences.slice(0, count).join(" ").trim();
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
  const { user } = useAuth();
  const cveId = params.id as string;

  const [cve, setCve] = useState<ProcessedCVE | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"beginner" | "advanced">("beginner");
  const [offensiveMode, setOffensiveMode] = useState(false);
  const [watchlistMatch, setWatchlistMatch] = useState<string | null>(null);

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

  // Watchlist context check
  useEffect(() => {
    if (!user || !cve) return;
    const affectedTech = cve.ai_explanation?.affected_tech || [];
    if (affectedTech.length === 0) return;
    getWatchlist(user.id)
      .then((wl) => {
        const affectedLower = affectedTech.map((t) => t.toLowerCase()).join(" ");
        for (const item of wl) {
          const name = item.display_name.toLowerCase();
          const cpe = item.cpe_string.toLowerCase();
          if (affectedLower.includes(name) || affectedLower.includes(cpe)) {
            setWatchlistMatch(item.display_name);
            return;
          }
        }
        setWatchlistMatch(null);
      })
      .catch(() => {});
  }, [user, cve]);

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

      {/* Header with BookmarkButton */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 mb-4">
        <div className="flex items-center gap-2">
          <h1 className="font-mono font-bold text-2xl sm:text-3xl text-acid">
            {cve.cve_id}
          </h1>
          <BookmarkButton cveId={cve.cve_id} />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span
            className={cn(
              "badge text-sm py-1 px-3",
              colors.bg,
              colors.border,
              colors.text
            )}
          >
            KRS {cve.priority_score}/100 · {cve.priority_label}
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
        {/* Nuclei badge */}
        {cve.enrichment.has_nuclei_template && (
          <a
            href={cve.enrichment.nuclei_template_url || "#"}
            target="_blank"
            rel="noopener noreferrer"
            className="badge bg-purple-500/15 border-purple-500/30 text-purple-400 hover:bg-purple-500/25 transition-colors"
          >
            <Terminal className="h-3.5 w-3.5" /> Nuclei Template
          </a>
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
          <span>KRS {cve.priority_score}/100</span>
          <span>100</span>
        </div>
      </div>

      {/* Description */}
      <div className="card p-4 mb-4">
        <p className="text-sm text-l-sub dark:text-gray-400 leading-relaxed">
          {cve.description}
        </p>
      </div>

      {/* Watchlist context banner */}
      {watchlistMatch && (
        <div className="p-3 mb-4 rounded-lg border border-amber-500/20 bg-amber-500/5 flex items-center gap-2 animate-fade-in">
          <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
          <p className="text-sm text-amber-400">
            This CVE affects <span className="font-medium">{watchlistMatch}</span> in your watchlist
          </p>
        </div>
      )}

      {/* Offensive Research Mode toggle */}
      <div className="flex items-center justify-between gap-4 mb-4">
        {/* Beginner/Advanced Toggle */}
        {ai && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-l-sub dark:text-gray-500">
              Explanation mode:
            </span>
            <button
              onClick={() => setMode("beginner")}
              className={cn(
                "px-3 py-1 rounded text-xs font-mono border transition-all",
                mode === "beginner"
                  ? "bg-acid/10 text-acid-dim dark:text-acid border-acid/30"
                  : "border-l-border dark:border-border text-l-sub dark:text-gray-500"
              )}
            >
              Beginner
            </button>
            <button
              onClick={() => setMode("advanced")}
              className={cn(
                "px-3 py-1 rounded text-xs font-mono border transition-all",
                mode === "advanced"
                  ? "bg-purple-500/10 text-purple-400 border-purple-500/30"
                  : "border-l-border dark:border-border text-l-sub dark:text-gray-500"
              )}
            >
              Advanced
            </button>
          </div>
        )}

        <OffensiveResearchToggle onToggle={setOffensiveMode} />
      </div>

      {/* AI Explanation — first 2 sentences ungated, rest gated */}
      {ai && (
        <div className="space-y-3 mb-6">
          <h3 className="font-display font-semibold text-sm text-l-sub dark:text-gray-500 uppercase tracking-wider">
            AI Analysis
          </h3>

          {/* Beginner mode */}
          {mode === "beginner" && (
            <>
              {/* First 2 sentences — always visible */}
              <div className="card p-5 animate-fade-in">
                <p className="text-base text-l-text dark:text-gray-200 leading-relaxed">
                  {firstSentences(ai.summary, 2)}
                </p>
              </div>

              {/* Rest of beginner content — gated */}
              <AuthGate user={user} blur="light" message="Sign in to read the full AI analysis">
                <div className="card p-5">
                  <p className="text-base text-l-text dark:text-gray-200 leading-relaxed">
                    {ai.summary}
                  </p>
                  {ai.impact && (
                    <p className="mt-3 text-sm text-l-sub dark:text-gray-400 leading-relaxed">
                      <span className="font-medium text-amber-400">Impact: </span>
                      {ai.impact}
                    </p>
                  )}
                  {ai.remediation && (
                    <p className="mt-3 text-sm text-l-sub dark:text-gray-400 leading-relaxed">
                      <span className="font-medium text-acid">Fix: </span>
                      {ai.remediation}
                    </p>
                  )}
                </div>
              </AuthGate>
            </>
          )}

          {/* Advanced mode — all sections including Phase 5.5 depth fields */}
          {mode === "advanced" && (
            <>
              <AccordionSection
                icon={<span>📝</span>}
                title="Summary"
                content={ai.summary}
                defaultOpen
              />

              <AuthGate user={user} blur="heavy" message="Sign in to access advanced analysis">
                <div className="space-y-3">
                  <AccordionSection
                    icon={<span>🔬</span>}
                    title="Technical Detail"
                    content={ai.technical_detail}
                  />

                  {/* Phase 5.5: Vulnerability Class Analysis */}
                  {ai.vulnerability_class_analysis && (
                    <AccordionSection
                      icon={<Microscope className="h-4 w-4 text-purple-400" />}
                      title="Vulnerability Class Analysis"
                      content={ai.vulnerability_class_analysis}
                    />
                  )}

                  <AccordionSection
                    icon={<span>💥</span>}
                    title="Impact"
                    content={ai.impact}
                  />

                  {/* Phase 5.5: Adversarial Context / Threat Brief */}
                  {ai.adversarial_context && (
                    <div className="card overflow-hidden border-red-500/15">
                      <button
                        onClick={() => {}}
                        className="flex w-full items-center justify-between px-4 py-3 text-left"
                      >
                        <div className="flex items-center gap-2 font-display font-semibold text-sm text-red-400">
                          <Skull className="h-4 w-4" />
                          Threat Brief — Adversarial Context
                        </div>
                      </button>
                      <div className="px-4 pb-4 text-sm text-l-sub dark:text-gray-400 leading-relaxed whitespace-pre-wrap">
                        {ai.adversarial_context}
                      </div>
                    </div>
                  )}

                  {/* Phase 5.5: Exploit Narrative */}
                  {ai.exploit_narrative && (
                    <AccordionSection
                      icon={<Swords className="h-4 w-4 text-amber-400" />}
                      title="Exploit Narrative"
                      content={ai.exploit_narrative}
                    />
                  )}

                  <AccordionSection
                    icon={<span>🛡</span>}
                    title="Remediation"
                    content={ai.remediation}
                  />
                </div>
              </AuthGate>
            </>
          )}
        </div>
      )}

      {/* MITRE ATT&CK Techniques — show badge chips only when no attack_techniques (legacy data) */}
      {mode === "advanced" &&
        ai?.mitre_techniques &&
        ai.mitre_techniques.length > 0 &&
        (!ai.attack_techniques || ai.attack_techniques.length === 0) && (
          <div className="mb-6 p-4 rounded-lg border border-red-500/20 bg-red-500/5">
            <h3 className="font-mono text-sm font-medium text-l-sub dark:text-gray-400 mb-3 uppercase tracking-widest">
              MITRE ATT&CK
            </h3>
            <div className="flex flex-wrap gap-2">
              {ai.mitre_techniques.map((t) => (
                <a
                  key={t.technique_id}
                  href={t.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex flex-col px-3 py-2 rounded border border-red-500/20
                             bg-red-500/5 hover:bg-red-500/10 transition-colors"
                >
                  <span className="font-mono text-xs text-red-400 font-medium">
                    {t.technique_id}
                  </span>
                  <span className="text-xs text-l-sub dark:text-gray-400">
                    {t.technique_name}
                  </span>
                  <span className="text-[10px] text-l-sub dark:text-gray-600">
                    {t.tactic}
                  </span>
                </a>
              ))}
            </div>
          </div>
        )}

      {/* Attack chain diagram — gated */}
      {ai && (
        <AuthGate user={user} blur="heavy" message="Sign in to view the attack chain">
          <div className="mb-6">
            <h3 className="font-display font-semibold text-sm text-l-sub dark:text-gray-500 uppercase tracking-wider mb-3">
              {ai.attack_techniques && ai.attack_techniques.length > 0 ? "ATT&CK Kill Chain" : "Attack Chain"}
            </h3>
            <AttackChainDiagram
              tags={ai.tags || []}
              technicalDetail={ai.technical_detail || ""}
              weaknesses={cve.weaknesses || []}
              attackTechniques={ai.attack_techniques}
            />
          </div>
        </AuthGate>
      )}

      {/* Nuclei Template Box — gated behind offensive mode */}
      {cve.enrichment.has_nuclei_template && (
        <div className="mb-6 p-4 rounded-lg border border-purple-500/20 bg-purple-500/5">
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-sm font-medium text-purple-400 flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              Nuclei Template Available
            </span>
            {cve.enrichment.nuclei_template_url && (
              <a
                href={cve.enrichment.nuclei_template_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono text-purple-400 hover:underline"
              >
                View on GitHub →
              </a>
            )}
          </div>

          {/* Commands only shown in offensive mode */}
          {offensiveMode && user ? (
            <div className="bg-l-panel dark:bg-surface rounded p-3 font-mono text-xs text-l-text dark:text-gray-300 overflow-x-auto animate-fade-in">
              <span className="text-l-sub dark:text-gray-500">
                # Run detection against your target:
              </span>
              <br />
              <span className="text-acid-dim dark:text-acid">nuclei</span>
              {" "}-u https://TARGET
              {cve.enrichment.nuclei_template_url &&
                cve.enrichment.nuclei_template_url.includes("/blob/main/") && (
                  <>
                    {" "}-t{" "}
                    {cve.enrichment.nuclei_template_url.split("/blob/main/")[1]}
                  </>
                )}
              {" "}-v
            </div>
          ) : !offensiveMode ? (
            <p className="text-xs text-l-sub dark:text-gray-500 font-mono">
              Enable Offensive Research Mode to view ready-to-run commands
            </p>
          ) : null}
        </div>
      )}

      {/* Exploit Intelligence link */}
      <Link
        href={`/exploit-intel/${cve.cve_id}`}
        className="flex items-center justify-between p-4 rounded-lg border
                   border-purple-500/20 bg-purple-500/5 hover:bg-purple-500/10
                   transition-colors group mb-6"
      >
        <div>
          <div className="font-mono text-sm font-medium text-purple-400 flex items-center gap-2">
            <Crosshair className="w-4 h-4" />
            Exploit Intelligence
          </div>
          <div className="text-xs text-l-sub dark:text-gray-500 mt-0.5">
            Metasploit modules · ExploitDB · PoC quality signals · Ready-to-use commands
          </div>
        </div>
        <div className="text-purple-400 group-hover:translate-x-1 transition-transform">
          →
        </div>
      </Link>

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

      {/* PoC URLs — gated */}
      {cve.enrichment.poc_urls.length > 0 && (
        <AuthGate user={user} blur="heavy" message="Sign in to view proof-of-concept links">
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
        </AuthGate>
      )}

      {/* Community Intelligence */}
      <div className="mb-6">
        <h3 className="font-display font-semibold text-sm text-l-sub dark:text-gray-500 uppercase tracking-wider mb-3">
          Community Intelligence
        </h3>
        <SeenInWildSection cveId={cve.cve_id} />
        <ResearcherNotesSection cveId={cve.cve_id} />
      </div>

      {/* Phase 5.5: Interactive CVE Assistant */}
      <CVEAssistantPanel
        cveId={cve.cve_id}
        cveDescription={cve.description}
        aiExplanation={ai || null}
      />

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

