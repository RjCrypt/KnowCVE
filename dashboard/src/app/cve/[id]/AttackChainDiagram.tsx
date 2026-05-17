"use client";

import { useMemo } from "react";
import type { AttackTechnique } from "@/types/cve";

interface AttackChainDiagramProps {
  tags: string[];
  technicalDetail: string;
  weaknesses?: string[];
  attackTechniques?: AttackTechnique[];
}

/* ── Tactic color palette (by tactic_phase) ──── */

const TACTIC_COLORS: Record<number, { bg: string; border: string; text: string }> = {
  1:  { bg: "rgba(77,157,224,0.10)",  border: "rgba(77,157,224,0.35)",  text: "rgba(77,157,224,1)" },     // Initial Access
  2:  { bg: "rgba(168,85,247,0.10)",  border: "rgba(168,85,247,0.35)",  text: "rgba(168,85,247,1)" },     // Execution
  3:  { bg: "rgba(59,130,246,0.10)",  border: "rgba(59,130,246,0.35)",  text: "rgba(59,130,246,1)" },     // Persistence
  4:  { bg: "rgba(245,158,11,0.10)",  border: "rgba(245,158,11,0.35)",  text: "rgba(245,158,11,1)" },     // Privilege Escalation
  5:  { bg: "rgba(107,114,128,0.10)", border: "rgba(107,114,128,0.35)", text: "rgba(107,114,128,1)" },    // Defense Evasion
  6:  { bg: "rgba(239,68,68,0.10)",   border: "rgba(239,68,68,0.35)",   text: "rgba(239,68,68,1)" },      // Credential Access
  7:  { bg: "rgba(34,197,94,0.10)",   border: "rgba(34,197,94,0.35)",   text: "rgba(34,197,94,1)" },      // Discovery
  8:  { bg: "rgba(249,115,22,0.10)",  border: "rgba(249,115,22,0.35)",  text: "rgba(249,115,22,1)" },     // Lateral Movement
  9:  { bg: "rgba(139,92,246,0.10)",  border: "rgba(139,92,246,0.35)",  text: "rgba(139,92,246,1)" },     // Collection
  10: { bg: "rgba(6,182,212,0.10)",   border: "rgba(6,182,212,0.35)",   text: "rgba(6,182,212,1)" },      // Command and Control
  11: { bg: "rgba(236,72,153,0.10)",  border: "rgba(236,72,153,0.35)",  text: "rgba(236,72,153,1)" },     // Exfiltration
  12: { bg: "rgba(255,68,68,0.15)",   border: "rgba(255,68,68,0.45)",   text: "rgba(255,68,68,1)" },      // Impact
};

const DEFAULT_COLOR = { bg: "rgba(107,114,128,0.10)", border: "rgba(107,114,128,0.35)", text: "rgba(107,114,128,1)" };
const PIVOT_BORDER = "#00ff88";

/* ── ATT&CK Technique Node (new) ───────────── */

function TechniqueNode({ technique, isLast }: { technique: AttackTechnique; isLast: boolean }) {
  const colors = TACTIC_COLORS[technique.tactic_phase] || DEFAULT_COLOR;
  const isPivot = technique.is_pivot;
  const attackUrl = `https://attack.mitre.org/techniques/${technique.technique_id.replace(".", "/")}`;

  return (
    <div className="flex items-center shrink-0">
      <a
        href={attackUrl}
        target="_blank"
        rel="noopener noreferrer"
        className="group relative flex flex-col w-56 rounded-lg border p-3 transition-all duration-200 hover:scale-[1.02] hover:shadow-lg"
        style={{
          backgroundColor: colors.bg,
          borderColor: isPivot ? PIVOT_BORDER : colors.border,
          borderWidth: isPivot ? "2px" : "1px",
          boxShadow: isPivot ? `0 0 12px ${PIVOT_BORDER}40` : undefined,
        }}
      >
        {/* Tactic phase label */}
        <span
          className="text-[9px] font-mono uppercase tracking-widest mb-1 opacity-70"
          style={{ color: colors.text }}
        >
          {technique.tactic}
        </span>

        {/* Technique ID badge */}
        <div className="flex items-center gap-2 mb-1.5">
          <span
            className="font-mono text-xs font-bold px-1.5 py-0.5 rounded"
            style={{
              backgroundColor: isPivot ? `${PIVOT_BORDER}20` : `${colors.text}15`,
              color: isPivot ? PIVOT_BORDER : colors.text,
            }}
          >
            {technique.technique_id}
          </span>
          {isPivot && (
            <span className="text-[9px] font-mono font-bold uppercase tracking-wider" style={{ color: PIVOT_BORDER }}>
              PIVOT
            </span>
          )}
        </div>

        {/* Technique name */}
        <span className="text-xs font-medium text-gray-200 dark:text-gray-200 mb-1.5 leading-tight line-clamp-2 light:text-gray-700">
          {technique.technique_name}
        </span>

        {/* CVE-specific description */}
        <span className="text-[11px] leading-snug text-gray-400 dark:text-gray-400 line-clamp-3 light:text-gray-500">
          {technique.description}
        </span>

        {/* External link indicator */}
        <span className="absolute top-2 right-2 text-[10px] opacity-0 group-hover:opacity-60 transition-opacity" style={{ color: colors.text }}>
          ↗
        </span>
      </a>

      {/* Arrow connector */}
      {!isLast && (
        <div className="flex items-center mx-1 shrink-0">
          <div className="w-6 h-px bg-gray-600 dark:bg-gray-600" />
          <div
            className="w-0 h-0 shrink-0"
            style={{
              borderTop: "4px solid transparent",
              borderBottom: "4px solid transparent",
              borderLeft: "6px solid rgba(107,114,128,0.5)",
            }}
          />
        </div>
      )}
    </div>
  );
}

/* ── Legacy SVG fallback (old data without attack_techniques) ── */

function deriveVector(tags: string[]): string {
  const lower = tags.map((t) => t.toLowerCase());
  if (lower.some((t) => t.includes("network") || t.includes("remote"))) return "Network Access";
  if (lower.some((t) => t.includes("web") || t.includes("http"))) return "Web Request";
  if (lower.some((t) => t.includes("local") || t.includes("physical"))) return "Local Access";
  if (lower.some((t) => t.includes("auth"))) return "Auth Bypass";
  return "Attack Vector";
}

function deriveExploit(tags: string[], weaknesses: string[]): string {
  const lower = tags.map((t) => t.toLowerCase());
  if (lower.some((t) => t.includes("rce") || t.includes("code execution"))) return "Code Execution";
  if (lower.some((t) => t.includes("injection") || t.includes("sqli"))) return "Injection";
  if (lower.some((t) => t.includes("overflow") || t.includes("buffer"))) return "Buffer Overflow";
  if (lower.some((t) => t.includes("xss") || t.includes("cross-site"))) return "XSS";
  if (lower.some((t) => t.includes("deserialization"))) return "Deserialization";
  if (weaknesses.length > 0) return weaknesses[0];
  return "Exploitation";
}

function deriveImpact(tags: string[]): string {
  const lower = tags.map((t) => t.toLowerCase());
  if (lower.some((t) => t.includes("rce"))) return "RCE";
  if (lower.some((t) => t.includes("data") || t.includes("leak") || t.includes("disclosure"))) return "Data Breach";
  if (lower.some((t) => t.includes("dos") || t.includes("denial"))) return "DoS";
  if (lower.some((t) => t.includes("privilege") || t.includes("escalation"))) return "Priv Escalation";
  return "Impact";
}

interface BoxConfig {
  label: string;
  colors: { bg: string; border: string; text: string };
}

function LegacySVGDiagram({ tags, weaknesses = [] }: { tags: string[]; weaknesses: string[] }) {
  const boxes = useMemo<BoxConfig[]>(() => {
    return [
      {
        label: "Attacker",
        colors: { bg: "rgba(48,54,61,0.6)", border: "rgba(139,148,158,0.4)", text: "rgba(139,148,158,1)" },
      },
      {
        label: deriveVector(tags),
        colors: { bg: "rgba(77,157,224,0.12)", border: "rgba(77,157,224,0.4)", text: "rgba(77,157,224,1)" },
      },
      {
        label: "Vulnerable\nComponent",
        colors: { bg: "rgba(240,165,0,0.12)", border: "rgba(240,165,0,0.4)", text: "rgba(240,165,0,1)" },
      },
      {
        label: deriveExploit(tags, weaknesses),
        colors: { bg: "rgba(255,68,68,0.12)", border: "rgba(255,68,68,0.35)", text: "rgba(255,100,100,1)" },
      },
      {
        label: deriveImpact(tags),
        colors: { bg: "rgba(255,68,68,0.18)", border: "rgba(255,68,68,0.5)", text: "rgba(255,68,68,1)" },
      },
    ];
  }, [tags, weaknesses]);

  const boxW = 120;
  const boxH = 48;
  const gap = 40;
  const padX = 20;
  const padY = 16;
  const totalW = padX * 2 + boxes.length * boxW + (boxes.length - 1) * gap;
  const totalH = padY * 2 + boxH;

  return (
    <div className="card p-4 overflow-x-auto">
      <svg
        viewBox={`0 0 ${totalW} ${totalH}`}
        className="w-full min-w-[600px]"
        preserveAspectRatio="xMidYMid meet"
      >
        {boxes.map((box, i) => {
          const x = padX + i * (boxW + gap);
          const y = padY;
          const cx = x + boxW / 2;
          const cy = y + boxH / 2;

          return (
            <g key={i}>
              <rect
                x={x} y={y} width={boxW} height={boxH} rx={8} ry={8}
                fill={box.colors.bg} stroke={box.colors.border} strokeWidth={1.5}
              />
              {box.label.includes("\n") ? (
                box.label.split("\n").map((line, li) => (
                  <text
                    key={li} x={cx} y={cy + (li - 0.5) * 14}
                    textAnchor="middle" dominantBaseline="middle"
                    fill={box.colors.text} fontSize={11}
                    fontFamily="var(--font-mono), monospace" fontWeight={500}
                  >
                    {line}
                  </text>
                ))
              ) : (
                <text
                  x={cx} y={cy} textAnchor="middle" dominantBaseline="middle"
                  fill={box.colors.text} fontSize={11}
                  fontFamily="var(--font-mono), monospace" fontWeight={500}
                >
                  {box.label}
                </text>
              )}
              {i < boxes.length - 1 && (
                <>
                  <line
                    x1={x + boxW + 4} y1={cy} x2={x + boxW + gap - 8} y2={cy}
                    stroke="rgba(139,148,158,0.35)" strokeWidth={1.5}
                  />
                  <polygon
                    points={`${x + boxW + gap - 8},${cy - 4} ${x + boxW + gap - 2},${cy} ${x + boxW + gap - 8},${cy + 4}`}
                    fill="rgba(139,148,158,0.5)"
                  />
                </>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* ── Main component (ATT&CK nodes or legacy fallback) ── */

export default function AttackChainDiagram({
  tags,
  technicalDetail,
  weaknesses = [],
  attackTechniques,
}: AttackChainDiagramProps) {
  // Sort techniques by tactic_phase for left-to-right rendering
  const sortedTechniques = useMemo(() => {
    if (!attackTechniques || attackTechniques.length === 0) return null;
    return [...attackTechniques].sort((a, b) => a.tactic_phase - b.tactic_phase);
  }, [attackTechniques]);

  // New ATT&CK technique-node kill chain
  if (sortedTechniques && sortedTechniques.length > 0) {
    return (
      <div className="card p-4 overflow-x-auto">
        <div className="flex items-center gap-0 min-w-max pb-2">
          {sortedTechniques.map((tech, idx) => (
            <TechniqueNode
              key={tech.technique_id + idx}
              technique={tech}
              isLast={idx === sortedTechniques.length - 1}
            />
          ))}
        </div>
      </div>
    );
  }

  // Fallback: legacy SVG diagram for old cached data
  return <LegacySVGDiagram tags={tags} weaknesses={weaknesses} />;
}
