"use client";

import { useMemo } from "react";

interface AttackChainDiagramProps {
  tags: string[];
  technicalDetail: string;
  weaknesses?: string[];
}

/* ── Derive labels from tags/detail ─────────────── */

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

/* ── SVG box helper ────────────────────────────── */

interface BoxConfig {
  label: string;
  colors: { bg: string; border: string; text: string };
}

export default function AttackChainDiagram({
  tags,
  technicalDetail,
  weaknesses = [],
}: AttackChainDiagramProps) {
  const boxes = useMemo<BoxConfig[]>(() => {
    return [
      {
        label: "Attacker",
        colors: {
          bg: "rgba(48,54,61,0.6)",
          border: "rgba(139,148,158,0.4)",
          text: "rgba(139,148,158,1)",
        },
      },
      {
        label: deriveVector(tags),
        colors: {
          bg: "rgba(77,157,224,0.12)",
          border: "rgba(77,157,224,0.4)",
          text: "rgba(77,157,224,1)",
        },
      },
      {
        label: "Vulnerable\nComponent",
        colors: {
          bg: "rgba(240,165,0,0.12)",
          border: "rgba(240,165,0,0.4)",
          text: "rgba(240,165,0,1)",
        },
      },
      {
        label: deriveExploit(tags, weaknesses),
        colors: {
          bg: "rgba(255,68,68,0.12)",
          border: "rgba(255,68,68,0.35)",
          text: "rgba(255,100,100,1)",
        },
      },
      {
        label: deriveImpact(tags),
        colors: {
          bg: "rgba(255,68,68,0.18)",
          border: "rgba(255,68,68,0.5)",
          text: "rgba(255,68,68,1)",
        },
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
        style={{ maxHeight: 120 }}
      >
        {boxes.map((box, i) => {
          const x = padX + i * (boxW + gap);
          const y = padY;
          const cx = x + boxW / 2;
          const cy = y + boxH / 2;

          return (
            <g key={i}>
              {/* Box */}
              <rect
                x={x}
                y={y}
                width={boxW}
                height={boxH}
                rx={8}
                ry={8}
                fill={box.colors.bg}
                stroke={box.colors.border}
                strokeWidth={1.5}
              />
              {/* Label */}
              {box.label.includes("\n") ? (
                box.label.split("\n").map((line, li) => (
                  <text
                    key={li}
                    x={cx}
                    y={cy + (li - 0.5) * 14}
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fill={box.colors.text}
                    fontSize={11}
                    fontFamily="var(--font-mono), monospace"
                    fontWeight={500}
                  >
                    {line}
                  </text>
                ))
              ) : (
                <text
                  x={cx}
                  y={cy}
                  textAnchor="middle"
                  dominantBaseline="middle"
                  fill={box.colors.text}
                  fontSize={11}
                  fontFamily="var(--font-mono), monospace"
                  fontWeight={500}
                >
                  {box.label}
                </text>
              )}

              {/* Arrow to next box */}
              {i < boxes.length - 1 && (
                <>
                  <line
                    x1={x + boxW + 4}
                    y1={cy}
                    x2={x + boxW + gap - 8}
                    y2={cy}
                    stroke="rgba(139,148,158,0.35)"
                    strokeWidth={1.5}
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
