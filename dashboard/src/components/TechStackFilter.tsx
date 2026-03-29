"use client";

import { useState, useEffect, useRef } from "react";
import { X, ChevronDown, Cpu } from "lucide-react";
import { cn } from "@/lib/utils";

const TECH_SUGGESTIONS = [
  "Apache", "Nginx", "Windows", "Linux", "AWS", "Azure",
  "Docker", "Kubernetes", "PHP", "Python", "Java", "Node.js",
  "WordPress", "Cisco", "Fortinet", "Palo Alto", "VMware",
  "Microsoft", "Google Chrome", "Firefox", "OpenSSL", "Redis",
  "MySQL", "PostgreSQL", "Jenkins", "GitLab", "Jira",
];

const STORAGE_KEY = "knowcve-stack";

interface TechStackFilterProps {
  onFilterChange: (techs: string[]) => void;
}

export default function TechStackFilter({ onFilterChange }: TechStackFilterProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const panelRef = useRef<HTMLDivElement>(null);

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved) as string[];
        setSelected(parsed);
        onFilterChange(parsed);
      }
    } catch {
      /* ignore */
    }
  }, []);

  // Close panel on click outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const updateSelection = (techs: string[]) => {
    setSelected(techs);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(techs));
    onFilterChange(techs);
  };

  const addTech = (tech: string) => {
    if (!selected.includes(tech)) {
      updateSelection([...selected, tech]);
    }
    setQuery("");
  };

  const removeTech = (tech: string) => {
    updateSelection(selected.filter((t) => t !== tech));
  };

  const clearAll = () => {
    updateSelection([]);
  };

  const filtered = TECH_SUGGESTIONS.filter(
    (t) =>
      t.toLowerCase().includes(query.toLowerCase()) &&
      !selected.includes(t)
  );

  return (
    <div className="relative" ref={panelRef}>
      {/* Active filter pill */}
      {selected.length > 0 && (
        <div className="flex items-center gap-2 mb-3 px-1">
          <Cpu className="h-3.5 w-3.5 text-acid" />
          <span className="text-xs font-mono text-l-sub dark:text-gray-400">
            Filtered for your stack:
          </span>
          <div className="flex flex-wrap gap-1.5">
            {selected.map((tech) => (
              <span
                key={tech}
                className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-acid/10 text-acid border border-acid/20"
              >
                {tech}
                <button
                  onClick={() => removeTech(tech)}
                  className="hover:text-red-400 transition-colors"
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </span>
            ))}
          </div>
          <button
            onClick={clearAll}
            className="text-[10px] text-l-sub dark:text-gray-500 hover:text-red-400 transition-colors ml-1"
          >
            Clear all
          </button>
        </div>
      )}

      {/* Toggle button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          "flex items-center gap-2 text-xs font-medium px-3 py-1.5 rounded-lg transition-all",
          "border",
          isOpen
            ? "bg-acid/10 text-acid border-acid/30"
            : "text-l-sub dark:text-gray-400 border-l-border dark:border-border hover:border-acid/30 hover:text-acid"
        )}
      >
        <Cpu className="h-3.5 w-3.5" />
        Filter by stack
        <ChevronDown
          className={cn(
            "h-3 w-3 transition-transform",
            isOpen && "rotate-180"
          )}
        />
      </button>

      {/* Floating panel */}
      {isOpen && (
        <div className="absolute top-full left-0 mt-2 z-40 w-72 card p-3 shadow-xl animate-slide-up">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search technologies..."
            className="input-base w-full text-xs mb-2"
            autoFocus
          />
          <div className="max-h-40 overflow-y-auto space-y-0.5">
            {filtered.map((tech) => (
              <button
                key={tech}
                onClick={() => addTech(tech)}
                className="w-full text-left text-xs px-2 py-1.5 rounded hover:bg-l-panel dark:hover:bg-panel text-l-text dark:text-gray-300 transition-colors"
              >
                {tech}
              </button>
            ))}
            {filtered.length === 0 && query && (
              <button
                onClick={() => addTech(query)}
                className="w-full text-left text-xs px-2 py-1.5 rounded hover:bg-l-panel dark:hover:bg-panel text-acid transition-colors"
              >
                + Add &quot;{query}&quot;
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
