"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { Search, X, Loader2 } from "lucide-react";
import { getCVEs } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { ProcessedCVE } from "@/types/cve";

interface CVESearchInputProps {
  onSelect: (cve: ProcessedCVE) => void;
  placeholder?: string;
  className?: string;
}

export default function CVESearchInput({ onSelect, placeholder = "Search CVEs…", className }: CVESearchInputProps) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<ProcessedCVE[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<NodeJS.Timeout | null>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  const doSearch = useCallback(async (q: string) => {
    if (!q.trim() || q.length < 3) {
      setResults([]);
      setOpen(false);
      return;
    }
    setLoading(true);
    try {
      const cves = await getCVEs({ search: q, page_size: 8 });
      setResults(cves);
      setOpen(cves.length > 0);
    } catch {
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleChange = (val: string) => {
    setQuery(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(val), 300);
  };

  const handleSelect = (cve: ProcessedCVE) => {
    onSelect(cve);
    setQuery("");
    setResults([]);
    setOpen(false);
  };

  const priorityColors: Record<string, string> = {
    CRITICAL: "text-red-400",
    HIGH: "text-amber-400",
    MEDIUM: "text-yellow-300",
    LOW: "text-blue-400",
  };

  return (
    <div className={cn("relative", className)} ref={ref}>
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-l-sub dark:text-gray-500" />
        <input
          type="text"
          value={query}
          onChange={(e) => handleChange(e.target.value)}
          onFocus={() => results.length > 0 && setOpen(true)}
          placeholder={placeholder}
          className="input-base w-full pl-9 pr-8 text-xs"
        />
        {query && (
          <button
            onClick={() => {
              setQuery("");
              setResults([]);
              setOpen(false);
            }}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
        {loading && (
          <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-acid animate-spin" />
        )}
      </div>

      {/* Results dropdown */}
      {open && (
        <div className="absolute top-full left-0 right-0 mt-1 max-h-64 overflow-y-auto rounded-lg border card shadow-xl z-50 animate-fade-in">
          {results.map((cve) => (
            <button
              key={cve.cve_id}
              onClick={() => handleSelect(cve)}
              className="w-full text-left px-3 py-2.5 hover:bg-l-panel dark:hover:bg-panel transition-colors border-b border-l-border/50 dark:border-border/50 last:border-0"
            >
              <div className="flex items-center gap-2 mb-0.5">
                <span className="font-mono text-xs text-acid font-medium">{cve.cve_id}</span>
                <span className={cn("text-[10px] font-mono font-medium", priorityColors[cve.priority_label])}>
                  {cve.priority_label}
                </span>
                <span className="text-[10px] font-mono text-l-sub dark:text-gray-600">
                  KRS {cve.priority_score}
                </span>
              </div>
              <p className="text-[11px] text-l-sub dark:text-gray-500 line-clamp-1">
                {cve.description}
              </p>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
