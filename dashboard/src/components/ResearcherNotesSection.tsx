"use client";

import { useEffect, useState } from "react";
import { MessageSquare, Send, Plus } from "lucide-react";
import { getNotes, addNote } from "@/lib/api";
import type { ResearcherNoteItem } from "@/types/cve";
import { cn, formatDateRelative } from "@/lib/utils";

interface Props {
  cveId: string;
}

export default function ResearcherNotesSection({ cveId }: Props) {
  const [notes, setNotes] = useState<ResearcherNoteItem[]>([]);
  const [newNote, setNewNote] = useState("");
  const [authorAlias, setAuthorAlias] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getNotes(cveId)
      .then(setNotes)
      .catch(() => {});
  }, [cveId]);

  const handleSubmit = async () => {
    if (newNote.trim().length < 10) {
      setError("Note must be at least 10 characters.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const created = await addNote(
        cveId,
        newNote.trim(),
        authorAlias.trim() || undefined
      );
      setNotes([created, ...notes]);
      setNewNote("");
      setAuthorAlias("");
      setShowForm(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to add note.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mt-4 p-4 rounded-lg border border-blue-500/20 bg-blue-500/5">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-mono text-sm font-medium text-blue-400 flex items-center gap-2 uppercase tracking-widest">
          <MessageSquare className="w-4 h-4" />
          Researcher Notes
        </h3>
        {notes.length > 0 && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30">
            {notes.length}
          </span>
        )}
      </div>

      {/* Notes list */}
      {notes.length > 0 ? (
        <div className="space-y-0 mb-3">
          {notes.map((n, i) => (
            <div
              key={n.id}
              className={cn(
                "py-3",
                i > 0 && "border-t border-blue-500/10"
              )}
            >
              <p className="text-sm text-l-sub dark:text-gray-300 leading-relaxed mb-1.5">
                {n.note}
              </p>
              <div className="flex items-center gap-3 text-[10px] font-mono text-l-sub dark:text-gray-500">
                <span>
                  {n.author_alias ? `@${n.author_alias}` : "anonymous"}
                </span>
                <span>{formatDateRelative(n.created_at)}</span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-l-sub dark:text-gray-400 mb-3">
          No notes yet. Be the first to share your findings.
        </p>
      )}

      {/* Add note button */}
      {!showForm && (
        <button
          onClick={() => setShowForm(true)}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono
                     bg-blue-500/10 text-blue-400 border border-blue-500/30
                     hover:bg-blue-500/20 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          Add Note
        </button>
      )}

      {/* Note form */}
      {showForm && (
        <div className="space-y-3 animate-fade-in">
          <div>
            <textarea
              value={newNote}
              onChange={(e) => setNewNote(e.target.value.slice(0, 500))}
              placeholder="Share your findings, workarounds, or observations..."
              className="input-base w-full h-24 resize-none text-xs"
              maxLength={500}
            />
            <div className="text-right text-[10px] font-mono text-l-sub dark:text-gray-600 mt-1">
              {newNote.length}/500
            </div>
          </div>

          <input
            type="text"
            value={authorAlias}
            onChange={(e) => setAuthorAlias(e.target.value.slice(0, 30))}
            placeholder="Display name (optional, e.g. researcher_42)"
            className="input-base w-full text-xs"
            maxLength={30}
          />

          {error && (
            <p className="text-xs text-red-400 font-mono">{error}</p>
          )}

          <div className="flex items-center gap-2">
            <button
              onClick={handleSubmit}
              disabled={submitting || newNote.trim().length < 10}
              className={cn(
                "inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono",
                "bg-blue-500/15 text-blue-400 border border-blue-500/30",
                "hover:bg-blue-500/25 transition-colors",
                (submitting || newNote.trim().length < 10) && "opacity-60"
              )}
            >
              <Send className="w-3.5 h-3.5" />
              {submitting ? "Posting…" : "Post Note"}
            </button>
            <button
              onClick={() => { setShowForm(false); setError(null); }}
              className="text-xs font-mono text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Disclaimer */}
      <p className="text-[10px] font-mono text-l-sub dark:text-gray-600 mt-3">
        Notes are public and unverified. Do not include personal information.
      </p>
    </div>
  );
}
