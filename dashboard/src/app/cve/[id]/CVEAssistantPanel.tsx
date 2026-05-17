"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { MessageSquare, Send, ChevronDown, ChevronUp, Loader2, Sparkles } from "lucide-react";
import { askCVEAssistant } from "@/lib/api";
import type { AIExplanation } from "@/types/cve";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

interface CVEAssistantPanelProps {
  cveId: string;
  cveDescription: string;
  aiExplanation: AIExplanation | null;
}

/* ── Suggested starter questions ───────────── */

function getSuggestedQuestions(ai: AIExplanation | null, desc: string): string[] {
  const questions: string[] = [];
  const lower = desc.toLowerCase();

  // Context-aware suggestions
  if (lower.includes("remote") || lower.includes("network") || lower.includes("web")) {
    questions.push("What if there's a WAF in front?");
  }
  if (lower.includes("container") || lower.includes("docker") || lower.includes("kubernetes")) {
    questions.push("Is this exploitable from an unprivileged container?");
  }
  if (lower.includes("auth") || lower.includes("authentication") || lower.includes("login")) {
    questions.push("What's the bypass for the auth check?");
  }
  if (lower.includes("memory") || lower.includes("buffer") || lower.includes("overflow") || lower.includes("heap")) {
    questions.push("What memory protections would mitigate this?");
  }
  if (lower.includes("rce") || lower.includes("code execution") || lower.includes("command injection")) {
    questions.push("What does post-exploitation look like?");
  }

  // Generic fallbacks
  if (questions.length < 3) {
    questions.push("How would you detect exploitation of this CVE?");
  }
  if (questions.length < 3) {
    questions.push("What compensating controls reduce risk?");
  }
  if (questions.length < 3) {
    questions.push("Which threat actors target this CVE class?");
  }

  return questions.slice(0, 3);
}

/* ── Chat message bubble ───────────────────── */

function MessageBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === "user";

  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"} mb-3 animate-fade-in`}>
      <div
        className={`max-w-[85%] rounded-xl px-4 py-2.5 text-sm leading-relaxed ${
          isUser
            ? "bg-acid/10 border border-acid/20 text-l-text dark:text-gray-200"
            : "bg-l-panel dark:bg-panel border border-l-border dark:border-border text-l-sub dark:text-gray-300"
        }`}
      >
        <div className="whitespace-pre-wrap">{message.content}</div>
      </div>
    </div>
  );
}

/* ── Main component ────────────────────────── */

export default function CVEAssistantPanel({
  cveId,
  cveDescription,
  aiExplanation,
}: CVEAssistantPanelProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const suggestions = getSuggestedQuestions(aiExplanation, cveDescription);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  // Focus input when expanded
  useEffect(() => {
    if (isExpanded && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isExpanded]);

  const sendMessage = useCallback(async (text: string) => {
    if (!text.trim() || loading) return;

    const userMsg: ChatMessage = { role: "user", content: text.trim() };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setError(null);
    setLoading(true);

    try {
      // Build history from existing messages (limit to 10 = 5 exchanges)
      const history = [...messages, userMsg].slice(-10).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const result = await askCVEAssistant(cveId, text.trim(), history);
      const assistantMsg: ChatMessage = { role: "assistant", content: result.reply };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : "Failed to get response";
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  }, [cveId, messages, loading]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    sendMessage(input);
  };

  return (
    <div className="mt-6 mb-4">
      {/* Toggle button */}
      <button
        id="cve-assistant-toggle"
        onClick={() => setIsExpanded(!isExpanded)}
        className={`w-full flex items-center justify-between px-4 py-3 rounded-xl border transition-all duration-300 ${
          isExpanded
            ? "bg-acid/5 border-acid/20 shadow-lg shadow-acid/5"
            : "bg-l-surface dark:bg-surface border-l-border dark:border-border hover:border-acid/30 hover:bg-acid/5"
        }`}
      >
        <div className="flex items-center gap-2">
          <div className={`p-1.5 rounded-lg ${isExpanded ? "bg-acid/15" : "bg-l-panel dark:bg-panel"}`}>
            <MessageSquare className={`h-4 w-4 ${isExpanded ? "text-acid" : "text-l-sub dark:text-gray-400"}`} />
          </div>
          <div className="text-left">
            <span className={`text-sm font-medium ${isExpanded ? "text-acid" : "text-l-text dark:text-gray-200"}`}>
              Ask about this CVE
            </span>
            <span className="text-[10px] font-mono text-l-sub dark:text-gray-500 ml-2">
              AI-POWERED
            </span>
          </div>
        </div>
        {isExpanded ? (
          <ChevronUp className="h-4 w-4 text-acid" />
        ) : (
          <ChevronDown className="h-4 w-4 text-l-sub dark:text-gray-500" />
        )}
      </button>

      {/* Expanded chat panel */}
      {isExpanded && (
        <div className="mt-2 rounded-xl border border-acid/15 bg-l-surface/95 dark:bg-surface/95 backdrop-blur-sm overflow-hidden animate-fade-in">
          {/* Chat area */}
          <div
            ref={scrollRef}
            className="p-4 min-h-[120px] max-h-[400px] overflow-y-auto scrollbar-hide"
          >
            {/* Welcome message if no messages yet */}
            {messages.length === 0 && (
              <div className="text-center py-6">
                <Sparkles className="h-8 w-8 mx-auto text-acid/40 mb-3" />
                <p className="text-sm text-l-sub dark:text-gray-400 mb-4">
                  Ask follow-up questions about <span className="font-mono text-acid">{cveId}</span>
                </p>

                {/* Suggested questions */}
                <div className="flex flex-wrap gap-2 justify-center">
                  {suggestions.map((q) => (
                    <button
                      key={q}
                      onClick={() => sendMessage(q)}
                      className="text-xs px-3 py-1.5 rounded-lg border border-acid/15 bg-acid/5
                                 text-l-sub dark:text-gray-400 hover:text-acid hover:border-acid/30
                                 transition-all duration-200"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Messages */}
            {messages.map((msg, idx) => (
              <MessageBubble key={idx} message={msg} />
            ))}

            {/* Loading indicator */}
            {loading && (
              <div className="flex justify-start mb-3">
                <div className="bg-l-panel dark:bg-panel border border-l-border dark:border-border rounded-xl px-4 py-2.5 flex items-center gap-2">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-acid" />
                  <span className="text-xs text-l-sub dark:text-gray-400">Analyzing...</span>
                </div>
              </div>
            )}

            {/* Error message */}
            {error && (
              <div className="text-center py-2">
                <span className="text-xs text-red-400">{error}</span>
              </div>
            )}
          </div>

          {/* Input area */}
          <form
            onSubmit={handleSubmit}
            className="flex items-center gap-2 px-4 py-3 border-t border-l-border/50 dark:border-border/50 bg-l-panel/50 dark:bg-panel/50"
          >
            <input
              ref={inputRef}
              id="cve-assistant-input"
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={`Ask about ${cveId}...`}
              disabled={loading}
              className="flex-1 bg-transparent text-sm text-l-text dark:text-gray-200 placeholder:text-l-sub dark:placeholder:text-gray-500
                         focus:outline-none font-sans"
              maxLength={500}
            />
            <button
              type="submit"
              disabled={!input.trim() || loading}
              className="p-2 rounded-lg bg-acid/10 text-acid hover:bg-acid/20 disabled:opacity-30
                         disabled:cursor-not-allowed transition-all duration-200"
            >
              <Send className="h-4 w-4" />
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
