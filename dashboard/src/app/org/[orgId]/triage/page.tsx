"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import {
  Columns3,
  Plus,
  Zap,
  Filter,
  X,
  User,
  ArrowRight,
} from "lucide-react";
import {
  DndContext,
  DragOverlay,
  pointerWithin,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
  useDroppable,
  useDraggable,
} from "@dnd-kit/core";
import { useAuth } from "@/lib/auth-context";
import { cn } from "@/lib/utils";
import {
  listTriageItems,
  createTriageItem,
  updateTriageItem,
  deleteTriageItem,
  autoPopulateTriage,
  listMembers,
  getTriageActivity,
} from "@/lib/api";
import type { TriageItem, TriageStatus, OrgMember, TriageActivity } from "@/types/cve";
import TriageCard from "@/components/TriageCard";
import CVESearchInput from "@/components/CVESearchInput";
import SLATimer from "@/components/SLATimer";
import Footer from "@/components/layout/Footer";
import type { ProcessedCVE } from "@/types/cve";

const COLUMNS: { id: TriageStatus; label: string; color: string }[] = [
  { id: "new", label: "New", color: "border-blue-500/50 bg-blue-500/5" },
  { id: "investigating", label: "Investigating", color: "border-amber-500/50 bg-amber-500/5" },
  { id: "remediation_planned", label: "Remediation", color: "border-purple-500/50 bg-purple-500/5" },
  { id: "mitigated", label: "Mitigated", color: "border-emerald-500/50 bg-emerald-500/5" },
  { id: "wont_fix", label: "Won't Fix", color: "border-l-muted/50 dark:border-muted/50 bg-l-panel/50 dark:bg-panel/50" },
];

/* ── Draggable Card Wrapper ── */
function DraggableCard({
  item,
  onSelect,
}: {
  item: TriageItem;
  onSelect: (item: TriageItem) => void;
}) {
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id: item.id,
  });
  const style = transform
    ? { transform: `translate3d(${transform.x}px, ${transform.y}px, 0)` }
    : undefined;

  return (
    <div ref={setNodeRef} style={style} {...attributes}>
      <TriageCard
        item={item}
        isDragging={isDragging}
        onSelect={onSelect}
        dragHandleProps={listeners}
      />
    </div>
  );
}

/* ── Droppable Column ── */
function DroppableColumn({
  column,
  items,
  isOver,
  children,
}: {
  column: (typeof COLUMNS)[0];
  items: TriageItem[];
  isOver: boolean;
  children: React.ReactNode;
}) {
  const { setNodeRef } = useDroppable({ id: column.id });
  const overdueCount = items.filter((i) => i.is_overdue).length;
  const criticalCount = items.filter(
    (i) => i.cve_data?.priority_label === "CRITICAL"
  ).length;

  return (
    <div
      ref={setNodeRef}
      className={cn(
        "flex flex-col rounded-xl border-t-2 min-h-[300px] transition-all",
        column.color,
        isOver && "ring-2 ring-acid/30 border-acid/50"
      )}
    >
      {/* Column header */}
      <div className="px-3 py-2.5 border-b border-l-border/50 dark:border-border/50">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-medium text-l-text dark:text-gray-200">{column.label}</h3>
          <span className="text-[10px] font-mono text-l-sub dark:text-gray-500 bg-l-panel dark:bg-panel rounded-full px-2 py-0.5">
            {items.length}
          </span>
        </div>
        {(criticalCount > 0 || overdueCount > 0) && (
          <div className="flex gap-2 mt-1">
            {criticalCount > 0 && (
              <span className="text-[9px] font-mono text-red-400">{criticalCount} critical</span>
            )}
            {overdueCount > 0 && (
              <span className="text-[9px] font-mono text-red-400 animate-pulse">{overdueCount} overdue</span>
            )}
          </div>
        )}
      </div>

      {/* Cards */}
      <div className="flex-1 p-2 space-y-2 overflow-y-auto max-h-[calc(100vh-280px)]">
        {children}
        {items.length === 0 && (
          <div className="text-center py-6 text-[11px] text-l-sub dark:text-gray-600">
            No items
          </div>
        )}
      </div>
    </div>
  );
}

export default function TriageBoardPage() {
  const { user } = useAuth();
  const params = useParams();
  const orgId = params.orgId as string;

  const [items, setItems] = useState<TriageItem[]>([]);
  const [members, setMembers] = useState<OrgMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [showSearch, setShowSearch] = useState(false);
  const [selectedItem, setSelectedItem] = useState<TriageItem | null>(null);
  const [activity, setActivity] = useState<TriageActivity[]>([]);
  const [activeDragId, setActiveDragId] = useState<string | null>(null);
  const [overColumnId, setOverColumnId] = useState<string | null>(null);
  const [autoPopCount, setAutoPopCount] = useState<number | null>(null);
  const [isMobile, setIsMobile] = useState(false);

  // Detect mobile
  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 768);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 5 } }),
    useSensor(KeyboardSensor)
  );

  const fetchData = useCallback(async () => {
    if (!user?.id) return;
    setLoading(true);
    try {
      const [triageResult, memberResult] = await Promise.all([
        listTriageItems(orgId, user.id),
        listMembers(orgId, user.id),
      ]);
      setItems(triageResult.data || []);
      setMembers(memberResult.data || []);
    } catch { /* fail */ }
    setLoading(false);
  }, [user?.id, orgId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Fetch activity when item is selected
  useEffect(() => {
    if (!selectedItem || !user) return;
    getTriageActivity(orgId, selectedItem.id, user.id)
      .then((r) => setActivity(r.data || []))
      .catch(() => setActivity([]));
  }, [selectedItem, orgId, user]);

  /* ── Handlers ── */

  const handleDragStart = (event: DragStartEvent) => {
    setActiveDragId(event.active.id as string);
  };

  const handleDragOver = (event: { over: { id: string } | null }) => {
    setOverColumnId(event.over?.id?.toString() || null);
  };

  const handleDragEnd = async (event: DragEndEvent) => {
    setActiveDragId(null);
    setOverColumnId(null);

    const { active, over } = event;
    if (!over || !user) return;

    const itemId = active.id as string;
    const newStatus = over.id as TriageStatus;
    const item = items.find((i) => i.id === itemId);
    if (!item || item.status === newStatus) return;

    // Optimistic update
    setItems((prev) =>
      prev.map((i) => (i.id === itemId ? { ...i, status: newStatus } : i))
    );

    try {
      await updateTriageItem(orgId, itemId, user.id, { status: newStatus });
      await fetchData(); // Refresh to get updated SLA times
    } catch {
      // Revert on failure
      setItems((prev) =>
        prev.map((i) => (i.id === itemId ? { ...i, status: item.status } : i))
      );
    }
  };

  const handleAddCVE = async (cve: ProcessedCVE) => {
    if (!user?.id) return;
    try {
      await createTriageItem(orgId, user.id, { cve_id: cve.cve_id });
      setShowSearch(false);
      await fetchData();
    } catch { /* fail */ }
  };

  const handleAutoPop = async () => {
    if (!user?.id) return;
    try {
      const result = await autoPopulateTriage(orgId, user.id);
      setAutoPopCount(result.items_added);
      await fetchData();
      setTimeout(() => setAutoPopCount(null), 3000);
    } catch { /* fail */ }
  };

  const handleStatusChange = async (itemId: string, newStatus: string) => {
    if (!user?.id) return;
    try {
      await updateTriageItem(orgId, itemId, user.id, { status: newStatus });
      await fetchData();
      if (selectedItem?.id === itemId) {
        setSelectedItem((prev) => prev ? { ...prev, status: newStatus as TriageStatus } : null);
      }
    } catch { /* fail */ }
  };

  const handleAssign = async (itemId: string, assigneeId: string) => {
    if (!user?.id) return;
    try {
      await updateTriageItem(orgId, itemId, user.id, { assignee_id: assigneeId || undefined });
      await fetchData();
      // Refresh selectedItem so the dropdown reflects the new assignee
      if (selectedItem?.id === itemId) {
        setSelectedItem((prev) => prev ? { ...prev, assignee_id: assigneeId || null } : null);
      }
    } catch { /* fail */ }
  };

  const handleDelete = async (itemId: string) => {
    if (!user?.id) return;
    try {
      await deleteTriageItem(orgId, itemId, user.id);
      setSelectedItem(null);
      await fetchData();
    } catch { /* fail */ }
  };

  const groupedItems = COLUMNS.map((col) => ({
    ...col,
    items: items.filter((i) => i.status === col.id),
  }));

  const activeItem = activeDragId ? items.find((i) => i.id === activeDragId) : null;

  if (loading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-10 w-48 skeleton" />
        <div className="grid grid-cols-5 gap-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-64 skeleton rounded-xl" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Header */}
      <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
        <div className="flex items-center gap-2">
          <Columns3 className="h-5 w-5 text-amber-400" />
          <h1 className="font-display font-bold text-xl text-l-text dark:text-gray-100">
            CVE Triage Board
          </h1>
          <span className="text-xs font-mono text-l-sub dark:text-gray-500">
            {items.length} items
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={() => setShowSearch(!showSearch)} className="btn-primary text-xs flex items-center gap-1.5">
            <Plus className="h-3.5 w-3.5" />
            Add CVE
          </button>
          <button onClick={handleAutoPop} className="btn-ghost text-xs flex items-center gap-1.5 border border-l-border dark:border-border">
            <Zap className="h-3.5 w-3.5" />
            Auto-populate
          </button>
        </div>
      </div>

      {/* Auto-populate toast */}
      {autoPopCount !== null && (
        <div className="mb-4 p-3 rounded-lg border border-acid/20 bg-acid/5 text-xs text-acid animate-fade-in">
          ✓ Added {autoPopCount} CRITICAL/HIGH CVEs to triage board
        </div>
      )}

      {/* Search bar */}
      {showSearch && (
        <div className="mb-4 animate-fade-in">
          <CVESearchInput
            onSelect={handleAddCVE}
            placeholder="Search CVEs to add to triage…"
          />
        </div>
      )}

      {/* ── Kanban Board (Desktop) ── */}
      {!isMobile ? (
        <DndContext
          sensors={sensors}
          collisionDetection={pointerWithin}
          onDragStart={handleDragStart}
          onDragOver={handleDragOver as Parameters<typeof DndContext>[0]["onDragOver"]}
          onDragEnd={handleDragEnd}
        >
          <div className="grid grid-cols-5 gap-3 mb-8">
            {groupedItems.map((col) => (
              <DroppableColumn
                key={col.id}
                column={col}
                items={col.items}
                isOver={overColumnId === col.id}
              >
                {col.items.map((item) => (
                  <DraggableCard
                    key={item.id}
                    item={item}
                    onSelect={setSelectedItem}
                  />
                ))}
              </DroppableColumn>
            ))}
          </div>

          <DragOverlay>
            {activeItem ? (
              <div className="w-64">
                <TriageCard item={activeItem} isDragging />
              </div>
            ) : null}
          </DragOverlay>
        </DndContext>
      ) : (
        /* ── Mobile List View ── */
        <div className="space-y-2 mb-8">
          {items.map((item) => (
            <div key={item.id} className="card p-3">
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-acid font-medium">{item.cve_id}</span>
                  <span className={cn(
                    "badge text-[9px] py-0.5",
                    item.cve_data?.priority_label === "CRITICAL" && "bg-red-500/15 border-red-500/30 text-red-400",
                    item.cve_data?.priority_label === "HIGH" && "bg-amber-500/15 border-amber-500/30 text-amber-400",
                  )}>
                    {item.cve_data?.priority_label || "—"}
                  </span>
                </div>
                <SLATimer slaDueAt={item.sla_due_at} status={item.status} compact />
              </div>
              <select
                value={item.status}
                onChange={(e) => handleStatusChange(item.id, e.target.value)}
                className="input-base text-xs w-full"
              >
                {COLUMNS.map((col) => (
                  <option key={col.id} value={col.id}>{col.label}</option>
                ))}
              </select>
            </div>
          ))}
        </div>
      )}

      {/* ── Detail Side Panel ── */}
      {selectedItem && (
        <div className="fixed inset-y-0 right-0 w-full max-w-md z-40 animate-slide-in">
          <div
            className="absolute inset-0 bg-void/40 backdrop-blur-sm"
            onClick={() => setSelectedItem(null)}
          />
          <div className="relative h-full ml-auto w-full max-w-md bg-l-surface dark:bg-surface border-l border-l-border dark:border-border overflow-y-auto">
            <div className="p-6">
              {/* Close */}
              <div className="flex items-center justify-between mb-4">
                <span className="font-mono text-lg text-acid font-bold">{selectedItem.cve_id}</span>
                <button onClick={() => setSelectedItem(null)} className="text-l-sub dark:text-gray-500 hover:text-l-text dark:hover:text-gray-300">
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* SLA */}
              <div className="mb-4">
                <SLATimer slaDueAt={selectedItem.sla_due_at} status={selectedItem.status} />
              </div>

              {/* CVE Description */}
              {selectedItem.cve_data && (
                <div className="mb-4">
                  <p className="text-xs text-l-sub dark:text-gray-400 leading-relaxed">
                    {selectedItem.cve_data.description}
                  </p>
                </div>
              )}

              {/* Status */}
              <div className="mb-4">
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">Status</label>
                <select
                  value={selectedItem.status}
                  onChange={(e) => handleStatusChange(selectedItem.id, e.target.value)}
                  className="input-base text-xs w-full"
                >
                  {COLUMNS.map((col) => (
                    <option key={col.id} value={col.id}>{col.label}</option>
                  ))}
                </select>
              </div>

              {/* Assignee */}
              <div className="mb-4">
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-1 block">Assignee</label>
                <select
                  value={selectedItem.assignee_id || ""}
                  onChange={(e) => handleAssign(selectedItem.id, e.target.value)}
                  className="input-base text-xs w-full"
                >
                  <option value="">Unassigned</option>
                  {members.map((m) => (
                    <option key={m.user_id} value={m.user_id}>
                      {m.display_name || m.email || m.user_id}
                    </option>
                  ))}
                </select>
              </div>

              {/* Activity Log */}
              <div className="mb-4">
                <label className="text-xs font-mono text-l-sub dark:text-gray-500 mb-2 block">Activity</label>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {activity.map((a) => (
                    <div key={a.id} className="text-[11px] text-l-sub dark:text-gray-500 border-l-2 border-l-border dark:border-border pl-2">
                      <span className="text-l-text dark:text-gray-300">{a.detail}</span>
                      <br />
                      <span className="text-[10px]">{new Date(a.created_at).toLocaleString()}</span>
                    </div>
                  ))}
                  {activity.length === 0 && (
                    <p className="text-[11px] text-l-sub dark:text-gray-600">No activity yet.</p>
                  )}
                </div>
              </div>

              {/* Actions */}
              <div className="flex gap-2">
                <a href={`/cve/${selectedItem.cve_id}`} className="btn-ghost text-xs flex items-center gap-1.5 border border-l-border dark:border-border">
                  View CVE <ArrowRight className="h-3 w-3" />
                </a>
                <button
                  onClick={() => handleDelete(selectedItem.id)}
                  className="btn-ghost text-xs text-red-400 hover:bg-red-500/10"
                >
                  Remove
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <Footer />
    </>
  );
}
