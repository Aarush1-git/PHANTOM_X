import React, { useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Info,
  ShieldAlert,
  Eye,
  Filter,
} from "lucide-react";
import { DiscrepancyListResponse, RoleResourceMapping } from "../../types/roleResource";

interface DiscrepancyInspectorProps {
  discrepancyData: DiscrepancyListResponse | null;
  onSelectCategory: (category: string) => void;
  selectedCategory: string;
  onInspectMapping: (mapping: RoleResourceMapping) => void;
  isLoading?: boolean;
}

export const DiscrepancyInspector: React.FC<DiscrepancyInspectorProps> = ({
  discrepancyData,
  onSelectCategory,
  selectedCategory,
  onInspectMapping,
  isLoading,
}) => {
  const breakdown = discrepancyData?.breakdown || {};
  const alignedCount = breakdown["ALIGNED"] ?? 0;
  const declaredNotObservedCount = breakdown["DECLARED_NOT_OBSERVED"] ?? 0;
  const observedNotDeclaredCount = breakdown["OBSERVED_NOT_DECLARED"] ?? 0;
  const insufficientCount = breakdown["EVIDENCE_INSUFFICIENT"] ?? 0;

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Prominent Evidence Disclaimer Callout */}
      <div className="p-4 bg-slate-900 border border-cyan-900/60 rounded-lg space-y-2">
        <div className="flex items-center gap-2 text-cyan-400 font-semibold text-xs">
          <Info className="w-4 h-4 shrink-0" />
          <span>Empirical Discrepancy Analysis — Analytical Boundary Notice</span>
        </div>
        <p className="text-slate-300 text-[11px] leading-relaxed">
          {discrepancyData?.evidence_limitations_note ||
            "Discrepancies represent empirical differences between declared specifications and observed traffic telemetry. They do NOT constitute verified security vulnerabilities, and unexercised permissions must not be assumed absent."}
        </p>
        <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-800">
          Formal authorization testing and exploit verification belong strictly to active scanning phases.
        </div>
      </div>

      {/* Category Breakdown Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {/* ALIGNED */}
        <button
          onClick={() => onSelectCategory(selectedCategory === "ALIGNED" ? "" : "ALIGNED")}
          className={`p-3 rounded-lg border text-left transition-all ${
            selectedCategory === "ALIGNED"
              ? "bg-emerald-950/50 border-emerald-500 ring-1 ring-emerald-500"
              : "bg-slate-900 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px]">
            <span>ALIGNED</span>
            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-lg font-bold text-emerald-400 mt-1">{alignedCount}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            Declared &amp; observed in traffic
          </div>
        </button>

        {/* DECLARED_NOT_OBSERVED */}
        <button
          onClick={() =>
            onSelectCategory(
              selectedCategory === "DECLARED_NOT_OBSERVED" ? "" : "DECLARED_NOT_OBSERVED"
            )
          }
          className={`p-3 rounded-lg border text-left transition-all ${
            selectedCategory === "DECLARED_NOT_OBSERVED"
              ? "bg-amber-950/50 border-amber-500 ring-1 ring-amber-500"
              : "bg-slate-900 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px]">
            <span>DECLARED NOT OBSERVED</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-lg font-bold text-amber-400 mt-1">
            {declaredNotObservedCount}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            In spec, unexercised in logs
          </div>
        </button>

        {/* OBSERVED_NOT_DECLARED */}
        <button
          onClick={() =>
            onSelectCategory(
              selectedCategory === "OBSERVED_NOT_DECLARED" ? "" : "OBSERVED_NOT_DECLARED"
            )
          }
          className={`p-3 rounded-lg border text-left transition-all ${
            selectedCategory === "OBSERVED_NOT_DECLARED"
              ? "bg-rose-950/50 border-rose-500 ring-1 ring-rose-500"
              : "bg-slate-900 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px]">
            <span>OBSERVED NOT DECLARED</span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-lg font-bold text-rose-400 mt-1">
            {observedNotDeclaredCount}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            Seen in traffic, missing in spec
          </div>
        </button>

        {/* EVIDENCE_INSUFFICIENT */}
        <button
          onClick={() =>
            onSelectCategory(
              selectedCategory === "EVIDENCE_INSUFFICIENT" ? "" : "EVIDENCE_INSUFFICIENT"
            )
          }
          className={`p-3 rounded-lg border text-left transition-all ${
            selectedCategory === "EVIDENCE_INSUFFICIENT"
              ? "bg-slate-800 border-slate-500 ring-1 ring-slate-500"
              : "bg-slate-900 border-slate-800 hover:border-slate-700"
          }`}
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px]">
            <span>INSUFFICIENT EVIDENCE</span>
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="text-lg font-bold text-slate-300 mt-1">{insufficientCount}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            Low sample count (&lt; 2)
          </div>
        </button>
      </div>

      {/* Discrepancy Items List */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="p-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="text-slate-300 font-semibold text-xs flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            <span>
              {selectedCategory
                ? `Discrepancies filtered by: ${selectedCategory}`
                : "All Discrepancy Mappings"}
            </span>
          </div>
          <span className="text-[11px] text-slate-500">
            {discrepancyData?.items?.length ?? 0} items
          </span>
        </div>

        <div className="divide-y divide-slate-800/60">
          {isLoading ? (
            <div className="p-8 text-center text-slate-500">Loading discrepancies...</div>
          ) : !discrepancyData?.items || discrepancyData.items.length === 0 ? (
            <div className="p-8 text-center text-slate-500">
              No discrepancies found for this filter.
            </div>
          ) : (
            discrepancyData.items.map((m) => {
              const disc = m.declared_vs_observed || {};
              const cat = disc.discrepancy_category || "NONE";

              let badgeStyle = "bg-slate-800 text-slate-300 border-slate-700";
              if (cat === "ALIGNED") {
                badgeStyle = "bg-emerald-950/80 text-emerald-300 border-emerald-800";
              } else if (cat === "DECLARED_NOT_OBSERVED") {
                badgeStyle = "bg-amber-950/80 text-amber-300 border-amber-800";
              } else if (cat === "OBSERVED_NOT_DECLARED") {
                badgeStyle = "bg-rose-950/80 text-rose-300 border-rose-800";
              } else if (cat === "EVIDENCE_INSUFFICIENT") {
                badgeStyle = "bg-slate-800 text-slate-400 border-slate-600";
              }

              return (
                <div
                  key={m.id}
                  className="p-3 hover:bg-slate-800/40 transition-colors flex items-start justify-between gap-3"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badgeStyle}`}>
                        {cat}
                      </span>
                      <span className="font-semibold text-slate-100">
                        {m.subject_name}
                      </span>
                      <span className="text-cyan-400 text-[11px]">&rarr; {m.relationship_type.replace(/_/g, " ")} &rarr;</span>
                      <span className="text-slate-200">{m.object_name}</span>
                    </div>

                    <div className="text-[11px] text-slate-400">
                      {disc.notes ||
                        (cat === "DECLARED_NOT_OBSERVED"
                          ? "Declared in role specification but zero runtime requests observed."
                          : cat === "OBSERVED_NOT_DECLARED"
                          ? "Traffic requests observed at runtime but endpoint is missing in declared specification."
                          : "Empirical observation matches declared role permissions.")}
                    </div>

                    <div className="flex items-center gap-4 text-[10px] text-slate-500">
                      <span>Source: {m.evidence_source}</span>
                      <span>Confidence: {Math.round(m.confidence_score * 100)}%</span>
                      <span>Samples: {m.sample_count}</span>
                    </div>
                  </div>

                  <button
                    onClick={() => onInspectMapping(m)}
                    className="shrink-0 inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] transition-colors"
                  >
                    <Eye className="w-3 h-3" />
                    <span>Evidence</span>
                  </button>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
