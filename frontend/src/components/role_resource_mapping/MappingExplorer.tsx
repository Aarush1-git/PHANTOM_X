import React from "react";
import {
  Filter,
  Layers,
  ChevronLeft,
  ChevronRight,
  Eye,
  Search,
  CheckCircle,
  Clock,
  AlertTriangle,
} from "lucide-react";
import { RoleResourceMapping } from "../../types/roleResource";

interface MappingExplorerProps {
  mappings: RoleResourceMapping[];
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (newPage: number) => void;
  // Filter states
  subjectTypeFilter: string;
  onSubjectTypeFilterChange: (val: string) => void;
  objectTypeFilter: string;
  onObjectTypeFilterChange: (val: string) => void;
  relationshipTypeFilter: string;
  onRelationshipTypeFilterChange: (val: string) => void;
  sourceFilter: string;
  onSourceFilterChange: (val: string) => void;
  statusFilter: string;
  onStatusFilterChange: (val: string) => void;
  minConfidenceFilter: number;
  onMinConfidenceFilterChange: (val: number) => void;
  // Inspect
  onInspectMapping: (mapping: RoleResourceMapping) => void;
  isLoading?: boolean;
}

export const MappingExplorer: React.FC<MappingExplorerProps> = ({
  mappings,
  total,
  page,
  pageSize,
  onPageChange,
  subjectTypeFilter,
  onSubjectTypeFilterChange,
  objectTypeFilter,
  onObjectTypeFilterChange,
  relationshipTypeFilter,
  onRelationshipTypeFilterChange,
  sourceFilter,
  onSourceFilterChange,
  statusFilter,
  onStatusFilterChange,
  minConfidenceFilter,
  onMinConfidenceFilterChange,
  onInspectMapping,
  isLoading,
}) => {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* Filters Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-3">
        <div className="flex items-center gap-2 text-slate-400 font-semibold text-xs">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Mapping Filters & Constraints</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
          {/* Subject Type */}
          <div>
            <label className="text-[10px] text-slate-500 block mb-1">SUBJECT TYPE</label>
            <select
              value={subjectTypeFilter}
              onChange={(e) => onSubjectTypeFilterChange(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-600 text-xs"
            >
              <option value="">All Subjects</option>
              <option value="ROLE">ROLE</option>
              <option value="IDENTITY">IDENTITY</option>
              <option value="RESOURCE">RESOURCE</option>
            </select>
          </div>

          {/* Object Type */}
          <div>
            <label className="text-[10px] text-slate-500 block mb-1">OBJECT TYPE</label>
            <select
              value={objectTypeFilter}
              onChange={(e) => onObjectTypeFilterChange(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-600 text-xs"
            >
              <option value="">All Objects</option>
              <option value="RESOURCE">RESOURCE</option>
              <option value="ENDPOINT">ENDPOINT</option>
              <option value="ROLE">ROLE</option>
            </select>
          </div>

          {/* Relationship Type */}
          <div>
            <label className="text-[10px] text-slate-500 block mb-1">RELATIONSHIP TYPE</label>
            <select
              value={relationshipTypeFilter}
              onChange={(e) => onRelationshipTypeFilterChange(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-600 text-xs"
            >
              <option value="">All Types</option>
              <option value="ROLE_ACCESSES_RESOURCE">ROLE_ACCESSES_RESOURCE</option>
              <option value="ROLE_ACCESSES_ENDPOINT">ROLE_ACCESSES_ENDPOINT</option>
              <option value="STRUCTURAL_CONTAINMENT">STRUCTURAL_CONTAINMENT</option>
              <option value="RESOURCE_REFERENCES_RESOURCE">RESOURCE_REFERENCES_RESOURCE</option>
              <option value="IDENTITY_ASSIGNED_ROLE">IDENTITY_ASSIGNED_ROLE</option>
              <option value="ROLE_DECLARED_INHERITANCE">ROLE_DECLARED_INHERITANCE</option>
              <option value="OBSERVED_ACCESS_OVERLAP">OBSERVED_ACCESS_OVERLAP</option>
            </select>
          </div>

          {/* Evidence Source */}
          <div>
            <label className="text-[10px] text-slate-500 block mb-1">SOURCE</label>
            <select
              value={sourceFilter}
              onChange={(e) => onSourceFilterChange(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-600 text-xs"
            >
              <option value="">All Sources</option>
              <option value="DECLARED">DECLARED</option>
              <option value="OBSERVED">OBSERVED</option>
              <option value="INFERRED">INFERRED</option>
            </select>
          </div>

          {/* Status */}
          <div>
            <label className="text-[10px] text-slate-500 block mb-1">STATUS</label>
            <select
              value={statusFilter}
              onChange={(e) => onStatusFilterChange(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-600 text-xs"
            >
              <option value="">All Statuses</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="CANDIDATE">CANDIDATE</option>
              <option value="DISPUTED">DISPUTED</option>
              <option value="ARCHIVED">ARCHIVED</option>
            </select>
          </div>

          {/* Min Confidence */}
          <div>
            <label className="text-[10px] text-slate-500 block mb-1">
              MIN CONFIDENCE: {Math.round(minConfidenceFilter * 100)}%
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={minConfidenceFilter}
              onChange={(e) => onMinConfidenceFilterChange(parseFloat(e.target.value))}
              className="w-full h-2 bg-slate-950 rounded-lg appearance-none cursor-pointer accent-cyan-500"
            />
          </div>
        </div>
      </div>

      {/* Table Container */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 text-[10px] uppercase tracking-wider">
                <th className="py-2.5 px-3">Subject</th>
                <th className="py-2.5 px-3">Relationship</th>
                <th className="py-2.5 px-3">Object</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3 text-right">Confidence</th>
                <th className="py-2.5 px-3 text-right">Samples</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    Loading relationship mappings...
                  </td>
                </tr>
              ) : mappings.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No mappings matching current filter criteria.
                  </td>
                </tr>
              ) : (
                mappings.map((m) => {
                  let sourceBadge = "bg-cyan-950/60 text-cyan-400 border-cyan-800/60";
                  if (m.evidence_source === "DECLARED") {
                    sourceBadge = "bg-emerald-950/60 text-emerald-400 border-emerald-800/60";
                  } else if (m.evidence_source === "INFERRED") {
                    sourceBadge = "bg-purple-950/60 text-purple-400 border-purple-800/60";
                  }

                  return (
                    <tr key={m.id} className="hover:bg-slate-800/40 transition-colors">
                      {/* Subject */}
                      <td className="py-2 px-3">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[9px] px-1 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            {m.subject_type}
                          </span>
                          <span className="font-semibold text-slate-100 max-w-[150px] truncate" title={m.subject_name}>
                            {m.subject_name}
                          </span>
                        </div>
                      </td>

                      {/* Relationship Type */}
                      <td className="py-2 px-3">
                        <span className="text-cyan-400 text-[11px]">
                          {m.relationship_type.replace(/_/g, " ")}
                        </span>
                      </td>

                      {/* Object */}
                      <td className="py-2 px-3">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[9px] px-1 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                            {m.object_type}
                          </span>
                          <span className="text-slate-200 max-w-[150px] truncate" title={m.object_name}>
                            {m.object_name}
                          </span>
                        </div>
                      </td>

                      {/* Source */}
                      <td className="py-2 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${sourceBadge}`}>
                          {m.evidence_source}
                        </span>
                      </td>

                      {/* Confidence */}
                      <td className="py-2 px-3 text-right">
                        <span
                          className={`font-bold ${
                            m.confidence_score >= 0.7
                              ? "text-emerald-400"
                              : m.confidence_score >= 0.5
                              ? "text-cyan-400"
                              : "text-amber-400"
                          }`}
                        >
                          {Math.round(m.confidence_score * 100)}%
                        </span>
                      </td>

                      {/* Sample Count */}
                      <td className="py-2 px-3 text-right text-slate-400">
                        {m.sample_count}
                      </td>

                      {/* Status */}
                      <td className="py-2 px-3">
                        <span
                          className={`text-[10px] font-semibold ${
                            m.status === "ACTIVE"
                              ? "text-emerald-400"
                              : m.status === "CANDIDATE"
                              ? "text-purple-400"
                              : "text-slate-400"
                          }`}
                        >
                          {m.status}
                        </span>
                      </td>

                      {/* Action */}
                      <td className="py-2 px-3 text-center">
                        <button
                          onClick={() => onInspectMapping(m)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-cyan-600 hover:text-slate-950 text-slate-300 text-[10px] transition-colors"
                          title="Inspect Evidence & Telemetry"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="p-3 bg-slate-950/60 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {mappings.length} of {total} mappings
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:bg-slate-900 disabled:text-slate-600 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-slate-300 font-semibold">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={page >= totalPages}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:bg-slate-900 disabled:text-slate-600 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
