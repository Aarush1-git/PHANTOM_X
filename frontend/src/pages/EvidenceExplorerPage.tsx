import React, { useState, useEffect } from "react";
import { FileSearch, Terminal, Database, Code, CheckCircle } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { SearchFilterBar } from "../components/common/SearchFilterBar";
import { EmptyState } from "../components/common/EmptyState";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { api } from "../services/api";
import { EvidenceResponse } from "../types";

export const EvidenceExplorerPage: React.FC = () => {
  const [evidenceList, setEvidenceList] = useState<EvidenceResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const fetchEvidence = async () => {
      try {
        setIsLoading(true);
        const data = await api.evidence.list();
        setEvidenceList(data);
      } catch {
        setEvidenceList([]);
      } finally {
        setIsLoading(false);
      }
    };
    fetchEvidence();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Forensic Evidence Explorer (Member 3)"
        description="Inspect raw HTTP traffic recordings, HAR artifacts, and deterministic proof data."
      />

      <SearchFilterBar searchQuery={search} onSearchChange={setSearch} placeholder="Filter evidence by ID or endpoint..." />

      {isLoading ? (
        <LoadingSpinner />
      ) : evidenceList.length === 0 ? (
        <EmptyState
          icon={FileSearch}
          title="No Forensic Evidence Recorded"
          description="Evidence packages captured during test executions and verified findings will be inspectable here."
        />
      ) : (
        <div className="space-y-4">
          {evidenceList.map((item) => (
            <div key={item.id} className="bg-phantom-900 border border-slate-800 rounded-lg p-5 font-mono text-xs">
              <div className="flex items-center justify-between mb-3">
                <span className="text-cyan-400 font-bold">EVIDENCE ID: {item.id}</span>
                <span className="text-slate-500">{new Date(item.created_at).toLocaleString()}</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-phantom-950 p-3 rounded border border-slate-800">
                  <span className="text-slate-500 block mb-1">REQUEST DUMP</span>
                  <pre className="text-slate-300 overflow-x-auto whitespace-pre-wrap">{item.request_dump}</pre>
                </div>
                <div className="bg-phantom-950 p-3 rounded border border-slate-800">
                  <span className="text-slate-500 block mb-1">RESPONSE DUMP</span>
                  <pre className="text-slate-300 overflow-x-auto whitespace-pre-wrap">{item.response_dump}</pre>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

