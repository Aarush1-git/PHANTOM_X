import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { Server, Globe, Radar, Compass, ArrowLeft, ShieldAlert, FileText, Cpu, GitBranch, Key } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { BehavioralDigitalTwinPanel } from "../components/behavioral_digital_twin";
import { WorkflowDiscoveryPanel } from "../components/workflow_discovery";
import { RoleResourceMappingPanel } from "../components/role_resource_mapping";
import { api } from "../services/api";
import { ApplicationResponse } from "../types";

export const ApplicationDetailsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [app, setApp] = useState<ApplicationResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"twin" | "workflows" | "role_resource">("twin");

  useEffect(() => {
    if (!id) return;
    const fetchApp = async () => {
      try {
        setIsLoading(true);
        const data = await api.applications.getById(id);
        setApp(data);
      } catch {
        // Dev fallback if not persisted
        setApp({
          id,
          organization_id: "org-1",
          name: "Sample Application",
          target_url: "http://localhost:3000",
          description: "Target application profile details.",
          risk_score: 0.0,
          status: "ACTIVE",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });
      } finally {
        setIsLoading(false);
      }
    };
    fetchApp();
  }, [id]);

  if (isLoading) return <LoadingSpinner />;
  if (!app) return <div>Application not found.</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-xs font-mono text-slate-500 mb-2">
        <Link to="/applications" className="hover:text-slate-300 flex items-center gap-1">
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Applications</span>
        </Link>
      </div>

      <PageHeader
        title={app.name}
        description={app.description || "Application profiling and attack surface mapping."}
        actions={
          <div className="flex gap-2">
            <Link
              to={`/discovery?app_id=${app.id}`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono border border-slate-700"
            >
              <Compass className="w-3.5 h-3.5" />
              <span>Explore APIs</span>
            </Link>
            <Link
              to={`/scans?app_id=${app.id}`}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
            >
              <Radar className="w-3.5 h-3.5" />
              <span>Launch Scan</span>
            </Link>
          </div>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">Target Profile</h3>
          <div className="text-xs space-y-2 font-mono">
            <div>
              <span className="text-slate-500 block">BASE URL</span>
              <span className="text-slate-200 break-all">{app.target_url}</span>
            </div>
            <div>
              <span className="text-slate-500 block">STATUS</span>
              <span className="text-emerald-400">{app.status}</span>
            </div>
            <div>
              <span className="text-slate-500 block">RISK SCORE</span>
              <span className="text-cyan-400 font-bold">{app.risk_score} / 100</span>
            </div>
            <div>
              <span className="text-slate-500 block">REGISTERED</span>
              <span className="text-slate-400">{new Date(app.created_at).toLocaleString()}</span>
            </div>
          </div>
        </div>

        <div className="md:col-span-2 space-y-4">
          {/* Tab Navigation */}
          <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
            <button
              onClick={() => setActiveTab("twin")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                activeTab === "twin"
                  ? "bg-cyan-600/20 text-cyan-400 border border-cyan-800/60 font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Behavioral Digital Twin</span>
            </button>
            <button
              onClick={() => setActiveTab("workflows")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                activeTab === "workflows"
                  ? "bg-cyan-600/20 text-cyan-400 border border-cyan-800/60 font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>Workflow Discovery</span>
            </button>
            <button
              onClick={() => setActiveTab("role_resource")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                activeTab === "role_resource"
                  ? "bg-cyan-600/20 text-cyan-400 border border-cyan-800/60 font-semibold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
              }`}
            >
              <Key className="w-3.5 h-3.5" />
              <span>Role &amp; Resource Mapping</span>
            </button>
          </div>

          {/* Panel Display */}
          {activeTab === "twin" ? (
            <BehavioralDigitalTwinPanel applicationId={app.id} />
          ) : activeTab === "workflows" ? (
            <WorkflowDiscoveryPanel applicationId={app.id} />
          ) : (
            <RoleResourceMappingPanel applicationId={app.id} />
          )}
        </div>
      </div>
    </div>
  );
};
