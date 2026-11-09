import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { Server, Globe, Radar, Compass, ArrowLeft, ShieldAlert, FileText } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { api } from "../services/api";
import { ApplicationResponse } from "../types";

export const ApplicationDetailsPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [app, setApp] = useState<ApplicationResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);

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

        <div className="md:col-span-2 bg-phantom-900 border border-slate-800 rounded-lg p-5">
          <h3 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider mb-4">
            Behavioral Digital Twin Status (Member 1)
          </h3>
          <div className="bg-slate-950/60 border border-slate-800 rounded p-4 text-xs text-slate-400 leading-relaxed">
            <p className="font-semibold text-slate-200 mb-1">State Machine & Role Mapping</p>
            The Behavioral Digital Twin models workflow sequences and role boundaries extracted by the Discovery Agent.
            Trigger an automated discovery session to populate endpoint graph models.
          </div>
        </div>
      </div>
    </div>
  );
};

