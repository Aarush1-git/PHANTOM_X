import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Server, Plus, Globe, Shield, ExternalLink, Trash2 } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { SearchFilterBar } from "../components/common/SearchFilterBar";
import { EmptyState } from "../components/common/EmptyState";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { Modal } from "../components/common/Modal";
import { api } from "../services/api";
import { ApplicationResponse } from "../types";

export const ApplicationsPage: React.FC = () => {
  const [apps, setApps] = useState<ApplicationResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [name, setName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [desc, setDesc] = useState("");
  const [envName, setEnvName] = useState("staging");

  const fetchApps = async () => {
    try {
      setIsLoading(true);
      const data = await api.applications.list();
      setApps(data);
    } catch {
      // Fallback empty if backend starting
      setApps([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.applications.create({
        name,
        target_url: targetUrl,
        description: desc,
        environment_name: envName,
      });
      setIsModalOpen(false);
      setName("");
      setTargetUrl("");
      setDesc("");
      fetchApps();
    } catch (err) {
      console.error(err);
    }
  };

  const filtered = apps.filter(
    (a) =>
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.target_url.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Target Applications"
        description="Register and manage authorized web applications and APIs for continuous security assessment."
        actions={
          <button
            onClick={() => setIsModalOpen(true)}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Register Application</span>
          </button>
        }
      />

      <SearchFilterBar searchQuery={search} onSearchChange={setSearch} placeholder="Search by name or URL..." />

      {isLoading ? (
        <LoadingSpinner />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Server}
          title="No Applications Registered"
          description="Register your first authorized target application to map endpoints and build a Behavioral Digital Twin."
          action={
            <button
              onClick={() => setIsModalOpen(true)}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Register Target Application</span>
            </button>
          }
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map((app) => (
            <div key={app.id} className="bg-phantom-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-start justify-between">
                  <h3 className="text-base font-semibold text-slate-100">{app.name}</h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    {app.status}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mt-2 break-all">
                  <Globe className="w-3.5 h-3.5 shrink-0 text-slate-500" />
                  <span>{app.target_url}</span>
                </div>
                {app.description && <p className="text-xs text-slate-400 mt-3 line-clamp-2">{app.description}</p>}
              </div>

              <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-xs font-mono text-slate-500">Risk Score: {app.risk_score}</span>
                <Link
                  to={`/applications/${app.id}`}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
                >
                  <span>Details</span> <ExternalLink className="w-3 h-3" />
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Register Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Register Target Application (Authorized Scope)"
        footer={
          <div className="flex gap-2">
            <button
              onClick={() => setIsModalOpen(false)}
              className="px-3 py-1.5 rounded border border-slate-800 hover:bg-slate-800 text-slate-300 text-xs font-mono"
            >
              Cancel
            </button>
            <button
              onClick={handleCreate}
              className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
            >
              Confirm Target Registration
            </button>
          </div>
        }
      >
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">APPLICATION NAME</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Booking Portal API"
              required
              className="w-full px-3 py-2 bg-phantom-950 border border-slate-800 rounded text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">TARGET BASE URL (AUTHORIZED SCOPE)</label>
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:3000 or https://staging.example.com"
              required
              className="w-full px-3 py-2 bg-phantom-950 border border-slate-800 rounded text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">ENVIRONMENT TIER</label>
            <select
              value={envName}
              onChange={(e) => setEnvName(e.target.value)}
              className="w-full px-3 py-2 bg-phantom-950 border border-slate-800 rounded text-sm text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="sandbox">Sandbox</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">DESCRIPTION</label>
            <textarea
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              placeholder="Application purpose and architecture overview..."
              rows={3}
              className="w-full px-3 py-2 bg-phantom-950 border border-slate-800 rounded text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </form>
      </Modal>
    </div>
  );
};

