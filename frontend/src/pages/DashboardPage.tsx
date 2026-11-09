import React from "react";
import { Link } from "react-router-dom";
import { Server, Radar, ShieldAlert, CheckCircle2, ArrowUpRight, Plus, Terminal } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { StatCard } from "../components/common/StatCard";
import { SeverityBadge, StatusBadge } from "../components/common/Badge";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

export const DashboardPage: React.FC = () => {
  const severityData = [
    { name: "CRITICAL", count: 0, fill: "#f43f5e" },
    { name: "HIGH", count: 0, fill: "#f59e0b" },
    { name: "MEDIUM", count: 0, fill: "#eab308" },
    { name: "LOW", count: 0, fill: "#3b82f6" },
    { name: "INFO", count: 0, fill: "#64748b" },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Intelligence Command"
        description="Autonomous DAST telemetry, continuous reconnaissance, and attack graph verification."
        actions={
          <div className="flex gap-3">
            <Link
              to="/scans"
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Security Scan</span>
            </Link>
            <Link
              to="/playground"
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors border border-slate-700"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>PHANTOM Playground</span>
            </Link>
          </div>
        }
      />

      {/* Architecture Initialization Notice Banner */}
      <div className="bg-slate-900/60 border border-cyan-500/30 rounded-lg p-4 flex items-start gap-4">
        <div className="p-2 rounded bg-cyan-500/10 text-cyan-400 shrink-0">
          <Terminal className="w-5 h-5" />
        </div>
        <div className="text-xs">
          <h4 className="font-semibold text-slate-100 flex items-center gap-2">
            <span>PHANTOM-X Architecture Milestone Active</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              FOUNDATION READY
            </span>
          </h4>
          <p className="text-slate-400 mt-1 leading-relaxed">
            All database models, backend API routes, AI agent interfaces, safety policies, and frontend pages are established.
            Each of our four developers can implement their assigned modules independently.
          </p>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Target Applications"
          value="0"
          subtitle="Registered scope targets"
          icon={Server}
          trend="+0 this week"
          trendColor="slate"
        />
        <StatCard
          title="Active Scans"
          value="0"
          subtitle="Autonomous sessions"
          icon={Radar}
          trend="OBSERVE Mode"
          trendColor="cyan"
        />
        <StatCard
          title="Verified Findings"
          value="0"
          subtitle="Self-challenged proofs"
          icon={ShieldAlert}
          trend="0 False Positives"
          trendColor="emerald"
        />
        <StatCard
          title="Regression Pass Rate"
          value="100%"
          subtitle="Time-travel checks"
          icon={CheckCircle2}
          trend="Baseline active"
          trendColor="emerald"
        />
      </div>

      {/* Main Grid: Telemetry & Vulnerability Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Chart */}
        <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200">Severity Distribution</h3>
            <span className="text-xs font-mono text-slate-500">REAL FINDINGS</span>
          </div>
          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0b0f17", borderColor: "#1e293b", fontSize: "12px" }}
                  itemStyle={{ color: "#f1f5f9" }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Feature Ownership Matrix */}
        <div className="lg:col-span-2 bg-phantom-900 border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-200">Team Feature Ownership Roadmap</h3>
            <span className="text-xs font-mono text-slate-500">4 MEMBERS</span>
          </div>

          <div className="space-y-3">
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400 font-semibold">MEMBER 1</span>
                <h4 className="text-sm text-slate-200 font-medium">Application Intelligence</h4>
                <p className="text-xs text-slate-500">Behavioral Digital Twin, API Endpoint Discovery & Role Mapping</p>
              </div>
              <Link to="/discovery" className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 font-mono">
                <span>View</span> <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400 font-semibold">MEMBER 2</span>
                <h4 className="text-sm text-slate-200 font-medium">Autonomous Attack Intelligence</h4>
                <p className="text-xs text-slate-500">Counterfactual Attack Lab, Attack Chains & Business Logic Scenarios</p>
              </div>
              <Link to="/attack-chains" className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 font-mono">
                <span>View</span> <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400 font-semibold">MEMBER 3</span>
                <h4 className="text-sm text-slate-200 font-medium">Security Testing & Proof</h4>
                <p className="text-xs text-slate-500">Controlled Execution, IDOR/BOLA Checks & Self-Challenging Proof Engine</p>
              </div>
              <Link to="/evidence" className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 font-mono">
                <span>View</span> <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400 font-semibold">MEMBER 4</span>
                <h4 className="text-sm text-slate-200 font-medium">Security Operations & Intelligence</h4>
                <p className="text-xs text-slate-500">Time-Travel Regression, Executive Reporting & Scope Safety Policy</p>
              </div>
              <Link to="/regression" className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 font-mono">
                <span>View</span> <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

