import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  CartesianGrid,
} from "recharts";
import { Server, AlertTriangle, ShieldCheck, Info } from "lucide-react";
import { ApplicationRiskResponse } from "../../types/dashboard";

interface ApplicationRiskChartProps {
  data?: ApplicationRiskResponse;
  isLoading?: boolean;
}

const TIER_COLORS: Record<string, string> = {
  CRITICAL: "#f43f5e",
  HIGH: "#f59e0b",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  CLEAN: "#10b981",
};

export const ApplicationRiskChart: React.FC<ApplicationRiskChartProps> = ({
  data,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 animate-pulse h-96 flex flex-col justify-between" />
    );
  }

  const applications = data?.top_exposed_applications || [];
  const tierDistribution = data?.risk_tier_distribution || {};

  const chartData = applications.map((app) => ({
    name: app.name.length > 18 ? `${app.name.substring(0, 15)}...` : app.name,
    fullName: app.name,
    openVulnerabilities: app.open_count,
    critical: app.critical_count,
    high: app.high_count,
    riskScore: app.risk_score,
    riskTier: app.risk_tier,
    color: TIER_COLORS[app.risk_tier] || "#3b82f6",
  }));

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex flex-col shadow-sm">
      <div className="flex flex-wrap items-center justify-between pb-3 border-b border-slate-800 gap-3">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Application Risk & Exposure Ranking</h3>
        </div>

        {/* Tier Badges */}
        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
          {Object.entries(tierDistribution).map(([tier, count]) => (
            <span
              key={tier}
              className="px-2 py-0.5 rounded border flex items-center gap-1.5"
              style={{
                borderColor: `${TIER_COLORS[tier] || "#64748b"}40`,
                backgroundColor: `${TIER_COLORS[tier] || "#64748b"}15`,
                color: TIER_COLORS[tier] || "#94a3b8",
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ backgroundColor: TIER_COLORS[tier] || "#94a3b8" }}
              />
              <span>{tier}: {count}</span>
            </span>
          ))}
        </div>
      </div>

      {applications.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center py-10 text-slate-500">
          <Info className="w-8 h-8 text-slate-600 mb-2" />
          <p className="text-xs">No registered target applications found.</p>
        </div>
      ) : (
        <div className="pt-4 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Bar Chart (7 Cols) */}
          <div className="lg:col-span-7 h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="name"
                  stroke="#64748b"
                  tick={{ fontSize: 10, fill: "#64748b" }}
                  interval={0}
                  angle={-15}
                  textAnchor="end"
                />
                <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: "#64748b" }} allowDecimals={false} />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const item = payload[0].payload;
                      return (
                        <div className="bg-slate-950 border border-slate-800 rounded p-2.5 text-xs shadow-lg font-mono">
                          <p className="font-semibold text-slate-100">{item.fullName}</p>
                          <p className="text-slate-400">Risk Tier: <span style={{ color: item.color }}>{item.riskTier}</span></p>
                          <p className="text-cyan-400">Open Vulnerabilities: {item.openVulnerabilities}</p>
                          <p className="text-rose-400">Critical: {item.critical} | High: {item.high}</p>
                          <p className="text-slate-500 text-[10px]">Base Risk Score: {item.riskScore}</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="openVulnerabilities" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Top Exposed Applications Table (5 Cols) */}
          <div className="lg:col-span-5 space-y-2 max-h-64 overflow-y-auto pr-1">
            <h4 className="text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wider font-mono">
              Most Exposed Assets
            </h4>
            {applications.slice(0, 5).map((app) => (
              <div
                key={app.application_id}
                className="bg-slate-950/70 border border-slate-800/80 rounded p-2.5 flex items-center justify-between text-xs hover:border-slate-700 transition-colors"
              >
                <div className="truncate mr-2">
                  <div className="flex items-center gap-1.5">
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ backgroundColor: TIER_COLORS[app.risk_tier] }}
                    />
                    <span className="font-medium text-slate-200 truncate">{app.name}</span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 truncate block mt-0.5">
                    {app.target_url}
                  </span>
                </div>
                <div className="text-right shrink-0 font-mono">
                  <span
                    className="px-1.5 py-0.5 rounded text-[10px] font-semibold"
                    style={{
                      backgroundColor: `${TIER_COLORS[app.risk_tier]}15`,
                      color: TIER_COLORS[app.risk_tier],
                    }}
                  >
                    {app.risk_tier}
                  </span>
                  <span className="block text-[11px] text-slate-400 mt-1">
                    {app.open_count} open ({app.critical_count} crit)
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

