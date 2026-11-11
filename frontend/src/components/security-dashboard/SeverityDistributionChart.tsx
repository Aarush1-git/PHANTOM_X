import React from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { Shield, Info } from "lucide-react";
import { SeverityDistributionResponse } from "../../types/dashboard";

interface SeverityDistributionChartProps {
  data?: SeverityDistributionResponse;
  isLoading?: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#f43f5e",
  HIGH: "#f59e0b",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  INFO: "#64748b",
};

export const SeverityDistributionChart: React.FC<SeverityDistributionChartProps> = ({
  data,
  isLoading = false,
}) => {
  if (isLoading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 animate-pulse h-80 flex flex-col justify-between" />
    );
  }

  const chartData = (data?.distribution || [])
    .filter((d) => d.count > 0)
    .map((d) => ({
      name: d.severity,
      value: d.count,
      percentage: d.percentage,
      open: d.open_count,
      fixed: d.fixed_count,
      color: SEVERITY_COLORS[d.severity] || "#64748b",
    }));

  const total = data?.total || 0;

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-5 flex flex-col h-full shadow-sm">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Severity Distribution</h3>
        </div>
        <span className="text-xs font-mono text-slate-400">Total: {total}</span>
      </div>

      {total === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center py-10 text-slate-500">
          <Info className="w-8 h-8 text-slate-600 mb-2" />
          <p className="text-xs">No vulnerabilities recorded for this scope.</p>
        </div>
      ) : (
        <div className="flex-1 flex flex-col sm:flex-row items-center justify-between gap-4 pt-3">
          {/* Donut Chart */}
          <div className="w-full sm:w-1/2 h-52 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const item = payload[0].payload;
                      return (
                        <div className="bg-slate-950 border border-slate-800 rounded p-2 text-xs shadow-lg font-mono">
                          <p className="font-semibold text-slate-200">{item.name}</p>
                          <p className="text-slate-400">Count: {item.value} ({item.percentage}%)</p>
                          <p className="text-emerald-400">Fixed: {item.fixed} | Open: {item.open}</p>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-xl font-bold font-mono text-slate-100">{total}</span>
              <span className="text-[10px] uppercase font-mono text-slate-500">Findings</span>
            </div>
          </div>

          {/* Detailed Severity List Legend */}
          <div className="w-full sm:w-1/2 space-y-2">
            {(data?.distribution || []).map((item) => (
              <div
                key={item.severity}
                className="flex items-center justify-between text-xs py-1 px-2 rounded bg-slate-950/60 border border-slate-800/60"
              >
                <div className="flex items-center gap-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: SEVERITY_COLORS[item.severity] || "#64748b" }}
                  />
                  <span className="font-mono text-slate-300 font-medium">{item.severity}</span>
                </div>
                <div className="flex items-center gap-3 font-mono">
                  <span className="text-slate-400">{item.count}</span>
                  <span className="text-[10px] text-slate-500 w-10 text-right">{item.percentage}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
