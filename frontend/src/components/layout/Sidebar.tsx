import React from "react";
import { NavLink } from "react-router-dom";
import {
  ShieldAlert,
  LayoutDashboard,
  Server,
  Compass,
  Radar,
  GitCompare,
  Bug,
  GitFork,
  FileSearch,
  History,
  FileText,
  Terminal,
  Settings,
  ScrollText,
  Wrench,
} from "lucide-react";

export const Sidebar: React.FC = () => {
  const navItems = [
    { label: "Dashboard", path: "/", icon: LayoutDashboard },
    { label: "Applications", path: "/applications", icon: Server },
    { label: "API Discovery", path: "/discovery", icon: Compass },
    { label: "Security Scans", path: "/scans", icon: Radar },
    { label: "Scan History & Diff", path: "/scan-history", icon: GitCompare },
    { label: "Vulnerabilities", path: "/vulnerabilities", icon: Bug },
    { label: "Attack Chains", path: "/attack-chains", icon: GitFork },
    { label: "Evidence Explorer", path: "/evidence", icon: FileSearch },
    { label: "Time-Travel Regression", path: "/time-travel", icon: History },
    { label: "Reports", path: "/reports", icon: FileText },
    { label: "Remediation", path: "/remediation", icon: Wrench },
    { label: "Playground", path: "/playground", icon: Terminal },
    { label: "Settings & Scope", path: "/settings", icon: Settings },
    { label: "Audit Logs", path: "/audit-logs", icon: ScrollText },
  ];

  return (
    <aside className="w-64 bg-phantom-950 border-r border-slate-800/80 flex flex-col shrink-0 select-none">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-6 border-b border-slate-800/80 gap-3">
        <div className="p-1.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
          <ShieldAlert className="w-5 h-5" />
        </div>
        <div>
          <span className="font-mono font-bold tracking-wider text-base text-slate-100">PHANTOM-X</span>
          <span className="block text-[10px] text-slate-500 tracking-tight font-mono">AUTONOMOUS DAST</span>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded text-sm font-medium transition-colors ${
                  isActive
                    ? "bg-slate-800/80 text-cyan-400 border-l-2 border-cyan-400"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Safety Badge Footer */}
      <div className="p-4 border-t border-slate-800/80 bg-phantom-900/30">
        <div className="flex items-center justify-between text-xs">
          <span className="text-slate-500 font-mono">SAFETY ENGINE</span>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            ENFORCED
          </span>
        </div>
        <p className="text-[11px] text-slate-500 mt-1">Authorized scope verification active.</p>
      </div>
    </aside>
  );
};

