import React from "react";
import { Link } from "react-router-dom";
import { ShieldCheck, User, LogOut, Radio } from "lucide-react";
import { useAuthStore } from "../../stores/authStore";

export const TopNav: React.FC = () => {
  const { userEmail, userRole, logout } = useAuthStore();

  return (
    <header className="h-16 bg-phantom-950/80 backdrop-blur border-b border-slate-800/80 px-6 flex items-center justify-between shrink-0">
      <div className="flex items-center gap-4">
        {/* Active Mode Pill */}
        <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span className="text-slate-400">MODE:</span>
          <span className="text-emerald-400 font-semibold">OBSERVE</span>
        </div>

        {/* Live Telemetry Ping */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-500 font-mono">
          <Radio className="w-3.5 h-3.5 text-cyan-400" />
          <span>DAST RUNTIME READY</span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* User profile dropdown / status */}
        <div className="flex items-center gap-3">
          <div className="text-right hidden sm:block">
            <span className="block text-xs font-medium text-slate-200">{userEmail || "sec-analyst@phantom.local"}</span>
            <span className="block text-[10px] font-mono text-cyan-400">{userRole || "SECURITY_ENGINEER"}</span>
          </div>
          <div className="p-2 rounded-full bg-slate-800 text-slate-300">
            <User className="w-4 h-4" />
          </div>
          <button
            onClick={logout}
            title="Log out"
            className="p-2 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};

