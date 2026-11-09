import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, Lock, Mail, ArrowRight } from "lucide-react";
import { useAuthStore } from "../stores/authStore";

export const LoginPage: React.FC = () => {
  const [email, setEmail] = useState("admin@phantom-x.local");
  const [password, setPassword] = useState("admin123");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const setAuth = useAuthStore((state) => state.setAuth);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      // In initialization, authenticate with mock / dev token
      setAuth("mock-jwt-token-phantom-x", email, "ADMIN");
      navigate("/");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-phantom-950 flex flex-col items-center justify-center p-4">
      <div className="max-w-md w-full bg-phantom-900 border border-slate-800 rounded-lg p-8 shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-mono text-xl font-bold tracking-wider text-slate-100">PHANTOM-X</h1>
            <p className="text-xs text-slate-400 font-mono">The application that investigates itself.</p>
          </div>
        </div>

        <div className="mb-6 bg-slate-900/80 border border-slate-800 p-3 rounded text-xs text-slate-400">
          <span className="text-emerald-400 font-mono font-medium">DAST Operator Sign-In</span>
          <p className="mt-1">Enter your authorized operator credentials to access scan telemetry and security attack graphs.</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">OPERATOR EMAIL</label>
            <div className="relative">
              <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full pl-9 pr-4 py-2 bg-phantom-950 border border-slate-800 rounded text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1">PASSWORD / ACCESS KEY</label>
            <div className="relative">
              <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full pl-9 pr-4 py-2 bg-phantom-950 border border-slate-800 rounded text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 py-2 px-4 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold rounded text-sm flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
          >
            <span>{isLoading ? "Authenticating..." : "Authenticate Session"}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="mt-6 pt-4 border-t border-slate-800/80 text-center">
          <p className="text-[11px] text-slate-500 font-mono">
            PHANTOM-X Autonomous Security Intelligence v0.1.0
          </p>
        </div>
      </div>
    </div>
  );
};

