import React from "react";
import { Loader2 } from "lucide-react";

interface LoadingSpinnerProps {
  label?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ label = "Loading security intelligence..." }) => {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-slate-400 gap-3">
      <Loader2 className="w-7 h-7 animate-spin text-cyan-400" />
      <span className="text-xs font-mono tracking-wider">{label}</span>
    </div>
  );
};

