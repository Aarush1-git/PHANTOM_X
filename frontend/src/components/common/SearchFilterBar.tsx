import React, { ReactNode } from "react";
import { Search } from "lucide-react";

interface SearchFilterBarProps {
  searchQuery: string;
  onSearchChange: (val: string) => void;
  placeholder?: string;
  children?: ReactNode;
}

export const SearchFilterBar: React.FC<SearchFilterBarProps> = ({
  searchQuery,
  onSearchChange,
  placeholder = "Search resources...",
  children,
}) => {
  return (
    <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 mb-5">
      <div className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder={placeholder}
          className="w-full pl-9 pr-4 py-2 bg-phantom-900 border border-slate-800 rounded text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
        />
      </div>
      {children && <div className="flex items-center gap-3">{children}</div>}
    </div>
  );
};

