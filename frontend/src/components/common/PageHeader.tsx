import React, { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  description?: string;
  actions?: ReactNode;
  badge?: ReactNode;
}

export const PageHeader: React.FC<PageHeaderProps> = ({ title, description, actions, badge }) => {
  return (
    <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-6 border-b border-slate-800/80 mb-6 gap-4">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold tracking-tight text-slate-100">{title}</h1>
          {badge}
        </div>
        {description && <p className="text-sm text-slate-400 mt-1">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-3">{actions}</div>}
    </div>
  );
};

