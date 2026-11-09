import React, { useState } from "react";
import { GitFork, ShieldAlert, ArrowRight, Zap } from "lucide-react";
import { PageHeader } from "../components/common/PageHeader";
import { SeverityBadge } from "../components/common/Badge";
import {
  ReactFlow,
  Background,
  Controls,
  Node,
  Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

export const AttackChainsPage: React.FC = () => {
  const initialNodes: Node[] = [
    {
      id: "1",
      position: { x: 50, y: 100 },
      data: { label: "1. Information Disclosure (/api/v1/meta)" },
      style: { background: "#0b0f17", color: "#f1f5f9", border: "1px solid #1e293b", borderRadius: "8px", padding: "10px", fontSize: "12px", fontFamily: "monospace" },
    },
    {
      id: "2",
      position: { x: 350, y: 100 },
      data: { label: "2. BOLA Horizontal Escalation (/api/v1/users/{id})" },
      style: { background: "#0b0f17", color: "#f59e0b", border: "1px solid #f59e0b", borderRadius: "8px", padding: "10px", fontSize: "12px", fontFamily: "monospace" },
    },
    {
      id: "3",
      position: { x: 700, y: 100 },
      data: { label: "3. Tenant Takeover / Privilege Escalation" },
      style: { background: "#0b0f17", color: "#f43f5e", border: "1px solid #f43f5e", borderRadius: "8px", padding: "10px", fontSize: "12px", fontFamily: "monospace" },
    },
  ];

  const initialEdges: Edge[] = [
    {
      id: "e1-2",
      source: "1",
      target: "2",
      label: "Leaked Tenant IDs",
      animated: true,
      style: { stroke: "#06b6d4" },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#06b6d4" },
    },
    {
      id: "e2-3",
      source: "2",
      target: "3",
      label: "Session Impersonation",
      animated: true,
      style: { stroke: "#f43f5e" },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#f43f5e" },
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Chain Intelligence (Member 2)"
        description="Autonomous multi-stage exploit paths synthesized by connecting discrete vulnerabilities."
        badge={<SeverityBadge severity="CRITICAL" />}
      />

      <div className="bg-phantom-900 border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Attack Graph: Tenant Impersonation Chain</h3>
            <p className="text-xs text-slate-400">Stepwise visualization of correlated vulnerability progression.</p>
          </div>
          <span className="px-2.5 py-1 rounded text-xs font-mono bg-rose-500/10 text-rose-400 border border-rose-500/30">
            CHAIN SEVERITY: CRITICAL
          </span>
        </div>

        <div className="h-96 w-full rounded border border-slate-800/80 bg-phantom-950 overflow-hidden">
          <ReactFlow nodes={initialNodes} edges={initialEdges} fitView>
            <Background color="#1e293b" gap={16} />
            <Controls className="bg-slate-900 border border-slate-800 text-slate-200" />
          </ReactFlow>
        </div>
      </div>
    </div>
  );
};

