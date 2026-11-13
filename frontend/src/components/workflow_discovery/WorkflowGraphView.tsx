import React, { useMemo } from "react";
import {
  ReactFlow,
  Controls,
  Background,
  BackgroundVariant,
  Node,
  Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { WorkflowGraph, StepType } from "../../types/workflow";

interface WorkflowGraphViewProps {
  graph: WorkflowGraph;
  workflowName?: string;
}

export const WorkflowGraphView: React.FC<WorkflowGraphViewProps> = ({
  graph,
  workflowName,
}) => {
  const { nodes, edges } = useMemo(() => {
    if (!graph || !graph.nodes || graph.nodes.length === 0) {
      return { nodes: [], edges: [] };
    }

    // Layout nodes horizontally or in grid
    const nodeList: Node[] = graph.nodes.map((nodeData, idx) => {
      let borderColor = "#38bdf8"; // default cyan
      let badgeBg = "bg-cyan-950/80 text-cyan-400 border-cyan-800";

      if (nodeData.step_type === "ENTRY") {
        borderColor = "#34d399"; // emerald
        badgeBg = "bg-emerald-950/80 text-emerald-400 border-emerald-800";
      } else if (nodeData.step_type === "TERMINAL") {
        borderColor = "#60a5fa"; // blue
        badgeBg = "bg-blue-950/80 text-blue-400 border-blue-800";
      } else if (nodeData.step_type === "DROPOUT") {
        borderColor = "#f59e0b"; // amber
        badgeBg = "bg-amber-950/80 text-amber-400 border-amber-800";
      }

      const xPos = 60 + idx * 240;
      const yPos = 100 + (idx % 2) * 50;

      return {
        id: nodeData.id,
        position: { x: xPos, y: yPos },
        data: {
          label: (
            <div className="space-y-1 text-left font-mono">
              <div className="flex items-center justify-between gap-2">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${badgeBg}`}>
                  {nodeData.step_type}
                </span>
                <span className="text-[10px] text-slate-400 font-bold">
                  {nodeData.method}
                </span>
              </div>
              <div className="text-xs font-semibold text-slate-100 truncate max-w-[180px]" title={nodeData.normalized_path}>
                {nodeData.normalized_path}
              </div>
              <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1 border-t border-slate-800">
                <span>{nodeData.avg_latency_ms}ms</span>
                <span>Err: {Math.round(nodeData.error_rate * 100)}%</span>
              </div>
            </div>
          ),
        },
        style: {
          background: "#0b0f17",
          border: `1.5px solid ${borderColor}`,
          borderRadius: "8px",
          padding: "10px",
          width: 200,
          boxShadow: `0 4px 14px rgba(0, 0, 0, 0.4)`,
        },
      };
    });

    const edgeList: Edge[] = (graph.edges || []).map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: `${Math.round(e.probability * 100)}% (${e.transition_count})`,
      type: "smoothstep",
      animated: e.probability > 0.5,
      markerEnd: {
        type: MarkerType.ArrowClosed,
        width: 16,
        height: 16,
        color: "#38bdf8",
      },
      style: {
        stroke: e.probability > 0.5 ? "#38bdf8" : "#64748b",
        strokeWidth: e.probability > 0.5 ? 2 : 1.2,
      },
      labelStyle: {
        fill: "#38bdf8",
        fontWeight: 700,
        fontSize: "10px",
        fontFamily: "monospace",
      },
      labelBgStyle: {
        fill: "#0b0f17",
        fillOpacity: 0.9,
        stroke: "#1e293b",
      },
    }));

    return { nodes: nodeList, edges: edgeList };
  }, [graph]);

  if (!graph || !graph.nodes || graph.nodes.length === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center border border-slate-800 rounded-lg bg-slate-900/40 text-slate-500 font-mono text-xs">
        <span>No graph nodes available for this workflow.</span>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {workflowName && (
        <div className="text-xs font-mono text-slate-300 font-semibold px-1">
          {workflowName}
        </div>
      )}
      <div className="h-[360px] w-full border border-slate-800 rounded-lg overflow-hidden bg-slate-950 relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          attributionPosition="bottom-right"
        >
          <Background color="#1e293b" gap={16} variant={BackgroundVariant.Dots} />
          <Controls className="bg-slate-900 border border-slate-700 fill-slate-300" />
        </ReactFlow>
      </div>
    </div>
  );
};
