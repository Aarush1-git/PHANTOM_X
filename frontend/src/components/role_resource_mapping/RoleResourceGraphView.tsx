import React, { useMemo, useState } from "react";
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
import { Key, Database, Globe, User, Shield, Info, ExternalLink } from "lucide-react";
import { RoleResourceMapping } from "../../types/roleResource";

interface RoleResourceGraphViewProps {
  mappings: RoleResourceMapping[];
  onSelectMapping?: (mapping: RoleResourceMapping) => void;
}

export const RoleResourceGraphView: React.FC<RoleResourceGraphViewProps> = ({
  mappings,
  onSelectMapping,
}) => {
  const [selectedElement, setSelectedElement] = useState<{
    type: "node" | "edge";
    id: string;
    details: any;
  } | null>(null);

  const { nodes, edges } = useMemo(() => {
    if (!mappings || mappings.length === 0) {
      return { nodes: [], edges: [] };
    }

    const nodeMap = new Map<string, { id: string; label: string; type: string; details: any }>();
    const edgeList: Edge[] = [];

    mappings.forEach((m) => {
      // 1. Subject Node
      const subjectKey = `${m.subject_type}:${m.subject_name}`;
      if (!nodeMap.has(subjectKey)) {
        nodeMap.set(subjectKey, {
          id: subjectKey,
          label: m.subject_name,
          type: m.subject_type,
          details: {
            name: m.subject_name,
            type: m.subject_type,
            id: m.subject_id,
          },
        });
      }

      // 2. Object Node
      const objectKey = `${m.object_type}:${m.object_name}`;
      if (!nodeMap.has(objectKey)) {
        nodeMap.set(objectKey, {
          id: objectKey,
          label: m.object_name,
          type: m.object_type,
          details: {
            name: m.object_name,
            type: m.object_type,
            id: m.object_id,
          },
        });
      }

      // 3. Edge styling by Provenance
      let strokeColor = "#38bdf8"; // cyan for OBSERVED
      let strokeDasharray: string | undefined = undefined;
      let isAnimated = false;

      if (m.evidence_source === "DECLARED") {
        strokeColor = "#34d399"; // emerald
      } else if (m.evidence_source === "INFERRED") {
        strokeColor = "#a855f7"; // purple
        strokeDasharray = "5 5";
      } else {
        isAnimated = m.confidence_score >= 0.7;
      }

      const edgeId = `edge-${m.id}`;
      edgeList.push({
        id: edgeId,
        source: subjectKey,
        target: objectKey,
        label: `${m.relationship_type.replace(/_/g, " ")} (${Math.round(m.confidence_score * 100)}%)`,
        type: "smoothstep",
        animated: isAnimated,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          width: 14,
          height: 14,
          color: strokeColor,
        },
        style: {
          stroke: strokeColor,
          strokeWidth: m.confidence_score >= 0.8 ? 2 : 1.2,
          strokeDasharray,
        },
        labelStyle: {
          fill: strokeColor,
          fontWeight: 600,
          fontSize: "9px",
          fontFamily: "monospace",
        },
        labelBgStyle: {
          fill: "#0b0f17",
          fillOpacity: 0.9,
          stroke: "#1e293b",
        },
        data: { mapping: m },
      });
    });

    // Layout nodes into organized concentric/layered positions
    const nodeList: Node[] = [];
    const nodeArray = Array.from(nodeMap.values());

    const roles = nodeArray.filter((n) => n.type === "ROLE");
    const identities = nodeArray.filter((n) => n.type === "IDENTITY");
    const resources = nodeArray.filter((n) => n.type === "RESOURCE");
    const endpoints = nodeArray.filter((n) => n.type === "ENDPOINT");

    const layoutGroup = (group: typeof nodeArray, startX: number, startY: number, stepY: number) => {
      group.forEach((item, idx) => {
        let borderColor = "#38bdf8";
        let badgeColor = "bg-cyan-950/80 text-cyan-400 border-cyan-800";
        let IconComponent = Key;

        if (item.type === "ROLE") {
          borderColor = "#c084fc"; // purple
          badgeColor = "bg-purple-950/80 text-purple-300 border-purple-800";
          IconComponent = Key;
        } else if (item.type === "RESOURCE") {
          borderColor = "#fbbf24"; // amber
          badgeColor = "bg-amber-950/80 text-amber-300 border-amber-800";
          IconComponent = Database;
        } else if (item.type === "ENDPOINT") {
          borderColor = "#38bdf8"; // sky
          badgeColor = "bg-sky-950/80 text-sky-300 border-sky-800";
          IconComponent = Globe;
        } else if (item.type === "IDENTITY") {
          borderColor = "#34d399"; // emerald
          badgeColor = "bg-emerald-950/80 text-emerald-300 border-emerald-800";
          IconComponent = User;
        }

        nodeList.push({
          id: item.id,
          position: { x: startX, y: startY + idx * stepY },
          data: {
            label: (
              <div className="space-y-1 text-left font-mono">
                <div className="flex items-center justify-between gap-1">
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${badgeColor}`}>
                    {item.type}
                  </span>
                  <IconComponent className="w-3 h-3 text-slate-400" />
                </div>
                <div className="text-xs font-semibold text-slate-100 truncate max-w-[170px]" title={item.label}>
                  {item.label}
                </div>
              </div>
            ),
            raw: item,
          },
          style: {
            background: "#0b0f17",
            border: `1.5px solid ${borderColor}`,
            borderRadius: "8px",
            padding: "8px 10px",
            width: 190,
            boxShadow: "0 4px 14px rgba(0, 0, 0, 0.4)",
          },
        });
      });
    };

    layoutGroup(identities, 40, 60, 90);
    layoutGroup(roles, 280, 60, 90);
    layoutGroup(resources, 540, 60, 90);
    layoutGroup(endpoints, 800, 60, 85);

    return { nodes: nodeList, edges: edgeList };
  }, [mappings]);

  const handleNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedElement({
      type: "node",
      id: node.id,
      details: node.data?.raw,
    });
  };

  const handleEdgeClick = (_: React.MouseEvent, edge: Edge) => {
    if (edge.data?.mapping) {
      const mapping = edge.data.mapping as RoleResourceMapping;
      setSelectedElement({
        type: "edge",
        id: edge.id,
        details: mapping,
      });
      if (onSelectMapping) {
        onSelectMapping(mapping);
      }
    }
  };

  if (!mappings || mappings.length === 0) {
    return (
      <div className="h-72 flex flex-col items-center justify-center border border-slate-800 rounded-lg bg-slate-900/40 text-slate-500 font-mono text-xs space-y-2">
        <Shield className="w-8 h-8 text-slate-600" />
        <span>No relationship mappings available to render graph.</span>
        <span className="text-[11px] text-slate-600">Run a discovery mode to discover roles and resources.</span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Visual Legend */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900/80 border border-slate-800 rounded-lg text-xs font-mono">
        <div className="flex items-center gap-4">
          <span className="text-slate-400 font-semibold">Nodes:</span>
          <span className="flex items-center gap-1.5 text-purple-300">
            <span className="w-2.5 h-2.5 rounded bg-purple-500/30 border border-purple-400" />
            <span>Role</span>
          </span>
          <span className="flex items-center gap-1.5 text-amber-300">
            <span className="w-2.5 h-2.5 rounded bg-amber-500/30 border border-amber-400" />
            <span>Resource</span>
          </span>
          <span className="flex items-center gap-1.5 text-sky-300">
            <span className="w-2.5 h-2.5 rounded bg-sky-500/30 border border-sky-400" />
            <span>Endpoint</span>
          </span>
          <span className="flex items-center gap-1.5 text-emerald-300">
            <span className="w-2.5 h-2.5 rounded bg-emerald-500/30 border border-emerald-400" />
            <span>Identity</span>
          </span>
        </div>

        <div className="flex items-center gap-4">
          <span className="text-slate-400 font-semibold">Edges:</span>
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="w-4 h-0.5 bg-emerald-400" />
            <span>Declared</span>
          </span>
          <span className="flex items-center gap-1.5 text-cyan-400">
            <span className="w-4 h-0.5 bg-cyan-400" />
            <span>Observed</span>
          </span>
          <span className="flex items-center gap-1.5 text-purple-400">
            <span className="w-4 h-0.5 border-t border-dashed border-purple-400" />
            <span>Inferred</span>
          </span>
        </div>
      </div>

      {/* Main Flow Canvas */}
      <div className="h-[460px] w-full border border-slate-800 rounded-lg overflow-hidden bg-slate-950 relative">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodeClick={handleNodeClick}
          onEdgeClick={handleEdgeClick}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          attributionPosition="bottom-right"
        >
          <Background color="#1e293b" gap={18} variant={BackgroundVariant.Dots} />
          <Controls className="bg-slate-900 border border-slate-700 fill-slate-300" />
        </ReactFlow>
      </div>

      {/* Selected Element Quick Inspector */}
      {selectedElement && (
        <div className="p-3.5 bg-slate-900 border border-slate-800 rounded-lg space-y-2 text-xs font-mono">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Info className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-slate-300 font-semibold">
                Selected {selectedElement.type === "node" ? "Node" : "Relationship"}
              </span>
            </div>
            <button
              onClick={() => setSelectedElement(null)}
              className="text-slate-500 hover:text-slate-300 text-[11px]"
            >
              Dismiss
            </button>
          </div>

          {selectedElement.type === "node" ? (
            <div className="flex items-center gap-4 text-slate-400">
              <div>
                <span className="text-slate-500">Name: </span>
                <span className="text-slate-200 font-bold">{selectedElement.details?.name}</span>
              </div>
              <div>
                <span className="text-slate-500">Type: </span>
                <span className="text-slate-200">{selectedElement.details?.type}</span>
              </div>
            </div>
          ) : (
            <div className="space-y-1.5">
              <div className="flex items-center gap-4 text-slate-400">
                <div>
                  <span className="text-slate-500">Relationship: </span>
                  <span className="text-cyan-400 font-bold">
                    {selectedElement.details?.relationship_type}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Source: </span>
                  <span className="text-slate-200">
                    {selectedElement.details?.evidence_source}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Confidence: </span>
                  <span className="text-emerald-400">
                    {Math.round((selectedElement.details?.confidence_score || 0) * 100)}%
                  </span>
                </div>
              </div>
              <div className="text-[11px] text-slate-400">
                {selectedElement.details?.subject_name} &rarr; {selectedElement.details?.object_name}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
