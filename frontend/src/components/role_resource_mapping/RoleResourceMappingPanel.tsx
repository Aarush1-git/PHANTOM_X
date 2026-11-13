import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  Layers,
  Network,
  AlertTriangle,
  RefreshCw,
  GitCompare,
  Database,
  Activity,
} from "lucide-react";
import { roleResourceApi } from "../../services/roleResourceApi";
import { RoleResourceMapping } from "../../types/roleResource";
import { RoleResourceOverviewComponent } from "./RoleResourceOverview";
import { RoleResourceGraphView } from "./RoleResourceGraphView";
import { MappingExplorer } from "./MappingExplorer";
import { DiscrepancyInspector } from "./DiscrepancyInspector";
import { RolesResourcesView } from "./RolesResourcesView";
import { EvidenceDetailModal } from "./EvidenceDetailModal";

interface RoleResourceMappingPanelProps {
  applicationId: string;
}

type TabType = "overview" | "graph" | "explorer" | "discrepancies" | "entities";

export const RoleResourceMappingPanel: React.FC<RoleResourceMappingPanelProps> = ({
  applicationId,
}) => {
  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const queryClient = useQueryClient();

  // Mapping Explorer filters & pagination
  const [page, setPage] = useState(1);
  const [subjectTypeFilter, setSubjectTypeFilter] = useState("");
  const [objectTypeFilter, setObjectTypeFilter] = useState("");
  const [relationshipTypeFilter, setRelationshipTypeFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [minConfidenceFilter, setMinConfidenceFilter] = useState(0);

  // Discrepancy category filter
  const [discrepancyCategory, setDiscrepancyCategory] = useState("");

  // Inspect Modal
  const [inspectMapping, setInspectMapping] = useState<RoleResourceMapping | null>(null);

  // Last discovery status notification
  const [lastDiscoveryStatus, setLastDiscoveryStatus] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  // 1. Fetch Overview
  const {
    data: overview,
    isLoading: loadingOverview,
    error: overviewError,
    refetch: refetchOverview,
  } = useQuery({
    queryKey: ["roleResourceOverview", applicationId],
    queryFn: () => roleResourceApi.getOverview(applicationId),
    enabled: !!applicationId,
  });

  // 2. Fetch Paginated Mappings for Explorer
  const {
    data: mappingsData,
    isLoading: loadingMappings,
    error: mappingsError,
  } = useQuery({
    queryKey: [
      "roleResourceMappings",
      applicationId,
      page,
      subjectTypeFilter,
      objectTypeFilter,
      relationshipTypeFilter,
      sourceFilter,
      statusFilter,
      minConfidenceFilter,
    ],
    queryFn: () =>
      roleResourceApi.listMappings(applicationId, {
        page,
        page_size: 15,
        subject_type: subjectTypeFilter || undefined,
        object_type: objectTypeFilter || undefined,
        relationship_type: relationshipTypeFilter || undefined,
        evidence_source: sourceFilter || undefined,
        status: statusFilter || undefined,
        min_confidence: minConfidenceFilter > 0 ? minConfidenceFilter : undefined,
      }),
    enabled: !!applicationId,
  });

  // 3. Fetch Full Mappings for Graph
  const { data: graphMappingsData } = useQuery({
    queryKey: ["roleResourceGraphMappings", applicationId],
    queryFn: () =>
      roleResourceApi.listMappings(applicationId, {
        page: 1,
        page_size: 100,
      }),
    enabled: !!applicationId,
  });

  // 4. Fetch Discrepancies
  const {
    data: discrepancyData,
    isLoading: loadingDiscrepancies,
  } = useQuery({
    queryKey: ["roleResourceDiscrepancies", applicationId, discrepancyCategory],
    queryFn: () =>
      roleResourceApi.getDiscrepancies(applicationId, discrepancyCategory || undefined),
    enabled: !!applicationId,
  });

  // 5. Fetch Roles
  const { data: rolesData, isLoading: loadingRoles } = useQuery({
    queryKey: ["roleResourceRoles", applicationId],
    queryFn: () => roleResourceApi.getRoles(applicationId),
    enabled: !!applicationId,
  });

  // 6. Fetch Resources
  const { data: resourcesData, isLoading: loadingResources } = useQuery({
    queryKey: ["roleResourceResources", applicationId],
    queryFn: () => roleResourceApi.getResources(applicationId),
    enabled: !!applicationId,
  });

  // Discovery Mutation
  const discoveryMutation = useMutation({
    mutationFn: async (mode: string) => {
      if (mode === "ALL") {
        return await roleResourceApi.triggerDiscovery(applicationId, { mode: "ALL" });
      }
      const modeKey = mode.toLowerCase() as "declared" | "observed" | "structural" | "overlap";
      return await roleResourceApi.triggerDiscoveryMode(applicationId, modeKey);
    },
    onSuccess: (result) => {
      setLastDiscoveryStatus({
        success: true,
        message: `Discovery completed: Discovered ${result.discovered_mappings_count} mappings (${result.declared_mappings_count} declared, ${result.observed_mappings_count} observed, ${result.inferred_mappings_count} inferred).`,
      });
      queryClient.invalidateQueries({ queryKey: ["roleResourceOverview", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["roleResourceMappings", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["roleResourceGraphMappings", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["roleResourceDiscrepancies", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["roleResourceRoles", applicationId] });
      queryClient.invalidateQueries({ queryKey: ["roleResourceResources", applicationId] });
    },
    onError: (err: any) => {
      setLastDiscoveryStatus({
        success: false,
        message: `Discovery failed: ${err.message || "Unknown error"}`,
      });
    },
  });

  const handleTriggerDiscovery = (mode: string) => {
    discoveryMutation.mutate(mode);
  };

  if (loadingOverview && !overview) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-8 flex items-center justify-center gap-2 text-xs font-mono text-slate-400">
        <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
        <span>Loading Role &amp; Resource Relationship Mapping telemetry...</span>
      </div>
    );
  }

  if (overviewError) {
    return (
      <div className="bg-slate-900 border border-red-900/40 rounded-lg p-6 flex items-start gap-3 font-mono">
        <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-xs">
          <div className="font-semibold text-red-300">
            Failed to load Role &amp; Resource Mapping data
          </div>
          <div className="text-slate-400">
            Please verify network connectivity or check if application exists.
          </div>
          <button
            onClick={() => refetchOverview()}
            className="mt-2 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px]"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Sub-tab Navigation */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab("overview")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            activeTab === "overview"
              ? "bg-cyan-600/20 text-cyan-400 border border-cyan-800/60 font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Overview</span>
        </button>

        <button
          onClick={() => setActiveTab("graph")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            activeTab === "graph"
              ? "bg-cyan-600/20 text-cyan-400 border border-cyan-800/60 font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Relationship Graph</span>
        </button>

        <button
          onClick={() => setActiveTab("explorer")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            activeTab === "explorer"
              ? "bg-cyan-600/20 text-cyan-400 border border-cyan-800/60 font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Mapping Explorer</span>
        </button>

        <button
          onClick={() => setActiveTab("discrepancies")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            activeTab === "discrepancies"
              ? "bg-cyan-600/20 text-cyan-400 border border-cyan-800/60 font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
          }`}
        >
          <GitCompare className="w-3.5 h-3.5" />
          <span>Declared vs. Observed</span>
        </button>

        <button
          onClick={() => setActiveTab("entities")}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            activeTab === "entities"
              ? "bg-cyan-600/20 text-cyan-400 border border-cyan-800/60 font-semibold"
              : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Roles &amp; Resources</span>
        </button>
      </div>

      {/* Tab Panels */}
      {activeTab === "overview" && overview && (
        <RoleResourceOverviewComponent
          overview={overview}
          isDiscovering={discoveryMutation.isPending}
          onTriggerDiscovery={handleTriggerDiscovery}
          lastDiscoveryStatus={lastDiscoveryStatus}
        />
      )}

      {activeTab === "graph" && (
        <RoleResourceGraphView
          mappings={graphMappingsData?.items || []}
          onSelectMapping={(m) => setInspectMapping(m)}
        />
      )}

      {activeTab === "explorer" && (
        <MappingExplorer
          mappings={mappingsData?.items || []}
          total={mappingsData?.total || 0}
          page={page}
          pageSize={15}
          onPageChange={setPage}
          subjectTypeFilter={subjectTypeFilter}
          onSubjectTypeFilterChange={(val) => {
            setSubjectTypeFilter(val);
            setPage(1);
          }}
          objectTypeFilter={objectTypeFilter}
          onObjectTypeFilterChange={(val) => {
            setObjectTypeFilter(val);
            setPage(1);
          }}
          relationshipTypeFilter={relationshipTypeFilter}
          onRelationshipTypeFilterChange={(val) => {
            setRelationshipTypeFilter(val);
            setPage(1);
          }}
          sourceFilter={sourceFilter}
          onSourceFilterChange={(val) => {
            setSourceFilter(val);
            setPage(1);
          }}
          statusFilter={statusFilter}
          onStatusFilterChange={(val) => {
            setStatusFilter(val);
            setPage(1);
          }}
          minConfidenceFilter={minConfidenceFilter}
          onMinConfidenceFilterChange={(val) => {
            setMinConfidenceFilter(val);
            setPage(1);
          }}
          onInspectMapping={(m) => setInspectMapping(m)}
          isLoading={loadingMappings}
        />
      )}

      {activeTab === "discrepancies" && (
        <DiscrepancyInspector
          discrepancyData={discrepancyData || null}
          selectedCategory={discrepancyCategory}
          onSelectCategory={setDiscrepancyCategory}
          onInspectMapping={(m) => setInspectMapping(m)}
          isLoading={loadingDiscrepancies}
        />
      )}

      {activeTab === "entities" && (
        <RolesResourcesView
          roles={rolesData?.items || []}
          resources={resourcesData?.items || []}
          onInspectMapping={(m) => setInspectMapping(m)}
          isLoading={loadingRoles || loadingResources}
        />
      )}

      {/* Evidence & Telemetry Inspector Modal */}
      {inspectMapping && (
        <EvidenceDetailModal
          mapping={inspectMapping}
          onClose={() => setInspectMapping(null)}
        />
      )}
    </div>
  );
};
