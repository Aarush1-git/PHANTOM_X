import { apiClient } from "./api";
import {
  ScanHistoryFilterParams,
  ScanHistoryListResponse,
  ScanDetailResponse,
  ScanComparisonSummary,
  ApplicationFilterOption,
} from "../types/scanHistory";

export const scanHistoryApi = {
  getScanHistory: async (params?: ScanHistoryFilterParams): Promise<ScanHistoryListResponse> => {
    const { data } = await apiClient.get<ScanHistoryListResponse>("/scan-history", {
      params,
    });
    return data;
  },

  getScanDetails: async (scanId: string): Promise<ScanDetailResponse> => {
    const { data } = await apiClient.get<ScanDetailResponse>(`/scan-history/${scanId}`);
    return data;
  },

  getFilterApplications: async (): Promise<ApplicationFilterOption[]> => {
    const { data } = await apiClient.get<ApplicationFilterOption[]>("/scan-history/applications");
    return data;
  },

  compareScans: async (
    baselineScanId: string,
    comparisonScanId: string,
    saveRecord: boolean = false
  ): Promise<ScanComparisonSummary> => {
    const { data } = await apiClient.get<ScanComparisonSummary>("/scan-history/compare", {
      params: {
        baseline_scan_id: baselineScanId,
        comparison_scan_id: comparisonScanId,
        save_record: saveRecord,
      },
    });
    return data;
  },

  saveScanComparison: async (
    baselineScanId: string,
    comparisonScanId: string
  ): Promise<ScanComparisonSummary> => {
    const { data } = await apiClient.post<ScanComparisonSummary>("/scan-history/compare", {
      baseline_scan_id: baselineScanId,
      comparison_scan_id: comparisonScanId,
      save_record: true,
    });
    return data;
  },
};
