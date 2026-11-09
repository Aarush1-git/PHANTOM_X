import { create } from "zustand";
import { ScanProgress, ScanStatus } from "../types";

interface LiveScanState {
  activeScans: Record<string, ScanProgress>;
  updateScanProgress: (progress: ScanProgress) => void;
  removeScan: (scanId: string) => void;
}

export const useScanStore = create<LiveScanState>((set) => ({
  activeScans: {},

  updateScanProgress: (progress: ScanProgress) => {
    set((state) => ({
      activeScans: {
        ...state.activeScans,
        [progress.scan_id]: progress,
      },
    }));
  },

  removeScan: (scanId: string) => {
    set((state) => {
      const next = { ...state.activeScans };
      delete next[scanId];
      return { activeScans: next };
    });
  },
}));

