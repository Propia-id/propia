import { createStore } from "zustand/vanilla";
import type { VPRequest, ApprovalData } from "../protocols/index";

export interface ApprovalState {
  request: VPRequest | null;
  approvalData: ApprovalData | null;
}

export interface ApprovalActions {
  setPending(request: VPRequest, approvalData: ApprovalData): void;
  clear(): void;
}

export type ApprovalStore = ApprovalState & ApprovalActions;

export function createApprovalStore() {
  return createStore<ApprovalStore>((set) => ({
    request: null,
    approvalData: null,

    setPending(request, approvalData) {
      set({ request, approvalData });
    },

    clear() {
      set({ request: null, approvalData: null });
    },
  }));
}
