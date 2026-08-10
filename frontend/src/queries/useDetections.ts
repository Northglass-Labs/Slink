import { useQuery } from "@tanstack/react-query";
import api from "../api";
import type { DetectionListResponse } from "../types";

export interface DetectionsParams {
  source?: string;
  severity?: string;
  status?: string;
  search?: string;
  after?: string;
  sort_by?: string;
  sort_dir?: string;
  limit?: number;
  offset?: number;
}

export const detectionsKey = (params: DetectionsParams) =>
  ["detections", params] as const;

export function useDetections(params: DetectionsParams) {
  return useQuery({
    // Cache key includes the params object — React Query automatically dedupes
    // identical filter/page combinations and refetches when filters change.
    queryKey: detectionsKey(params),
    queryFn: async () => {
      const res = await api.get<DetectionListResponse>("/detections", { params });
      return res.data;
    },
    refetchInterval: 30_000,
  });
}
