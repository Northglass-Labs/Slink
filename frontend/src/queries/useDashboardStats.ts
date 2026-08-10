import { useQuery } from "@tanstack/react-query";
import api from "../api";
import type { DashboardStats } from "../types";

export const dashboardStatsKey = ["dashboard", "stats"] as const;

export function useDashboardStats() {
  return useQuery({
    queryKey: dashboardStatsKey,
    queryFn: async () => {
      const res = await api.get<DashboardStats>("/dashboard/stats");
      return res.data;
    },
    refetchInterval: 30_000,
  });
}
