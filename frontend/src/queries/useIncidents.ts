import { useQuery } from "@tanstack/react-query";
import api from "../api";
import type { Incident } from "../types";

// Shared cache key — exported so mutations elsewhere can invalidate this query
// (e.g. after creating or closing an incident).
export const incidentsKey = ["incidents"] as const;

export function useIncidents() {
  return useQuery({
    queryKey: incidentsKey,
    queryFn: async () => {
      const res = await api.get<Incident[]>("/incidents");
      return res.data;
    },
  });
}

export function useActiveIncidents() {
  return useQuery({
    queryKey: [...incidentsKey, "active"],
    queryFn: async () => {
      const res = await api.get<Incident[]>("/incidents");
      return res.data.filter((i) => i.status === "active");
    },
  });
}
