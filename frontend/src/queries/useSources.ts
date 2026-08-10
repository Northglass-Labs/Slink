import { useQuery } from "@tanstack/react-query";
import api from "../api";
import type { SourceStatus } from "../types";

export const sourcesKey = ["sources"] as const;

export function useSources() {
  return useQuery({
    queryKey: sourcesKey,
    queryFn: async () => {
      const res = await api.get<SourceStatus[]>("/sources");
      return res.data;
    },
    // Background poll every 30s — keeps source health current without manual
    // setInterval plumbing in the consuming components.
    refetchInterval: 30_000,
  });
}
