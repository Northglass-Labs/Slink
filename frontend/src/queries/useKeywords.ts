import { useQuery } from "@tanstack/react-query";
import api from "../api";
import type { Keyword } from "../types";

export const keywordsKey = ["keywords"] as const;

export function useKeywords() {
  return useQuery({
    queryKey: keywordsKey,
    queryFn: async () => {
      const res = await api.get<Keyword[]>("/keywords");
      return res.data;
    },
  });
}
