import { createElement, StrictMode, type ReactElement } from "react";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { Detection } from "../types";

export interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

export function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

export function makeDetection(id: number, overrides: Partial<Detection> = {}): Detection {
  return {
    id,
    source: "ransomwatch",
    title: `Detection ${id}`,
    snippet: "snippet",
    source_url: "",
    severity: "high",
    status: "new",
    matched_keywords: [],
    first_seen: "2026-11-01T00:00:00Z",
    last_seen: "2026-11-01T00:00:00Z",
    ...overrides,
  };
}

/** Shape of an axios error as the components read it. */
export function httpError(status: number) {
  return Object.assign(new Error(`HTTP ${status}`), { response: { status } });
}

export function newQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 20_000 } },
  });
}

/** Render in StrictMode (as main.tsx does), inside a QueryClientProvider. */
export function renderStrict(ui: ReactElement, client = newQueryClient()) {
  const result = render(
    createElement(
      StrictMode,
      null,
      createElement(QueryClientProvider, { client }, ui),
    ),
  );
  return { ...result, client };
}

/** Let pending promise callbacks and any follow-up renders run. */
export function settle(ms = 30) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

/**
 * A promise that rejects after a real delay. A mock that rejects instantly
 * lets React batch "loading" and "done" into one render, which hides
 * effect-driven retry loops; real network latency does not.
 */
export function rejectAfter(error: unknown, ms = 5): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(error), ms));
}
