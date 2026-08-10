import type { Detection } from "../types";

/** Left-border color for detection rows — called from DetectionRow */
export function severityBorderColor(severity: Detection["severity"]): string {
  const map: Record<Detection["severity"], string> = {
    critical: "var(--color-sev-critical)",
    high: "var(--color-sev-high)",
    medium: "var(--color-sev-medium)",
    low: "var(--color-sev-low)",
  };
  return map[severity];
}
