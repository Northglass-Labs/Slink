import type { ReactNode } from "react";

interface StatCardProps {
  label: string;
  value: ReactNode;
  subtitle?: ReactNode;
  variant?: "default" | "warning" | "danger" | "success";
}

const variantColors = {
  default: "var(--color-text-primary)",
  warning: "var(--color-warning, #f59e0b)",
  danger: "var(--color-danger, #ef4444)",
  success: "var(--color-success, #34d399)",
};

export function StatCard({ label, value, subtitle, variant = "default" }: StatCardProps) {
  return (
    <div
      style={{
        background: "var(--color-surface-1)",
        border: "1px solid var(--color-border)",
        borderRadius: 8,
        padding: 16,
      }}
    >
      <div
        style={{
          color: "var(--color-text-tertiary)",
          fontSize: 11,
          textTransform: "uppercase",
          letterSpacing: "0.5px",
          marginBottom: 6,
        }}
      >
        {label}
      </div>
      <div
        style={{
          color: variantColors[variant],
          fontSize: 28,
          fontWeight: 700,
        }}
      >
        {value}
      </div>
      {subtitle && (
        <div
          style={{
            color: "var(--color-text-tertiary)",
            fontSize: 11,
            marginTop: 4,
          }}
        >
          {subtitle}
        </div>
      )}
    </div>
  );
}
