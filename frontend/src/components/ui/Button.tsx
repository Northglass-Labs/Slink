import { forwardRef } from "react";
import type { ButtonHTMLAttributes } from "react";

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";
type ButtonSize = "sm" | "md";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const baseStyle = {
  fontFamily: "var(--font-sans)",
  fontWeight: 500,
  border: "none",
  cursor: "pointer",
  borderRadius: 8,
  transition: "all 150ms ease",
  whiteSpace: "nowrap" as const,
};

const sizeStyles: Record<ButtonSize, React.CSSProperties> = {
  sm: { padding: "4px 10px", fontSize: 11 },
  md: { padding: "8px 16px", fontSize: 13 },
};

const variantStyles: Record<ButtonVariant, React.CSSProperties> = {
  primary: {
    background: "var(--color-accent)",
    color: "var(--color-text-inverse)",
    boxShadow: "0 2px 8px var(--color-accent-glow)",
  },
  secondary: {
    background: "var(--color-surface-2)",
    color: "var(--color-text-secondary)",
    border: "1px solid var(--color-border)",
  },
  danger: {
    background: "rgba(239,68,68,0.10)",
    color: "var(--color-danger)",
    border: "1px solid rgba(239,68,68,0.3)",
  },
  ghost: {
    background: "transparent",
    color: "var(--color-text-secondary)",
    border: "1px solid var(--color-border)",
  },
};

const disabledStyle: React.CSSProperties = {
  background: "var(--color-surface-4)",
  color: "var(--color-text-secondary)",
  cursor: "not-allowed",
  opacity: 0.7,
  boxShadow: "none",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "primary", size = "md", disabled, style, ...rest },
  ref,
) {
  const computed: React.CSSProperties = {
    ...baseStyle,
    ...sizeStyles[size],
    ...variantStyles[variant],
    ...(disabled ? disabledStyle : {}),
    ...style,
  };
  return <button ref={ref} disabled={disabled} style={computed} {...rest} />;
});
