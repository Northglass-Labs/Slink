import { forwardRef } from "react";
import type { SelectHTMLAttributes } from "react";

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
}

const selectStyle: React.CSSProperties = {
  padding: "8px 12px",
  borderRadius: 8,
  fontSize: 13,
  fontFamily: "var(--font-sans)",
  background: "var(--color-surface-0)",
  border: "1px solid var(--color-border)",
  color: "var(--color-text-primary)",
  outline: "none",
  transition: "border-color 150ms ease",
  cursor: "pointer",
};

const labelStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 500,
  color: "var(--color-text-secondary)",
  marginBottom: 4,
  display: "block",
};

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { label, children, style, onFocus, onBlur, ...rest },
  ref,
) {
  return (
    <div>
      {label && <label style={labelStyle}>{label}</label>}
      <select
        ref={ref}
        style={{ ...selectStyle, ...style }}
        onFocus={(e) => {
          e.currentTarget.style.borderColor = "var(--color-accent)";
          onFocus?.(e);
        }}
        onBlur={(e) => {
          e.currentTarget.style.borderColor = "var(--color-border)";
          onBlur?.(e);
        }}
        {...rest}
      >
        {children}
      </select>
    </div>
  );
});
