import { forwardRef } from "react";
import type { InputHTMLAttributes } from "react";

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
}

const inputStyle: React.CSSProperties = {
  padding: "8px 12px",
  borderRadius: 8,
  fontSize: 13,
  fontFamily: "var(--font-sans)",
  background: "var(--color-surface-0)",
  border: "1px solid var(--color-border)",
  color: "var(--color-text-primary)",
  outline: "none",
  transition: "border-color 150ms ease, box-shadow 150ms ease",
  width: "100%",
};

const labelStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 500,
  color: "var(--color-text-secondary)",
  marginBottom: 4,
  display: "block",
};

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { label, style, onFocus, onBlur, ...rest },
  ref,
) {
  return (
    <div>
      {label && <label style={labelStyle}>{label}</label>}
      <input
        ref={ref}
        style={{ ...inputStyle, ...style }}
        onFocus={(e) => {
          e.currentTarget.style.borderColor = "var(--color-accent)";
          e.currentTarget.style.boxShadow = "0 0 0 3px var(--color-accent-muted)";
          onFocus?.(e);
        }}
        onBlur={(e) => {
          e.currentTarget.style.borderColor = "var(--color-border)";
          e.currentTarget.style.boxShadow = "none";
          onBlur?.(e);
        }}
        {...rest}
      />
    </div>
  );
});
