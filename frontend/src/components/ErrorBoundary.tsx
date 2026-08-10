import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log to console for dev; could be extended to call a backend error endpoint later
    console.error("ErrorBoundary caught:", error, errorInfo);
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            minHeight: "100vh",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "var(--color-surface-0)",
            color: "var(--color-text-primary)",
            fontFamily: "var(--font-sans)",
            padding: 20,
          }}
        >
          <div
            style={{
              maxWidth: 500,
              textAlign: "center",
              padding: 32,
              background: "var(--color-surface-1)",
              border: "1px solid var(--color-border)",
              borderRadius: 12,
            }}
          >
            <h1
              style={{
                fontSize: 20,
                fontWeight: 600,
                marginBottom: 12,
                color: "var(--color-danger, #ef4444)",
              }}
            >
              Something went wrong
            </h1>
            <p
              style={{
                color: "var(--color-text-secondary)",
                fontSize: 14,
                marginBottom: 20,
                lineHeight: 1.5,
              }}
            >
              The app encountered an unexpected error. Try reloading — if the problem
              persists, check the browser console for details.
            </p>
            {this.state.error && (
              <div
                style={{
                  background: "var(--color-surface-0)",
                  border: "1px solid var(--color-border)",
                  borderRadius: 6,
                  padding: 12,
                  marginBottom: 20,
                  textAlign: "left",
                  fontFamily: "var(--font-mono, monospace)",
                  fontSize: 11,
                  color: "var(--color-text-tertiary)",
                  overflow: "auto",
                  maxHeight: 150,
                }}
              >
                {this.state.error.message}
              </div>
            )}
            <button
              onClick={this.handleReload}
              style={{
                padding: "10px 24px",
                borderRadius: 8,
                fontSize: 13,
                fontWeight: 500,
                fontFamily: "var(--font-sans)",
                background: "var(--color-accent)",
                color: "var(--color-text-inverse)",
                border: "none",
                cursor: "pointer",
              }}
            >
              Reload app
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
