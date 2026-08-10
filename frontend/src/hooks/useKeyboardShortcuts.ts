import { useEffect } from "react";

interface ShortcutHandlers {
  onNext?: () => void; // j
  onPrev?: () => void; // k
  onExpand?: () => void; // Enter
  onCollapse?: () => void; // Escape
  onAcknowledge?: () => void; // a
  onDismiss?: () => void; // d
  onEscalate?: () => void; // e
  onSearch?: () => void; // /
  onHelp?: () => void; // ?
}

export function useKeyboardShortcuts(handlers: ShortcutHandlers) {
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      // Don't intercept when typing in input/textarea/select
      const tag = (event.target as HTMLElement).tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

      switch (event.key) {
        case "j":
          handlers.onNext?.();
          break;
        case "k":
          handlers.onPrev?.();
          break;
        case "Enter":
          handlers.onExpand?.();
          break;
        case "Escape":
          handlers.onCollapse?.();
          break;
        case "a":
          handlers.onAcknowledge?.();
          break;
        case "d":
          handlers.onDismiss?.();
          break;
        case "e":
          handlers.onEscalate?.();
          break;
        case "/":
          event.preventDefault();
          handlers.onSearch?.();
          break;
        case "?":
          handlers.onHelp?.();
          break;
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handlers]);
}
