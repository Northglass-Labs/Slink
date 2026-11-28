import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import api from "../api";
import DetectionDetail from "./DetectionDetail";
import { deferred, httpError, makeDetection, rejectAfter, renderStrict, settle } from "../test/helpers";

const auth = vi.hoisted(() => ({ role: "admin" as "admin" | "viewer" }));

vi.mock("../api", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { username: "tester", role: auth.role } }),
}));

const get = vi.mocked(api.get);
const post = vi.mocked(api.post);

const SUMMARY = {
  cached: false,
  summary: "Ransomware group claims a new victim.",
  attack_techniques: [],
  pivots: [],
  generated_at: "2026-11-01T00:00:00Z",
};

function aiCalls() {
  return post.mock.calls.filter(([url]) => String(url).includes("/ai-summary"));
}
function rawCalls() {
  return get.mock.calls.filter(([url]) => url === "/detections/7");
}

function mount() {
  return renderStrict(
    <table>
      <tbody>
        <DetectionDetail detection={makeDetection(7)} onStatusChange={() => {}} />
      </tbody>
    </table>,
  );
}

beforeEach(() => {
  auth.role = "admin";
  get.mockReset();
  post.mockReset();
  // Default: incidents list empty, raw detection returns raw_data.
  get.mockImplementation(async (url: string) => {
    if (url === "/incidents") return { data: [] };
    if (url === "/detections/7") return { data: { ...makeDetection(7), raw_data: { k: "v" } } };
    return { data: [] };
  });
});

describe("DetectionDetail AI tab", () => {
  it("sends one request per click and caches the result across tab switches", async () => {
    post.mockResolvedValue({ data: SUMMARY });
    const user = userEvent.setup();
    mount();

    await user.click(screen.getByRole("button", { name: "AI Summary" }));
    expect(await screen.findByText(SUMMARY.summary)).toBeTruthy();
    expect(aiCalls()).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "Investigate" }));
    await user.click(screen.getByRole("button", { name: "AI Summary" }));
    expect(screen.getByText(SUMMARY.summary)).toBeTruthy();
    await settle();
    expect(aiCalls()).toHaveLength(1);
  });

  it("does not request anything until the tab is opened", async () => {
    post.mockResolvedValue({ data: SUMMARY });
    mount();
    await settle();
    expect(aiCalls()).toHaveLength(0);
  });

  it("sends one request for two quick clicks while one is pending", async () => {
    const pending = deferred<{ data: typeof SUMMARY }>();
    post.mockReturnValue(pending.promise);
    const user = userEvent.setup();
    mount();

    const tab = screen.getByRole("button", { name: "AI Summary" });
    await user.click(tab);
    await user.click(tab);
    expect(aiCalls()).toHaveLength(1);

    await act(async () => pending.resolve({ data: SUMMARY }));
    expect(await screen.findByText(SUMMARY.summary)).toBeTruthy();
    expect(aiCalls()).toHaveLength(1);
  });

  it("shows the error, stops, and retries exactly once per click", async () => {
    post.mockImplementation(() => rejectAfter(httpError(502)));
    const user = userEvent.setup();
    mount();

    await user.click(screen.getByRole("button", { name: "AI Summary" }));
    expect(await screen.findByText(/Upstream model call failed/)).toBeTruthy();
    // A failed load must not retry on its own (the request storm on main).
    await settle(100);
    expect(aiCalls()).toHaveLength(1);

    // Re-clicking the tab retries once.
    await user.click(screen.getByRole("button", { name: "AI Summary" }));
    await screen.findByText(/Upstream model call failed/);
    await settle(100);
    expect(aiCalls()).toHaveLength(2);

    // So does the Retry control, and it can succeed.
    post.mockResolvedValue({ data: SUMMARY });
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText(SUMMARY.summary)).toBeTruthy();
    await settle(100);
    expect(aiCalls()).toHaveLength(3);
  });

  it("maps 503 to the disabled message", async () => {
    post.mockImplementation(() => rejectAfter(httpError(503)));
    const user = userEvent.setup();
    mount();
    await user.click(screen.getByRole("button", { name: "AI Summary" }));
    expect(await screen.findByText(/AI summary disabled/)).toBeTruthy();
  });

  it("logs no errors when the response arrives after unmount", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const pending = deferred<{ data: typeof SUMMARY }>();
    post.mockReturnValue(pending.promise);
    const user = userEvent.setup();
    const { unmount } = mount();

    await user.click(screen.getByRole("button", { name: "AI Summary" }));
    unmount();
    await act(async () => pending.resolve({ data: SUMMARY }));
    await settle();
    expect(errors).not.toHaveBeenCalled();
  });
});

describe("DetectionDetail Raw tab", () => {
  it("sends one request, caches it, and shows the data", async () => {
    const user = userEvent.setup();
    mount();

    await user.click(screen.getByRole("button", { name: "Raw JSON" }));
    expect(await screen.findByText(/"k": "v"/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Investigate" }));
    await user.click(screen.getByRole("button", { name: "Raw JSON" }));
    expect(screen.getByText(/"k": "v"/)).toBeTruthy();
    await settle();
    expect(rawCalls()).toHaveLength(1);
  });

  it("sends one request for two quick clicks while one is pending", async () => {
    const pending = deferred<{ data: unknown }>();
    get.mockImplementation((url: string) =>
      url === "/detections/7" ? pending.promise : Promise.resolve({ data: [] }),
    );
    const user = userEvent.setup();
    mount();

    const tab = screen.getByRole("button", { name: "Raw JSON" });
    await user.click(tab);
    await user.click(tab);
    expect(rawCalls()).toHaveLength(1);
    await act(async () => pending.resolve({ data: { ...makeDetection(7), raw_data: { k: "v" } } }));
    expect(await screen.findByText(/"k": "v"/)).toBeTruthy();
    expect(rawCalls()).toHaveLength(1);
  });

  it("shows the error, stops, and retries exactly once per click", async () => {
    get.mockImplementation(async (url: string) => {
      if (url === "/detections/7") return rejectAfter(httpError(500));
      return { data: [] };
    });
    const user = userEvent.setup();
    mount();

    await user.click(screen.getByRole("button", { name: "Raw JSON" }));
    expect(await screen.findByText("Failed to load raw data.")).toBeTruthy();
    await settle(100);
    expect(rawCalls()).toHaveLength(1);

    await user.click(screen.getByRole("button", { name: "Raw JSON" }));
    await screen.findByText("Failed to load raw data.");
    await settle(100);
    expect(rawCalls()).toHaveLength(2);

    get.mockImplementation(async (url: string) =>
      url === "/detections/7"
        ? { data: { ...makeDetection(7), raw_data: { k: "v" } } }
        : { data: [] },
    );
    await user.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText(/"k": "v"/)).toBeTruthy();
    await settle(100);
    expect(rawCalls()).toHaveLength(3);
  });

  it("gives a viewer no Raw tab and never requests raw data", async () => {
    auth.role = "viewer";
    mount();
    expect(screen.queryByRole("button", { name: "Raw JSON" })).toBeNull();
    await settle();
    expect(rawCalls()).toHaveLength(0);
    // Sanity: the other tabs are still there.
    expect(within(document.body).getByRole("button", { name: "AI Summary" })).toBeTruthy();
  });

  it("logs no errors when the response arrives after unmount", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const pending = deferred<{ data: unknown }>();
    get.mockImplementation((url: string) =>
      url === "/detections/7" ? pending.promise : Promise.resolve({ data: [] }),
    );
    const user = userEvent.setup();
    const { unmount } = mount();

    await user.click(screen.getByRole("button", { name: "Raw JSON" }));
    unmount();
    await act(async () => pending.resolve({ data: { ...makeDetection(7), raw_data: { k: "v" } } }));
    await waitFor(() => expect(errors).not.toHaveBeenCalled());
  });
});
