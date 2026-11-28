import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import api from "../api";
import DetectionFeed from "./DetectionFeed";
import { makeDetection, renderStrict, settle } from "../test/helpers";
import type { DetectionListResponse } from "../types";

vi.mock("../api", () => ({
  default: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
}));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { username: "tester", role: "viewer" } }),
}));

const get = vi.mocked(api.get);

interface ListParams {
  offset?: number;
  limit?: number;
  severity?: string;
  search?: string;
}

// The server's answer for /detections; tests replace it to simulate new data.
let serve: (params: ListParams) => DetectionListResponse;

function rows(ids: number[]): DetectionListResponse {
  return { items: ids.map((id) => makeDetection(id)), total: ids.length };
}

function listCalls(): ListParams[] {
  return get.mock.calls
    .filter(([url]) => url === "/detections")
    .map(([, config]) => (config as { params: ListParams }).params);
}

async function refetch(client: { invalidateQueries: (f: { queryKey: string[] }) => Promise<void> }) {
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["detections"] });
  });
}

beforeEach(() => {
  get.mockReset();
  serve = () => rows([102, 101, 100]);
  get.mockImplementation(async (url: string, config?: unknown) => {
    if (url === "/detections") return { data: serve((config as { params: ListParams }).params) };
    return { data: [] };
  });
});

describe("DetectionFeed new-detection banner", () => {
  it("shows no banner on first load even with a stale stored id, then stores the baseline", async () => {
    localStorage.setItem("slink_last_seen_id", "5");
    renderStrict(<DetectionFeed />);

    await screen.findAllByText("Detection 101");
    expect(screen.queryByText(/new detection/)).toBeNull();
    await waitFor(() => expect(localStorage.getItem("slink_last_seen_id")).toBe("102"));
  });

  it("announces new ids and saves the newest id when dismissed", async () => {
    const { client } = renderStrict(<DetectionFeed />);
    await screen.findAllByText("Detection 101");

    serve = () => rows([104, 103, 102, 101, 100]);
    await refetch(client);
    const banner = await screen.findByText(/2 new detections/);

    await userEvent.setup().click(banner);
    await waitFor(() => expect(screen.queryByText(/new detection/)).toBeNull());
    expect(localStorage.getItem("slink_last_seen_id")).toBe("104");
  });

  it("uses the singular for one new detection", async () => {
    const { client } = renderStrict(<DetectionFeed />);
    await screen.findAllByText("Detection 101");
    serve = () => rows([103, 102, 101, 100]);
    await refetch(client);
    expect(await screen.findByText(/1 new detection —/)).toBeTruthy();
  });
});

describe("DetectionFeed selection and expansion", () => {
  it("keeps them across a refetch and resets them when a filter changes", async () => {
    const user = userEvent.setup();
    const { client } = renderStrict(<DetectionFeed />);
    await screen.findAllByText("Detection 101");

    // Select the first row (checkbox 0 is select-all) and expand the second.
    await user.click(screen.getAllByRole("checkbox")[1]);
    expect(screen.getByText("1 selected")).toBeTruthy();
    await user.click(screen.getAllByText("Detection 101")[0]);
    expect((await screen.findAllByRole("button", { name: "AI Summary" })).length).toBeGreaterThan(0);

    await refetch(client);
    await settle();
    expect(screen.getByText("1 selected")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "AI Summary" }).length).toBeGreaterThan(0);

    await user.selectOptions(screen.getByDisplayValue("All severities"), "high");
    await waitFor(() => expect(screen.queryByText("1 selected")).toBeNull());
    expect(screen.queryAllByRole("button", { name: "AI Summary" })).toHaveLength(0);
  });
});

describe("DetectionFeed paging", () => {
  beforeEach(() => {
    serve = ({ offset = 0 }) => ({
      items: [makeDetection(1000 + offset), makeDetection(2000 + offset)],
      total: 120,
    });
  });

  it("requests only offset=0 after a filter change on page 2", async () => {
    const user = userEvent.setup();
    renderStrict(<DetectionFeed />);
    await screen.findAllByText("Detection 1000");

    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findAllByText("Detection 1050");
    expect(listCalls().some((p) => p.offset === 50)).toBe(true);

    await user.selectOptions(screen.getByDisplayValue("All severities"), "high");
    await screen.findAllByText("Detection 1000");
    await settle(100);

    const filtered = listCalls().filter((p) => p.severity === "high");
    expect(filtered.length).toBeGreaterThan(0);
    expect(filtered.every((p) => p.offset === 0)).toBe(true);
    expect(screen.getByText(/Page 1 of/)).toBeTruthy();
  });

  it("requests only offset=0 after a search change on page 2", async () => {
    const user = userEvent.setup();
    renderStrict(<DetectionFeed />);
    await screen.findAllByText("Detection 1000");

    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findAllByText("Detection 1050");

    await user.type(screen.getByPlaceholderText("Search detections…"), "lockbit");
    await waitFor(() => expect(listCalls().some((p) => p.search === "lockbit")).toBe(true), {
      timeout: 2000,
    });
    await settle(100);

    const searched = listCalls().filter((p) => p.search === "lockbit");
    expect(searched.every((p) => p.offset === 0)).toBe(true);
    expect(within(document.body).getByText(/Page 1 of/)).toBeTruthy();
  });
});
