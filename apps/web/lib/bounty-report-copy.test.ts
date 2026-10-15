import { describe, expect, it, vi } from "vitest";
import { copyBountyReportMarkdown } from "./bounty-report-copy";

describe("bounty report clipboard", () => {
  it("copies the exact response body used by Markdown download", async () => {
    const bytes = "# Report α\n\n| Asset | Amount |\n| --- | --- |\n| TOKEN\\_A | 900719925474099312345 |\n";
    const fetcher = vi.fn(async () => new Response(bytes, { status: 200 }));
    const write = vi.fn(async () => {});
    const copied = await copyBountyReportMarkdown("/report/download", fetcher as unknown as typeof fetch, write);
    expect(copied).toBe(bytes);
    expect(write).toHaveBeenCalledExactlyOnceWith(bytes);
    expect(fetcher).toHaveBeenCalledWith("/report/download", { cache: "no-store" });
  });
  it("does not copy failed downloads", async () => {
    const write = vi.fn(async () => {});
    await expect(copyBountyReportMarkdown("/report/download",
      (async () => new Response("integrity invalid", { status: 409 })) as typeof fetch, write))
      .rejects.toThrow("Report Markdown unavailable");
    expect(write).not.toHaveBeenCalled();
  });
});
