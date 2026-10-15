/** Copy the exact server-rendered Markdown bytes used by the finalized download. */
export async function copyBountyReportMarkdown(url: string,
  fetcher: typeof fetch, writeText: (value: string) => Promise<void>): Promise<string> {
  const response = await fetcher(url, { cache: "no-store" });
  if (!response.ok) throw Error("Report Markdown unavailable.");
  const markdown = await response.text();
  await writeText(markdown);
  return markdown;
}
