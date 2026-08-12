export function formatDate(value: Date | string | null): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
export function shortSha(value: string | null): string { return value ? value.slice(0, 10) : "Pending"; }
