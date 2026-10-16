import { describe, expect, it, vi } from "vitest";
const db = vi.hoisted(() => ({ finding: vi.fn(), investigation: vi.fn(), hypothesis: vi.fn(), members: vi.fn() }));
vi.mock("@contracthunter/db", () => ({ getFinding: (...args: unknown[]) => db.finding(...args),
  getInvestigation: (...args: unknown[]) => db.investigation(...args),
  getVulnerabilityHypothesis: (...args: unknown[]) => db.hypothesis(...args),
  listInvestigationFindings: (...args: unknown[]) => db.members(...args), readStaticProtocolGraph: vi.fn() }));
import { resolveInvestigationPathSubject } from "./investigation-path-server";
const scan = "11111111-1111-4111-8111-111111111111", other = "22222222-2222-4222-8222-222222222222";
const finding = "33333333-3333-4333-8333-333333333333", investigation = "44444444-4444-4444-8444-444444444444";
describe("Investigation Path subject resolution", () => {
  it("requires exact same-scan finding and existing investigation membership", () => {
    db.finding.mockReturnValueOnce({ id: finding, scanId: other });
    expect(resolveInvestigationPathSubject({} as never, scan, "finding", finding)).toBeNull();
    db.finding.mockReturnValueOnce({ id: finding, scanId: scan });
    expect(resolveInvestigationPathSubject({} as never, scan, "finding", finding)?.findingIds).toEqual([finding]);
    db.investigation.mockReturnValueOnce({ id: investigation, scanId: scan });
    db.members.mockReturnValueOnce([{ id: finding, scanId: scan }, { id: other, scanId: other }]);
    expect(resolveInvestigationPathSubject({} as never, scan, "investigation", investigation)?.findingIds).toEqual([finding]);
  });
  it("uses only exact hypothesis investigation IDs, never affected names", () => {
    db.hypothesis.mockReturnValueOnce({ scanId: scan, relatedInvestigationIds: JSON.stringify([investigation]),
      affectedContracts: '["Vault"]', affectedFunctions: '["withdraw"]' });
    db.investigation.mockReturnValueOnce({ id: investigation, scanId: scan });
    db.members.mockReturnValueOnce([{ id: finding, scanId: scan }]);
    expect(resolveInvestigationPathSubject({} as never, scan, "hypothesis", other)?.findingIds).toEqual([finding]);
    db.hypothesis.mockReturnValueOnce({ scanId: scan, relatedInvestigationIds: "malformed",
      affectedContracts: '["Vault"]', affectedFunctions: '["withdraw"]' });
    expect(resolveInvestigationPathSubject({} as never, scan, "hypothesis", other)?.findingIds).toEqual([]);
  });
  it("reports bounded subject membership rather than silently treating it as complete", () => {
    db.investigation.mockReturnValueOnce({ scanId: scan });
    db.members.mockReturnValueOnce(Array.from({ length: 40 }, (_, i) => ({ id: `${String(i).padStart(8, "0")}-3333-4333-8333-333333333333`, scanId: scan })));
    const subject = resolveInvestigationPathSubject({} as never, scan, "investigation", investigation);
    expect(subject?.findingIds).toHaveLength(32); expect(subject?.linksTruncated).toBe(true);
  });
});
