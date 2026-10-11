import { describe, expect, it } from "vitest";
import { makeImpactObservationPlan, planHash, snapshotHash, type ImpactStateProvenance } from "@contracthunter/core";
import { captureImpactState, makeImpactStateDiff } from "./impact-state";

const target = `0x${"1".repeat(40)}`, sender = `0x${"2".repeat(40)}`, holder = `0x${"3".repeat(40)}`;
const slot = `0x${"0".repeat(64)}`;
const provenance = (hash: string): ImpactStateProvenance => ({ executionId: "00000000-0000-4000-8000-000000000001",
  sessionId: "00000000-0000-4000-8000-000000000002", runtimeTokenSha256: "a".repeat(64), chainId: 31337,
  forkBlock: 1, forkBlockHash: `0x${"b".repeat(64)}`, targetCodeHashes: { [target]: `sha256:${"c".repeat(64)}` },
  artifactId: "00000000-0000-4000-8000-000000000003", sourceSha256: `sha256:${"d".repeat(64)}`, planSha256: hash });
const word = (value: bigint) => `0x${value.toString(16).padStart(64, "0")}`;

describe("Impact C1 state capture and diff", () => {
  it("captures every bounded category with exact values and preserves unavailable reads", async () => {
    const plan = makeImpactObservationPlan(sender, [target], { erc20Balances: [{ token: target, holder }],
      erc721Owners: [{ token: target, tokenId: "7" }], erc1155Balances: [{ token: target, holder, tokenId: "8" }],
      storageSlots: [{ contract: target, slot }], viewCalls: [{ kind: "erc20_totalSupply", target }] });
    const p = provenance(planHash(plan));
    const read = (post: boolean) => async (method: string, params: unknown[]): Promise<unknown> => {
      if (method === "eth_blockNumber") return post ? "0x2" : "0x1";
      if (method === "eth_getBlockByNumber") return { number: post ? "0x2" : "0x1", timestamp: post ? "0x65" : "0x64" };
      if (method === "eth_getBalance") return params[0] === target ? post ? "0xb" : "0xa" : "0x64";
      if (method === "eth_getStorageAt") return word(post ? 43n : 42n);
      const data = String((params[0] as { data: string }).data);
      if (data.startsWith("0x70a08231")) return word(post ? 9n : 10n);
      if (data.startsWith("0x6352211e")) {
        if (post) throw Error("token missing");
        return `0x${holder.slice(2).padStart(64, "0")}`;
      }
      if (data.startsWith("0x00fdd58e")) return word(5n);
      if (data === "0x18160ddd") return word(1000n);
      throw Error("unexpected method");
    };
    const pre = await captureImpactState(plan, p, "pre", read(false));
    const post = await captureImpactState(plan, p, "post", read(true));
    const diff = makeImpactStateDiff(pre, post);
    expect(pre.observedAtBlock).toBe(1);
    expect(post.observedAtTimestamp).toBe("101");
    expect(diff.changes.find((item) => item.id === `native:${target}`)?.delta).toBe("1");
    expect(diff.changes.find((item) => item.id === `erc20:${target}:${holder}`)?.delta).toBe("-1");
    expect(diff.changes.find((item) => item.id === `storage:${target}:${slot}`)?.after).toBe(word(43n));
    expect(diff.changes.find((item) => item.id === `erc721:${target}:7`)).toMatchObject({
      beforeStatus: "available", afterStatus: "unavailable", afterErrorCode: "rpc_error" });
    expect(diff.changes).toHaveLength(4);
    expect(pre.contentSha256).toBe(snapshotHash(pre));
  });

  it("makes a valid zero-change diff and rejects bad plans or cross-session snapshots", async () => {
    const plan = makeImpactObservationPlan(sender, [target]);
    const p = provenance(planHash(plan));
    const read = async (method: string, params: unknown[]) => method === "eth_blockNumber" ? "0x1" :
      method === "eth_getBlockByNumber" ? { number: "0x1", timestamp: "0x64" } :
        method === "eth_getBalance" && params[0] === target ? "0x20000000000001" : "0x1";
    const pre = await captureImpactState(plan, p, "pre", read);
    const post = await captureImpactState(plan, p, "post", read);
    expect(pre.observations.find((item) => item.id === `native:${target}`)?.value).toBe("9007199254740993");
    expect(makeImpactStateDiff(pre, post).changes).toEqual([]);
    expect(() => makeImpactObservationPlan(sender, [target], { storageSlots: [
      { contract: target, slot }, { contract: target, slot }] })).toThrow("impact_observation_plan_invalid");
    expect(() => makeImpactObservationPlan(sender, [target], { nativeBalances: [target] }))
      .toThrow("impact_observation_plan_invalid");
    expect(() => makeImpactObservationPlan(sender, [target], { viewCalls: [{ kind: "arbitrary", target }] })).toThrow();
    expect(() => makeImpactStateDiff(pre, { ...post, provenance: { ...p, sessionId: "wrong" } })).toThrow();
    expect(() => makeImpactStateDiff(pre, { ...post, observations: [] })).toThrow();
  });

  it("canonicalizes input order and rejects plans beyond the fixed entry bound", () => {
    const slot2 = "0x" + "1".repeat(64);
    const first = makeImpactObservationPlan(sender, [target], { nativeBalances: [holder],
      storageSlots: [{ contract: target, slot: slot2 }, { contract: target, slot }] });
    const second = makeImpactObservationPlan(sender, [target], { storageSlots: [
      { contract: target, slot }, { contract: target, slot: slot2 }], nativeBalances: [holder] });
    expect(planHash(first)).toBe(planHash(second));
    expect(() => makeImpactObservationPlan(sender, [target], {
      storageSlots: Array.from({ length: 17 }, (_, index) => ({
        contract: target, slot: "0x" + index.toString(16).padStart(64, "0") })),
    })).toThrow();
  });
});
