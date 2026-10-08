import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AUTHORITATIVE_SOURCE_CLOSURE_SCHEMA } from "./authoritative-source-closure";
import { SOURCE_CLOSURE_FINGERPRINT_SCHEMA, fingerprintAuthoritativeSourceClosure } from "./source-closure-fingerprint";

const file = (sourceUnitName: string, snapshotSourceKey: string, rawBytes: Buffer) => ({
  sourceUnitName, snapshotSourceKey, rawBytes, byteLength: rawBytes.length,
  rawSha256: createHash("sha256").update(rawBytes).digest("hex"),
});
const base = () => ({ schema: AUTHORITATIVE_SOURCE_CLOSURE_SCHEMA, compilationProfile: "plain-solidity-exact-pragma-v1",
  targetSourceUnit: "contracts/A.sol", files: [file("contracts/A.sol", "contracts/A.sol", Buffer.from("a\r\nb ")), file("contracts/B.sol", "contracts/B.sol", Buffer.from("import A;"))] });
const digest = (input: ReturnType<typeof base>) => fingerprintAuthoritativeSourceClosure(input).sha256;

describe("canonical authoritative source closure fingerprint", () => {
  it("uses a stable versioned binary framing and canonical file order", () => {
    const input = base(), result = fingerprintAuthoritativeSourceClosure(input);
    expect(result).toMatchObject({ schema: SOURCE_CLOSURE_FINGERPRINT_SCHEMA, fileCount: 2, totalBytes: 14 });
    expect(digest(base())).toBe(result.sha256);
    expect(digest({ ...input, files: [...input.files].reverse() })).toBe(result.sha256);
  });
  it("commits to exact raw bytes including one byte, newline style, whitespace, and lossy UTF-8", () => {
    const input = base(), original = digest(input);
    for (const changed of [Buffer.from("a\r\nb!"), Buffer.from("a\nb "), Buffer.from("a\r\nb  "), Buffer.from([0xff]), Buffer.from([0xfe])]) {
      const alternate = digest({ ...input, files: [file("contracts/A.sol", "contracts/A.sol", changed), input.files[1]] });
      expect(alternate).not.toBe(original);
    }
    const invalidA = digest({ ...input, files: [file("contracts/A.sol", "contracts/A.sol", Buffer.from([0xff])), input.files[1]] });
    const invalidB = digest({ ...input, files: [file("contracts/A.sol", "contracts/A.sol", Buffer.from([0xfe])), input.files[1]] });
    expect(invalidA).not.toBe(invalidB);
    expect(Buffer.from([0xff]).toString("utf8")).toBe(Buffer.from([0xfe]).toString("utf8"));
  });
  it("commits to target, profile, source-unit names, snapshot keys, and membership", () => {
    const input = base(), original = digest(input);
    expect(digest({ ...input, targetSourceUnit: "contracts/B.sol" })).not.toBe(original);
    expect(digest({ ...input, compilationProfile: "other-profile" })).not.toBe(original);
    expect(digest({ ...input, files: [input.files[0], file("contracts/C.sol", "contracts/B.sol", input.files[1].rawBytes)] })).not.toBe(original);
    expect(digest({ ...input, files: [input.files[0], file("contracts/B.sol", "contracts/C.sol", input.files[1].rawBytes)] })).not.toBe(original);
    expect(digest({ ...input, files: [input.files[0]] })).not.toBe(original);
    expect(digest({ ...input, files: [...input.files, file("contracts/C.sol", "contracts/C.sol", Buffer.from("c"))] })).not.toBe(original);
  });
  it("keeps scan, commit, compiler, and strategy outside the input model", () => {
    const input = base(), original = digest(input);
    const otherProvenance = { ...input, scanId: "other", resolvedCommit: "other", compilerIdentity: { version: "0.8.99" }, selectedStrategy: "echidna-stateful-invariant" };
    expect(digest(otherProvenance)).toBe(original);
  });
  it("rejects duplicate membership, target omission, and unverified stored hashes", () => {
    const input = base();
    expect(() => digest({ ...input, files: [input.files[0], { ...input.files[0] }] })).toThrow();
    expect(() => digest({ ...input, files: [input.files[0], file("contracts/C.sol", "contracts/A.sol", Buffer.from("c"))] })).toThrow();
    expect(() => digest({ ...input, targetSourceUnit: "contracts/Missing.sol" })).toThrow();
    expect(() => digest({ ...input, files: [{ ...input.files[0], rawSha256: "0".repeat(64) }, input.files[1]] })).toThrow();
  });
});
