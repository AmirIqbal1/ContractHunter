import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { COMPILATION_MANIFEST_SCHEMA, type CompilationManifest } from "@contracthunter/core";
import { AuthoritativeClosureError, resolveAuthoritativeSourceClosure } from "./authoritative-source-closure";

const source = (text: string) => { const rawBytes = Buffer.from(text); return { rawBytes, rawSha256: createHash("sha256").update(rawBytes).digest("hex"), byteLength: rawBytes.length }; };
const files = new Map([
  ["src/Main.sol", source('pragma solidity 0.8.24; import "./Dep.sol"; contract Main {}')],
  ["src/Dep.sol", source('pragma solidity 0.8.24; import "./Main.sol"; contract Dep {}')],
  ["src/Unused.sol", source('pragma solidity 0.8.24; contract Unused {}')],
]);
const manifest: CompilationManifest = { schema: COMPILATION_MANIFEST_SCHEMA, scanId: randomUUID(), resolvedCommit: "a".repeat(40), compilationProfileKind: "plain-solidity-exact-pragma-v1",
  compiler: { version: "0.8.24", artifactSha256: "b".repeat(64) }, sourceRoots: ["src"], libraryRoots: [], remappings: [],
  sourceUnits: [...files].map(([name, bytes]) => ({ sourceUnitName: name, snapshotSourceKey: name, rawSha256: bytes.rawSha256, byteLength: bytes.byteLength, contractNames: [name.split("/").at(-1)!.slice(0, -4)] })) };
const resolve = (data = files, current = manifest) => resolveAuthoritativeSourceClosure({ manifest: current, targetSourceUnit: "src/Main.sol", source: (key) => data.get(key) ?? null });
const rejects = (run: () => unknown, code: string) => { try { run(); throw new Error("expected rejection"); } catch (error) { expect(error).toBeInstanceOf(AuthoritativeClosureError); expect((error as AuthoritativeClosureError).code).toBe(code); } };

describe("snapshot-only authoritative closure", () => {
  it("resolves a cycle once, excludes unrelated units, and orders raw bytes deterministically", () => {
    const first = resolve(), second = resolve();
    expect(first).toEqual(second);
    expect(first.files.map((file) => file.sourceUnitName)).toEqual(["src/Dep.sol", "src/Main.sol"]);
    expect(first.files[1].rawBytes).toEqual(files.get("src/Main.sol")!.rawBytes);
    expect(first.compilerIdentity).toEqual(manifest.compiler);
    expect(first.resolvedCommit).toBe(manifest.resolvedCommit);
  });
  it("rejects missing, mismatched, and invalid UTF-8 snapshot bytes", () => {
    const absent = new Map(files); absent.delete("src/Dep.sol"); rejects(() => resolve(absent), "source_missing");
    const changed = new Map(files); changed.set("src/Dep.sol", source("pragma solidity 0.8.24; contract Changed {}")); rejects(() => resolve(changed), "source_integrity_failed");
    const invalid = new Map(files); const bad = { ...files.get("src/Dep.sol")!, rawBytes: Buffer.from([0xff]) };
    invalid.set("src/Dep.sol", bad); rejects(() => resolve(invalid), "source_integrity_failed");
    const invalidManifest = { ...manifest, sourceUnits: manifest.sourceUnits.map((unit) => unit.sourceUnitName === "src/Dep.sol" ? { ...unit, rawSha256: createHash("sha256").update(Buffer.from([0xff])).digest("hex"), byteLength: 1 } : unit) };
    rejects(() => resolve(new Map(files).set("src/Dep.sol", { rawBytes: Buffer.from([0xff]), rawSha256: invalidManifest.sourceUnits.find((unit) => unit.sourceUnitName === "src/Dep.sol")!.rawSha256, byteLength: 1 }), invalidManifest), "invalid_utf8");
  });
  it("rejects imports outside the persisted exact source-unit universe", () => {
    const bad = source('pragma solidity 0.8.24; import "forge-std/Test.sol"; contract Main {}');
    const data = new Map(files).set("src/Main.sol", bad);
    const current = { ...manifest, sourceUnits: manifest.sourceUnits.map((unit) => unit.sourceUnitName === "src/Main.sol" ? { ...unit, rawSha256: bad.rawSha256, byteLength: bad.byteLength } : unit) };
    rejects(() => resolve(data, current), "unsupported_import");
  });
});
