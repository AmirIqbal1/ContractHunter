import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import nodePath from "node:path";
import { randomUUID, createHash } from "node:crypto";
import { mapRepository } from "./repository-mapper";
import { withRepositoryClassificationOverride, validateRepositoryMap } from "@contracthunter/core";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((p) => rm(p, { recursive: true, force: true }))); });
async function fixture(files: Record<string, string>) {
  const root = await mkdtemp(nodePath.join(tmpdir(), "ch-repository-map-")); directories.push(root);
  for (const [name, content] of Object.entries(files)) {
    await mkdir(nodePath.dirname(nodePath.join(root, name)), { recursive: true });
    await writeFile(nodePath.join(root, name), content);
  }
  const scanId = randomUUID(), resolvedCommit = "a".repeat(40);
  return { root, scanId, resolvedCommit, map: () => mapRepository({ scanId, resolvedCommit, repositoryPath: root }) };
}
const classification = (map: Awaited<ReturnType<typeof mapRepository>>, path: string) => map.files.find((f) => f.path === path)?.classification;

describe("deterministic Repository Mapper", () => {
  it("classifies a simple project with exact evidence and preserves multiple declarations", async () => {
    const f = await fixture({
      "contracts/core/Vault.sol": "pragma solidity ^0.8.0; contract Vault { function deposit() external {} }",
      "contracts/interfaces/IVault.sol": "interface IVault { function deposit() external; }",
      "contracts/libraries/Math.sol": "library Math { function one() internal pure returns(uint) { return 1; } }",
      "test/Vault.t.sol": "contract VaultTest {}", "script/Deploy.s.sol": "contract Deploy {}",
      "contracts/Mixed.sol": "contract A {} interface IB {} library L {}",
    });
    const map = await f.map();
    expect(classification(map, "contracts/core/Vault.sol")).toMatchObject({ automatic: "core", reasons: ["explicit-core-directory", "external-entry-point"] });
    expect(classification(map, "contracts/interfaces/IVault.sol")?.effective).toBe("interface");
    expect(classification(map, "contracts/libraries/Math.sol")?.effective).toBe("library");
    expect(classification(map, "test/Vault.t.sol")?.effective).toBe("test");
    expect(classification(map, "script/Deploy.s.sol")?.effective).toBe("deployment");
    expect(map.files.find((x) => x.path === "contracts/Mixed.sol")?.declarations.map((x) => x.kind)).toEqual(["contract", "interface", "library"]);
    expect(map.summary.contracts).toBe(4);
    expect(await f.map()).toEqual(map);
  });
  it("keeps multiple roots and dependency source distinct", async () => {
    const f = await fixture({ "src/A.sol": "contract A {}", "packages/module/contracts/B.sol": "contract B {}",
      "lib/dependency/src/C.sol": "contract C {}", "lib/Owned.sol": "library Owned {}" });
    const map = await f.map();
    expect(map.roots.map((x) => [x.path, x.kind])).toEqual([["lib", "project"], ["lib/dependency/src", "dependency"], ["packages/module/contracts", "project"], ["src", "project"]]);
    expect(classification(map, "lib/dependency/src/C.sol")?.effective).toBe("dependency");
    expect(classification(map, "lib/Owned.sol")?.effective).toBe("library");
  });
  it("avoids substring false positives and leaves ambiguous contracts unknown", async () => {
    const f = await fixture({ "contracts/TestamentVault.sol": "contract TestamentVault {}",
      "contracts/Mockingbird.sol": "contract Mockingbird {}", "mocks/FakeToken.sol": "contract FakeToken {}" });
    const map = await f.map();
    expect(classification(map, "contracts/TestamentVault.sol")?.effective).toBe("unknown");
    expect(classification(map, "contracts/Mockingbird.sol")?.effective).toBe("unknown");
    expect(classification(map, "mocks/FakeToken.sol")?.effective).toBe("mock");
  });
  it("resolves exact imports, retains unsupported aliases, and accepts cycles", async () => {
    const f = await fixture({ "src/A.sol": 'import "./B.sol"; import "src/B.sol"; import "@alias/C.sol"; contract A {}',
      "src/B.sol": 'import "./A.sol"; contract B {}' });
    const map = await f.map();
    expect(map.files.find((x) => x.path === "src/A.sol")?.imports).toEqual([
      { imported: "./B.sol", resolvedSourceUnit: "src/B.sol", status: "resolved" },
      { imported: "src/B.sol", resolvedSourceUnit: "src/B.sol", status: "resolved" },
      { imported: "@alias/C.sol", resolvedSourceUnit: null, status: "unresolved" },
    ]);
    expect(map.files.find((x) => x.path === "src/B.sol")?.imports[0].resolvedSourceUnit).toBe("src/A.sol");
  });
  it("does not invent declarations for malformed Solidity", async () => {
    const f = await fixture({ "src/Broken.sol": "contract Broken { function x() external {" });
    const file = (await f.map()).files[0];
    expect(file.parseStatus).toBe("incomplete"); expect(file.declarations).toEqual([]);
  });
  it("uses immutable snapshot bytes even when the checkout differs", async () => {
    const f = await fixture({ "src/Vault.sol": "contract Checkout {}" });
    const rawBytes = Buffer.from("contract Snapshot {}");
    const map = await mapRepository({ scanId: f.scanId, resolvedCommit: f.resolvedCommit, repositoryPath: f.root,
      snapshotFiles: [{ sourceKey: "src/Vault.sol", rawBytes, rawSha256: createHash("sha256").update(rawBytes).digest("hex"), byteLength: rawBytes.length }] });
    expect(map.files[0].declarations[0].name).toBe("Snapshot");
    expect(map.files[0].source.authority).toBe("snapshot");
  });
  it("skips symlinks and rejects forged map identities", async () => {
    const f = await fixture({ "src/A.sol": "contract A {}" });
    await symlink("../../outside", nodePath.join(f.root, "src", "escape.sol"));
    await symlink(".", nodePath.join(f.root, "src", "loop"));
    const map = await f.map();
    expect(map.warnings.filter((w) => w.code === "symlink-skipped")).toHaveLength(2);
    expect(map.files.some((x) => x.path.endsWith("escape.sol"))).toBe(false);
    expect(() => validateRepositoryMap({ ...map, id: `rm:${"0".repeat(64)}` })).toThrow();
  });
  it("rejects traversal, absolute and duplicate snapshot identities", async () => {
    const f = await fixture({ "src/A.sol": "contract A {}" });
    const rawBytes = Buffer.from("contract A {}"), source = {
      sourceKey: "src/A.sol", rawBytes, rawSha256: createHash("sha256").update(rawBytes).digest("hex"), byteLength: rawBytes.length };
    for (const sourceKey of ["../escape.sol", "/tmp/escape.sol", "src/../escape.sol"])
      await expect(mapRepository({ scanId: f.scanId, resolvedCommit: f.resolvedCommit, repositoryPath: f.root,
        snapshotFiles: [{ ...source, sourceKey }] })).rejects.toThrow();
    await expect(mapRepository({ scanId: f.scanId, resolvedCommit: f.resolvedCommit, repositoryPath: f.root,
      snapshotFiles: [source, source] })).rejects.toThrow("Duplicate snapshot source key");
  });
  it("retains exact finding and target references without elevating classification", async () => {
    const f = await fixture({ "contracts/A.sol": "contract A {}" });
    const findingId = randomUUID();
    const map = await mapRepository({ scanId: f.scanId, resolvedCommit: f.resolvedCommit, repositoryPath: f.root,
      findingRefs: [{ id: findingId, sourceUnitName: "contracts/A.sol" }],
      targetRefs: [{ id: "target-1", sourceUnitName: "contracts/A.sol" }] });
    expect(map.files[0]).toMatchObject({ findingRefs: [findingId], targetRefs: ["target-1"],
      classification: { automatic: "unknown" } });
  });
  it("keeps automatic classification when a manual override is modeled", async () => {
    const f = await fixture({ "contracts/periphery/Router.sol": "contract Router {}" });
    const cls = (await f.map()).files[0].classification;
    const updated = withRepositoryClassificationOverride(cls, { value: "core", reason: "researcher-review" });
    expect(updated).toMatchObject({ automatic: "periphery", effective: "core", override: { value: "core" } });
    expect(cls.override).toBeNull();
  });
  it("handles a representative large tree with stable ordering", async () => {
    const files = Object.fromEntries(Array.from({ length: 400 }, (_, i) => [`src/C${i}.sol`, `contract C${i} {}`]));
    const f = await fixture(files), first = await f.map(), second = await f.map();
    expect(first).toEqual(second); expect(first.files).toHaveLength(400);
    expect(new Set(first.files.map((x) => x.id)).size).toBe(400);
  });
  it("rejects duplicate file identity, invalid import targets and impossible summaries", async () => {
    const f = await fixture({ "src/A.sol": 'import "./B.sol"; contract A {}', "src/B.sol": "contract B {}" });
    const map = await f.map();
    expect(() => validateRepositoryMap({ ...map, files: [...map.files, map.files[0]] })).toThrow();
    const altered = structuredClone(map);
    altered.files[0].imports[0].resolvedSourceUnit = "src/Missing.sol";
    expect(() => validateRepositoryMap(altered)).toThrow("repository_map_import_invalid");
    expect(() => validateRepositoryMap({ ...map, summary: { ...map.summary, contracts: 10 } })).toThrow("repository_map_summary_invalid");
  });
});
