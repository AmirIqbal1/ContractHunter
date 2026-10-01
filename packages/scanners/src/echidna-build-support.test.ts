import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ECHIDNA_BINARY_SHA256, ECHIDNA_BUILD_ID, ECHIDNA_COMPAT_VERSION, ECHIDNA_UPSTREAM_VERSION } from "@contracthunter/core";

const root = path.resolve(import.meta.dirname, "../../..");
const read = (file: string) => readFileSync(path.join(root, file));
describe("retained Echidna build support", () => {
  it("keeps source, patch, lock, license, recipe, manifest, and Docker pins aligned", () => {
    const manifest = JSON.parse(read("third_party/echidna/build-manifest.json").toString("utf8")) as Record<string, string>;
    const checksums = read("third_party/echidna/checksums.txt").toString("utf8").trim().split("\n");
    for (const line of checksums) {
      const match = /^([a-f0-9]{64})  ([A-Za-z0-9_./-]+)$/.exec(line); expect(match).not.toBeNull();
      expect(createHash("sha256").update(read(match![2])).digest("hex")).toBe(match![1]);
    }
    expect(manifest).toMatchObject({ schema: "contracthunter-echidna-build-v1", buildId: ECHIDNA_BUILD_ID, upstreamVersion: ECHIDNA_UPSTREAM_VERSION, compatibilityVersion: ECHIDNA_COMPAT_VERSION, binarySha256: ECHIDNA_BINARY_SHA256 });
    const digestFor = (file: string) => createHash("sha256").update(read(file)).digest("hex");
    expect(manifest.sourceArchiveSha256).toBe(digestFor("third_party/echidna/upstream-v2.3.3.tar.gz"));
    expect(manifest.compatibilityPatchSha256).toBe(digestFor("third_party/echidna/contracthunter-compat-v1.patch"));
    expect(manifest.cryticRequirementsLockSha256).toBe(digestFor("third_party/echidna/crytic-requirements.lock"));
    const recipe = read("docker/echidna/build.sh").toString("utf8"), dockerfile = read("Dockerfile").toString("utf8"), notice = read("third_party/echidna/README.md").toString("utf8"), license = read("third_party/echidna/LICENSE").toString("utf8");
    for (const value of [manifest.sourceArchiveSha256, manifest.compatibilityPatchSha256, manifest.flakeLockSha256, manifest.patchedSourceNarHash, manifest.binarySha256]) expect(recipe).toContain(value);
    expect(recipe).toContain("--option max-jobs 1 --option cores 1");
    for (const value of [manifest.builderImage, manifest.pythonRuntimeImage]) expect(dockerfile).toContain(value.replace("docker.io/library/", "").replace("docker.io/", ""));
    expect(dockerfile).toContain("--require-hashes -r /build/crytic-requirements.lock");
    for (const value of [manifest.upstreamCommit, manifest.sourceArchiveSha256, manifest.compatibilityPatchSha256, manifest.buildId, manifest.binarySha256]) expect(notice).toContain(value);
    expect(license).toMatch(/GNU AFFERO GENERAL PUBLIC LICENSE/i);
  });
});
