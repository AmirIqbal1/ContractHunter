import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { detectCompilerRequirements, detectFoundryCompiler, discoverSoliditySources, extractSolidityPragmas, resolveCompilerVersions } from "./compiler-detection";

async function fixture(): Promise<string> { return mkdtemp(path.join(tmpdir(), "contracthunter-solc-")); }

describe("Foundry compiler detection", () => {
  it("reads exact solc_version from the default profile", async () => {
    const root = await fixture();
    await writeFile(path.join(root, "foundry.toml"), '[profile.default]\nsolc_version = "0.8.24"\n[profile.ci]\nsolc_version = "0.7.6"');
    expect(await detectFoundryCompiler(root)).toBe("0.8.24");
  });

  it("ignores unrelated profiles and returns null without a version", async () => {
    const root = await fixture();
    await writeFile(path.join(root, "foundry.toml"), '[profile.ci]\nsolc_version = "0.7.6"');
    expect(await detectFoundryCompiler(root)).toBeNull();
  });

  it("reports malformed TOML", async () => {
    const root = await fixture();
    await writeFile(path.join(root, "foundry.toml"), "[profile.default\nsolc_version =");
    await expect(detectFoundryCompiler(root)).rejects.toThrow("Malformed foundry.toml");
  });
});

describe("Solidity pragma extraction and discovery", () => {
  it("extracts exact, caret, and comparator constraints but ignores comments and experimental pragmas", () => {
    const source = `// pragma solidity 0.4.0;\n/* pragma solidity 0.5.0; */\npragma experimental ABIEncoderV2;\npragma solidity 0.8.24;\npragma solidity ^0.8.20;\npragma solidity >=0.7.0 <0.9.0;`;
    expect(extractSolidityPragmas(source)).toEqual(["0.8.24", "^0.8.20", ">=0.7.0 <0.9.0"]);
  });

  it("collects multiple files and reports no pragma", async () => {
    const root = await fixture(); await mkdir(path.join(root, "contracts"));
    await writeFile(path.join(root, "contracts", "A.sol"), "pragma solidity ^0.8.20;");
    await writeFile(path.join(root, "contracts", "B.sol"), "contract B {}");
    const sources = await discoverSoliditySources(root);
    expect(sources).toHaveLength(2);
    expect((await detectCompilerRequirements(root)).constraints).toEqual(["^0.8.20"]);
  });

  it("does not follow symlinks outside the workspace", async () => {
    const root = await fixture(); const outside = await fixture();
    await writeFile(path.join(outside, "Escape.sol"), "pragma solidity 0.4.0;");
    await symlink(outside, path.join(root, "escape"));
    await writeFile(path.join(root, "Safe.sol"), "pragma solidity 0.8.24;");
    expect((await detectCompilerRequirements(root)).constraints).toEqual(["0.8.24"]);
  });

  it("reports no Solidity files and no detectable pragma", async () => {
    await expect(detectCompilerRequirements(await fixture())).rejects.toThrow("No Solidity source files");
    const root = await fixture(); await writeFile(path.join(root, "A.sol"), "contract A {}");
    await expect(detectCompilerRequirements(root)).rejects.toThrow("Unable to determine");
  });
});

describe("compiler constraint resolution", () => {
  const available = ["0.7.6", "0.8.19", "0.8.20", "0.8.24", "0.8.25-rc.1"];
  it("resolves exact versions and highest compatible stable releases", () => {
    expect(resolveCompilerVersions(["0.8.20"], available, 8)).toEqual(["0.8.20"]);
    expect(resolveCompilerVersions(["^0.8.20"], available, 8)).toEqual(["0.8.24"]);
  });
  it("deduplicates compatible requirements", () => {
    expect(resolveCompilerVersions(["^0.8.20", ">=0.8.19 <0.9.0", "^0.8.20"], available, 8)).toEqual(["0.8.24"]);
  });
  it("creates multiple compiler groups for incompatible ranges", () => {
    expect(resolveCompilerVersions(["^0.7.0", "^0.8.20"], available, 8)).toEqual(["0.7.6", "0.8.24"]);
  });
  it("reports unresolvable constraints and maximum-version limits", () => {
    expect(() => resolveCompilerVersions(["^0.6.0"], available, 8)).toThrow("Unable to determine");
    expect(() => resolveCompilerVersions(["0.7.6", "0.8.20"], available, 1)).toThrow("configured limit");
  });
  it("reports conflicting constraints within one source unit", () => {
    expect(() => resolveCompilerVersions([">=0.7.0 <0.8.0 >=0.8.20 <0.9.0"], available, 8)).toThrow("Unable to determine");
  });
});
