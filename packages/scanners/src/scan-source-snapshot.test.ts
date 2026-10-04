import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { closeDatabase, createDatabase, createScan, finalizeScanSourceSnapshot, getScanSource, getScanSourceSnapshot, listScanSources } from "@contracthunter/db";
import { canonicalScanSourceKey, captureScanSourceSnapshot } from "./scan-source-snapshot";

const directories: string[] = [], commit = "a".repeat(40);
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(path.join(tmpdir(), "ch-scan-snapshot-")); directories.push(root);
  const repository = path.join(root, "repository"); mkdirSync(repository);
  const database = createDatabase(path.join(root, "test.db"));
  const scan = createScan(database, { repositoryUrl: "https://github.com/example/source", repositoryName: "example/source", depth: "quick" });
  database.sqlite.prepare("UPDATE scans SET status='preparing_dependencies', dependency_status='ready', resolved_commit=? WHERE id=?").run(commit, scan.id);
  const put = (key: string, bytes: Buffer | string) => { const filename = path.join(repository, ...key.split("/")); mkdirSync(path.dirname(filename), { recursive: true }); writeFileSync(filename, bytes); };
  return { root, repository, database, scanId: scan.id, put };
}
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

describe("immutable scan source snapshots", () => {
  it("preserves CRLF, LF, trailing whitespace, and invalid UTF-8 as distinct raw bytes", async () => {
    const f = fixture();
    try {
      const values = [Buffer.from("contract A {}\r\n"), Buffer.from("contract B {}\n"), Buffer.from("contract C {}  \n"), Buffer.from([0x2f, 0x2f, 0xff, 0x0a]), Buffer.from([0x2f, 0x2f, 0xfe, 0x0a])];
      values.forEach((bytes, i) => f.put(`src/File${i}.sol`, bytes));
      const captured = await captureScanSourceSnapshot(f.repository);
      finalizeScanSourceSnapshot(f.database, f.scanId, commit, captured);
      expect(getScanSourceSnapshot(f.database, f.scanId)).toMatchObject({ available: true, fileCount: values.length });
      values.forEach((bytes, i) => {
        const stored = getScanSource(f.database, f.scanId, `src/File${i}.sol`);
        expect(stored).toMatchObject({ available: true, rawSha256: digest(bytes), byteLength: bytes.length });
        if (stored.available) expect(stored.rawBytes).toEqual(bytes);
      });
      expect(values[3].toString("utf8")).toBe(values[4].toString("utf8"));
      expect(digest(values[3])).not.toBe(digest(values[4]));
      expect(digest(values[0])).not.toBe(digest(Buffer.from("contract A {}\n")));
    } finally { closeDatabase(f.database); }
  });

  it("captures nested roots and only explicitly imported node_modules sources", async () => {
    const f = fixture();
    try {
      f.put("src/nested/Main.sol", 'import "../../node_modules/dep/Used.sol"; contract Main {}');
      f.put("node_modules/dep/Used.sol", "contract Used {}");
      f.put("node_modules/dep/Unused.sol", "contract Unused {}");
      expect((await captureScanSourceSnapshot(f.repository)).map((file) => file.sourceKey)).toEqual(["node_modules/dep/Used.sol", "src/nested/Main.sol"]);
    } finally { closeDatabase(f.database); }
  });

  it("resolves an internal directory symlink but rejects external links, loops, and aliases", async () => {
    const internal = fixture();
    try {
      internal.put("node_modules/dep/Util.sol", "contract Util {}"); mkdirSync(path.join(internal.repository, "lib")); symlinkSync("../node_modules/dep", path.join(internal.repository, "lib", "shared"));
      expect((await captureScanSourceSnapshot(internal.repository)).map((file) => file.sourceKey)).toEqual(["lib/shared/Util.sol"]);
    } finally { closeDatabase(internal.database); }
    const wrongRoot = fixture();
    try {
      wrongRoot.put("vendor/Util.sol", "contract Util {}"); mkdirSync(path.join(wrongRoot.repository, "lib")); symlinkSync("../vendor", path.join(wrongRoot.repository, "lib", "shared"));
      await expect(captureScanSourceSnapshot(wrongRoot.repository)).rejects.toMatchObject({ code: "unsafe_source" });
    } finally { closeDatabase(wrongRoot.database); }
    const escaped = fixture();
    try {
      escaped.put("src/Good.sol", "contract Good {}"); symlinkSync(tmpdir(), path.join(escaped.repository, "src", "outside"));
      await expect(captureScanSourceSnapshot(escaped.repository)).rejects.toMatchObject({ code: "unsafe_source" });
    } finally { closeDatabase(escaped.database); }
    const loop = fixture();
    try {
      loop.put("src/Good.sol", "contract Good {}"); symlinkSync(".", path.join(loop.repository, "src", "loop"));
      await expect(captureScanSourceSnapshot(loop.repository)).rejects.toMatchObject({ code: "unsafe_source" });
    } finally { closeDatabase(loop.database); }
    const alias = fixture();
    try {
      alias.put("src/Good.sol", "contract Good {}"); mkdirSync(path.join(alias.repository, "lib")); symlinkSync("../src", path.join(alias.repository, "lib", "same"));
      await expect(captureScanSourceSnapshot(alias.repository)).rejects.toMatchObject({ code: "unsafe_source" });
    } finally { closeDatabase(alias.database); }
  });

  it("rejects traversal, absolute, long, unsupported-root, and duplicate keys before persistence", async () => {
    for (const key of ["../escape.sol", "/tmp/Escape.sol", `src/${"a".repeat(500)}.sol`, "test/Only.sol", "src/../lib/A.sol"]) expect(() => canonicalScanSourceKey(key)).toThrow();
    const f = fixture();
    try {
      f.put("src/A.sol", 'import "../../escape.sol"; contract A {}');
      await expect(captureScanSourceSnapshot(f.repository)).rejects.toMatchObject({ code: "unsupported_import" });
      expect(getScanSourceSnapshot(f.database, f.scanId)).toEqual({ available: false, reason: "legacy_or_unavailable" });
      const bytes = Buffer.from("contract A {}"); const duplicate = { sourceKey: "src/A.sol", rawBytes: bytes, rawSha256: digest(bytes), byteLength: bytes.length };
      expect(() => finalizeScanSourceSnapshot(f.database, f.scanId, commit, [duplicate, duplicate])).toThrow();
      expect(getScanSourceSnapshot(f.database, f.scanId).available).toBe(false);
    } finally { closeDatabase(f.database); }
  });

  it("fails closed at file count, individual byte, and total byte limits", async () => {
    const count = fixture();
    try { for (let i = 0; i < 101; i++) count.put(`src/F${i}.sol`, "contract F {}"); await expect(captureScanSourceSnapshot(count.repository)).rejects.toMatchObject({ code: "source_limit" }); expect(getScanSourceSnapshot(count.database, count.scanId).available).toBe(false); }
    finally { closeDatabase(count.database); }
    const individual = fixture();
    try { individual.put("src/Huge.sol", Buffer.alloc(2_097_153, 0x20)); await expect(captureScanSourceSnapshot(individual.repository)).rejects.toMatchObject({ code: "source_limit" }); expect(getScanSourceSnapshot(individual.database, individual.scanId).available).toBe(false); }
    finally { closeDatabase(individual.database); }
    const total = fixture();
    try { for (let i = 0; i < 3; i++) total.put(`src/Big${i}.sol`, Buffer.alloc(2_000_000, 0x20)); await expect(captureScanSourceSnapshot(total.repository)).rejects.toMatchObject({ code: "source_limit" }); expect(getScanSourceSnapshot(total.database, total.scanId).available).toBe(false); }
    finally { closeDatabase(total.database); }
  });

  it("survives checkout mutation and deletion, stays immutable, and cascades with scan deletion", async () => {
    const f = fixture();
    try {
      const original = Buffer.from("contract Original {}\r\n"); f.put("src/A.sol", original);
      const captured = await captureScanSourceSnapshot(f.repository); finalizeScanSourceSnapshot(f.database, f.scanId, commit, captured);
      f.put("src/A.sol", "contract Changed {}"); unlinkSync(path.join(f.repository, "src/A.sol")); rmSync(f.repository, { recursive: true });
      const stored = getScanSource(f.database, f.scanId, "src/A.sol");
      expect(stored.available && stored.rawBytes).toEqual(original);
      expect(listScanSources(f.database, f.scanId)).toEqual([{ sourceKey: "src/A.sol", rawSha256: digest(original), byteLength: original.length }]);
      expect(() => finalizeScanSourceSnapshot(f.database, f.scanId, commit, captured)).toThrow();
      expect(() => f.database.sqlite.prepare("UPDATE scan_source_snapshot_files SET raw_bytes = ? WHERE scan_id = ?").run(Buffer.from("changed"), f.scanId)).toThrow();
      expect(() => f.database.sqlite.prepare("DELETE FROM scan_source_snapshot_files WHERE scan_id = ?").run(f.scanId)).toThrow();
      expect(() => f.database.sqlite.prepare("DELETE FROM scan_source_snapshots WHERE scan_id = ?").run(f.scanId)).toThrow();
      f.database.sqlite.prepare("DELETE FROM scans WHERE id = ?").run(f.scanId);
      expect(f.database.sqlite.prepare("SELECT count(*) AS count FROM scan_source_snapshot_files").get()).toEqual({ count: 0 });
    } finally { closeDatabase(f.database); }
  });

  it("rolls back an injected mid-persistence failure and leaves legacy scans unavailable", async () => {
    const f = fixture();
    try {
      expect(getScanSourceSnapshot(f.database, f.scanId)).toEqual({ available: false, reason: "legacy_or_unavailable" });
      expect(getScanSource(f.database, f.scanId, "src/A.sol")).toEqual({ available: false, reason: "legacy_or_unavailable" });
      f.put("src/A.sol", "contract A {}"); f.put("src/B.sol", "contract B {}");
      const captured = await captureScanSourceSnapshot(f.repository);
      f.database.sqlite.exec("CREATE TRIGGER test_fail_source_insert BEFORE INSERT ON scan_source_snapshot_files WHEN NEW.source_key = 'src/B.sol' BEGIN SELECT RAISE(ABORT, 'injected failure'); END");
      expect(() => finalizeScanSourceSnapshot(f.database, f.scanId, commit, captured)).toThrow();
      expect(f.database.sqlite.prepare("SELECT count(*) AS count FROM scan_source_snapshots").get()).toEqual({ count: 0 });
      expect(f.database.sqlite.prepare("SELECT count(*) AS count FROM scan_source_snapshot_files").get()).toEqual({ count: 0 });
      expect(listScanSources(f.database, f.scanId)).toEqual([]);
    } finally { closeDatabase(f.database); }
  });
});
