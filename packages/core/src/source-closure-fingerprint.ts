import { createHash } from "node:crypto";
import { AUTHORITATIVE_SOURCE_CLOSURE_SCHEMA, type ResolvedAuthoritativeSourceClosure } from "./authoritative-source-closure";
import { SCAN_SOURCE_LIMITS } from "./scan-source-snapshot";

export const SOURCE_CLOSURE_FINGERPRINT_SCHEMA = "contracthunter-source-closure-fingerprint-v1" as const;
export type SourceClosureFingerprint = {
  schema: typeof SOURCE_CLOSURE_FINGERPRINT_SCHEMA;
  sha256: string;
  fileCount: number;
  totalBytes: number;
};

type FingerprintInput = Pick<ResolvedAuthoritativeSourceClosure, "schema" | "targetSourceUnit" | "files"> & { compilationProfile: string };

/** All integers are unsigned 64-bit big-endian; strings are UTF-8 with a u64 byte-length prefix. */
export function fingerprintAuthoritativeSourceClosure(closure: FingerprintInput): SourceClosureFingerprint {
  if (closure.schema !== AUTHORITATIVE_SOURCE_CLOSURE_SCHEMA || !closure.compilationProfile || closure.compilationProfile.length > 128 ||
      !closure.targetSourceUnit || closure.targetSourceUnit.length > 1024 || !Array.isArray(closure.files) ||
      closure.files.length < 1 || closure.files.length > SCAN_SOURCE_LIMITS.files) throw new Error("Invalid authoritative source closure fingerprint input.");
  const hash = createHash("sha256");
  const integer = (value: number) => {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid authoritative source closure integer.");
    const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); hash.update(bytes);
  };
  const framed = (value: string) => {
    const bytes = Buffer.from(value, "utf8");
    if (bytes.length > 4096) throw new Error("Invalid authoritative source closure identifier.");
    integer(bytes.length); hash.update(bytes);
  };
  framed(SOURCE_CLOSURE_FINGERPRINT_SCHEMA);
  framed(closure.schema);
  framed(closure.compilationProfile);
  framed(closure.targetSourceUnit);
  const files = [...closure.files].sort((a, b) => a.sourceUnitName < b.sourceUnitName ? -1 : a.sourceUnitName > b.sourceUnitName ? 1 : 0);
  integer(files.length);
  const units = new Set<string>(), keys = new Set<string>();
  let totalBytes = 0;
  for (const file of files) {
    if (!file.sourceUnitName || !file.snapshotSourceKey || file.sourceUnitName.length > 1024 || file.snapshotSourceKey.length > 1024 ||
        units.has(file.sourceUnitName) || keys.has(file.snapshotSourceKey) || !Buffer.isBuffer(file.rawBytes) ||
        file.byteLength !== file.rawBytes.length || file.byteLength > SCAN_SOURCE_LIMITS.fileBytes ||
        !/^[a-f0-9]{64}$/.test(file.rawSha256) || createHash("sha256").update(file.rawBytes).digest("hex") !== file.rawSha256)
      throw new Error("Invalid authoritative source closure file.");
    units.add(file.sourceUnitName); keys.add(file.snapshotSourceKey);
    totalBytes += file.byteLength;
    if (totalBytes > SCAN_SOURCE_LIMITS.totalBytes) throw new Error("Authoritative source closure exceeds snapshot bounds.");
    framed(file.sourceUnitName);
    framed(file.snapshotSourceKey);
    integer(file.byteLength);
    hash.update(Buffer.from(file.rawSha256, "hex"));
  }
  if (!units.has(closure.targetSourceUnit)) throw new Error("Authoritative target source unit is outside the closure.");
  return { schema: SOURCE_CLOSURE_FINGERPRINT_SCHEMA, sha256: hash.digest("hex"), fileCount: files.length, totalBytes };
}
