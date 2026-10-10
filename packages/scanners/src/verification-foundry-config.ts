const STABLE_COMPILER = /^\d+\.\d+\.\d+$/;

export function createContractHunterFoundryConfig(compilerVersion: string, authoritativeLayout = false): string {
  if (!STABLE_COMPILER.test(compilerVersion)) throw new Error("A stable Solidity compiler version is required.");
  return `[profile.default]
src = "${authoritativeLayout ? "." : "src"}"
test = "test"
out = "out"
cache_path = "cache"
libs = []
solc_version = "${compilerVersion}"
auto_detect_solc = false
offline = true
ffi = false
fs_permissions = []
script = ".contracthunter-disabled-scripts"
${authoritativeLayout ? "auto_detect_remappings = false\n" : ""}`;
}

export const invariantFoundrySettings = { fuzzRuns: 128, invariantRuns: 64, invariantDepth: 32, invariantFailOnRevert: false } as const;

export function createContractHunterInvariantFoundryConfig(compilerVersion: string, planHash: string, authoritativeLayout = false): string {
  if (!STABLE_COMPILER.test(compilerVersion) || !/^[a-f0-9]{64}$/.test(planHash)) throw new Error("Invariant compiler version or plan hash is invalid.");
  return `${createContractHunterFoundryConfig(compilerVersion, authoritativeLayout)}${authoritativeLayout ? "" : "auto_detect_remappings = false\n"}\n[fuzz]\nruns = ${invariantFoundrySettings.fuzzRuns}\nseed = "0x${planHash}"\n\n[invariant]\nruns = ${invariantFoundrySettings.invariantRuns}\ndepth = ${invariantFoundrySettings.invariantDepth}\nfail_on_revert = ${invariantFoundrySettings.invariantFailOnRevert}\n`;
}
