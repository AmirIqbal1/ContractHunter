const STABLE_COMPILER = /^\d+\.\d+\.\d+$/;

export function createContractHunterFoundryConfig(compilerVersion: string): string {
  if (!STABLE_COMPILER.test(compilerVersion)) throw new Error("A stable Solidity compiler version is required.");
  return `[profile.default]
src = "src"
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
`;
}
