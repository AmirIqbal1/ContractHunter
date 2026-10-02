# Echidna compatibility build (ContractHunter v0.2.1 release preparation)

ContractHunter uses a locally modified build of [crytic/echidna](https://github.com/crytic/echidna), upstream tag `v2.3.3`, commit `4454f3a337ed58e89a3be488b8eac03e83cd40f2`. The official source archive is included as `upstream-v2.3.3.tar.gz` (SHA-256 `fab7817640a613856365766031518a8bde5471a9fb14618dfb0b77e3820a7cba`). Its license is reproduced in `LICENSE`.

`contracthunter-compat-v1.patch` (SHA-256 `03fd0c880d555108525f0c0e78812c794bdfe9a4a37f568946b7b862cb4b0e2e`) changes only JSON output identity and terminal classification, stdout purity, and bounded shrink finalization. The upstream version still reports `Echidna 2.3.3`; the distinct compatibility ID is `contracthunter-echidna-compat-v1`, and structured results report `2.3.3+contracthunter.1`. No fuzzing, EVM, mutation, ABI, coverage, or transaction execution logic is modified.

## Build and dependency locks

`docker/echidna/build.sh` verifies the archive and patch, extracts the source to `/src`, applies the patch using the **locked nixpkgs `patch` package**, verifies upstream `flake.lock` and the patched source NAR hash, then builds `packages.x86_64-linux.echidna-redistributable` with `max-jobs=1` and `cores=1`. It verifies the resulting binary SHA-256 and upstream reported version. The builder is `docker.io/nixos/nix:2.24.14@sha256:4411619b45575be9fb47063c0878e2d9ef86988678b23c01bf3dd1b967d753fc`. Upstream `flake.lock` pins nixpkgs to `af84f9d270d404c17699522fab95bbf928a2d92f`, including Haskell and C library dependencies; the lock file SHA-256 is `2257be1d516bbcc315f2d14bb374757e6a75b626b5205b74fafee840b0c64de2`. Inputs come from content-addressed, signed Nix caches during image build. Runtime execution performs no package installation or download.

Two independent clean serial Nix builds produced byte-identical binary SHA-256 `b6f84d8d48fcffe4d48b9be0378e65f37a36c304c3325d72aa868fcfac204ff1`. The ELF is static (`ldd`: not a dynamic executable; `readelf -d`: no dynamic section). This includes `libsecp256k1` statically, so no `libsecp256k1.so.5` or other Echidna runtime library is required. Parallel `-j2` builds yielded different `.data` pointer ordering; the production recipe therefore fixes `-j1` and checks the exact binary hash without post-link normalization.

Echidna invokes `crytic-compile` to compile Solidity. The worker image gets `crytic-compile==0.3.11` and its full Python dependency set through `crytic-requirements.lock`, with hashes for exact Python 3.11 x86_64 wheels. The Python source image is `docker.io/library/python:3.11-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b`. The worker passes the exact trusted, locally cached solc path to crytic-compile. The worker has no runtime network.

The build is currently x86_64 only. The Nix stage rejects a different architecture, and the worker image must use an x86_64 Python runtime. A separate arm64 reproducibility proof is needed before enabling arm64.

`build-manifest.json` is machine-readable build metadata; `checksums.txt` records source, patch, lock, recipe, license, and manifest hashes. The worker checks the copied root-owned executable's real path, regular-file status, executable bit, SHA-256, reported upstream version, and build ID before opening its socket.

## Distribution

Echidna is AGPLv3. Distribution of this modified binary requires appropriate corresponding-source handling under that license, including the exact upstream source, the compatibility patch, build recipe, dependency lock, and applicable notices. The files here retain those materials for review. This is a practical distribution consideration, not a legal conclusion.
