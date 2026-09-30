#!/bin/sh
set -eu
echo 'fab7817640a613856365766031518a8bde5471a9fb14618dfb0b77e3820a7cba  /build/upstream-v2.3.3.tar.gz' | sha256sum -c -
echo '03fd0c880d555108525f0c0e78812c794bdfe9a4a37f568946b7b862cb4b0e2e  /build/contracthunter-compat-v1.patch' | sha256sum -c -
mkdir /src /out
tar -xzf /build/upstream-v2.3.3.tar.gz -C /src --strip-components=1
cd /src
nix shell --extra-experimental-features 'nix-command flakes' \
  --option sandbox false --option max-jobs 1 --option cores 1 \
  --option substituters 'https://trailofbits.cachix.org https://cache.nixos.org' \
  --option trusted-public-keys 'trailofbits.cachix.org-1:jRuxrlFghP6HstIaZg7DhvTgHyK/lcYa7U8y3CgKjzU= cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=' \
  --inputs-from path:/src nixpkgs#patch --command patch -p1 < /build/contracthunter-compat-v1.patch
test "$(sha256sum flake.lock | cut -d ' ' -f 1)" = 2257be1d516bbcc315f2d14bb374757e6a75b626b5205b74fafee840b0c64de2
test "$(nix hash path --extra-experimental-features 'nix-command flakes' /src)" = 'sha256-29jP6+U6k4H60+foTc37Vl7Mbd/dRSDowUHq10jc19Y='
nix build --extra-experimental-features 'nix-command flakes' \
  --option sandbox false --option max-jobs 1 --option cores 1 \
  --option substituters 'https://trailofbits.cachix.org https://cache.nixos.org' \
  --option trusted-public-keys 'trailofbits.cachix.org-1:jRuxrlFghP6HstIaZg7DhvTgHyK/lcYa7U8y3CgKjzU= cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=' \
  --no-link --print-build-logs --print-out-paths 'path:/src#packages.x86_64-linux.echidna-redistributable' > /out/nix-output-path.txt
result_path=$(tail -n 1 /out/nix-output-path.txt)
cp "$result_path/bin/echidna" /out/echidna
echo 'b6f84d8d48fcffe4d48b9be0378e65f37a36c304c3325d72aa868fcfac204ff1  /out/echidna' | sha256sum -c -
test "$(/out/echidna --version)" = 'Echidna 2.3.3'
