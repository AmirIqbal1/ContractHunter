/** Keccak-256 for canonical EVM function selectors. SHA3-256 has different padding. */
const mask = (1n << 64n) - 1n;
const rotations = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
  41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const roundConstants = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
function rotate(value: bigint, count: number): bigint {
  return count === 0 ? value : ((value << BigInt(count)) | (value >> BigInt(64 - count))) & mask;
}
function permute(state: bigint[]): void {
  for (const round of roundConstants) {
    const columns = Array.from({ length: 5 }, (_, x) => state[x]! ^ state[x + 5]! ^ state[x + 10]! ^ state[x + 15]! ^ state[x + 20]!);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      state[x + 5 * y] = state[x + 5 * y]! ^ columns[(x + 4) % 5]! ^ rotate(columns[(x + 1) % 5]!, 1);
    const moved = Array<bigint>(25).fill(0n);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      moved[y + 5 * ((2 * x + 3 * y) % 5)] = rotate(state[x + 5 * y]!, rotations[x + 5 * y]!);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++)
      state[x + 5 * y] = moved[x + 5 * y]! ^ ((~moved[(x + 1) % 5 + 5 * y]!) & moved[(x + 2) % 5 + 5 * y]!);
    state[0] = state[0]! ^ round;
  }
}
export function keccak256(value: string): string {
  const bytes = Buffer.from(value, "utf8"), rate = 136, padded = Buffer.alloc(Math.ceil((bytes.length + 1) / rate) * rate);
  bytes.copy(padded); padded[bytes.length] = 0x01; padded[padded.length - 1] |= 0x80;
  const state = Array<bigint>(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate; i++) state[Math.floor(i / 8)] = state[Math.floor(i / 8)]! ^
      (BigInt(padded[offset + i]!) << BigInt(8 * (i % 8)));
    permute(state);
  }
  return `0x${Array.from({ length: 32 }, (_, i) => Number((state[Math.floor(i / 8)]! >> BigInt(8 * (i % 8))) & 0xffn)
    .toString(16).padStart(2, "0")).join("")}`;
}
/** Unsupported or noncanonical compiler type strings never produce selector guesses. */
export function canonicalFunctionSelector(signature: string): string | null {
  const match = /^([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)$/.exec(signature);
  if (!match || ["receive", "fallback", "constructor"].includes(match[1]!)) return null;
  const type = /^(?:address|bool|string|bytes|bytes(?:[1-9]|[12][0-9]|3[012])|u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256))(?:\[(?:0|[1-9][0-9]*)\])*$/;
  if (match[2] && match[2]!.split(",").some((part) => !type.test(part))) return null;
  return keccak256(signature).slice(0, 10);
}
