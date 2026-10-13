# Instruction-scan findings

`./ct-check.sh` as of commit `08f984c`, rustc 1.98.1, 2026-10-13. The scan fails: 156 instructions
in 31 (mnemonic, symbol) groups are not on Intel's DOIT list and are not allowlisted. They come
from seven places in the source that operate on secret data, plus one false positive that is kept
out of the allowlist on purpose.

Source lines were found by rebuilding each config with `-C debuginfo=line-tables-only` (which
produced the same instruction counts as the scanned builds) and reading `llvm-objdump -l`. Where
the innermost line is inside `core` or `stdarch`, the call site below was found by reading the
code around the instruction.

## Findings

| # | Instruction | Config | Source | Data |
|---|---|---|---|---|
| 1 | `vpmaxsd`, `vpminsd` | avx2, avx2-size | `src/algebraic/poly/arch/avx2.rs:261` | secret |
| 2 | `vunpcklpd`, `vunpckhpd` | avx2, serial-v3 | sha3-selkie `src/backend/avx2.rs:87-90, 167-170` | secret |
| 3 | `movmskps` | serial | `src/lib.rs:513` (via subtle `src/lib.rs:354`) | secret |
| 4 | `shufps` | serial | `src/algebraic/field.rs:71, 209, 224`; `src/sampling.rs:165` | secret |
| 5 | `andps` | serial | `src/algebraic/field.rs:211` | secret |
| 6 | `bzhi` | serial-v3 | `src/algebraic/field.rs:211` | secret |
| 7 | `vshufps` | serial-v3 | `src/algebraic/poly/arch/generic.rs:179`; `src/algebraic/field.rs:209` | secret |

1. **AVX2 `decompress` clamps before packing.** `pack_lanes` calls `_mm256_packus_epi32`, and in
   `avx2::decompress` LLVM emits a `vpmaxsd`/`vpminsd` clamp ahead of the `vpackusdw`. This path
   also decompresses the message in `from_message`. `VPACKUSDW` is listed, and so are the
   unsigned `VPMAXUD`/`VPMINUD`; the signed forms are not. `compress` calls the same
   `pack_lanes` without getting the clamp.

2. **sha3-selkie's 4-way Keccak transposes.** `_mm256_unpacklo_epi64`/`_mm256_unpackhi_epi64`
   come out as the floating-point `vunpcklpd`/`vunpckhpd` instead of the listed
   `VPUNPCKLQDQ`/`VPUNPCKHQDQ`. Keccak hashes the secret seeds (G, J and PRF), and this code is
   in the dependency, not this crate. It also appears in serial-v3, because sha3-selkie picks its
   backend from target features alone.

3. **The ciphertext comparison in `decapsulate`.** `ciphertext.0.ct_eq(&c_prime)` inlines
   subtle's byte `ct_eq` over the slice. LLVM vectorizes the loop and reduces the result with
   `pcmpeqd` + `movmskps`. The operand is the comparison result: whether implicit rejection
   fires. `PMOVMSKB` is listed; `MOVMSKPS` is not.

4. **Baseline SSE2 narrowing.** At baseline x86-64, LLVM vectorizes the `u64` arithmetic in
   `FieldElement::new` (`field.rs:71`), `compress` (`:209`) and `decompress` (`:224`), and the
   CBD subtraction (`sampling.rs:165`). It uses `shufps` to narrow 64-bit lanes back to 32-bit,
   since SSE2 has no integer instruction for that. Reached from `compress`, `decompress`,
   `from_message`, `decode_decompress` and `sample_cbd`.

5. **`compress`'s mask in the float domain.** `quotient & ((1 << d) - 1)` is done with `andps`
   where `pand` (listed) would do.

6. **`compress`'s mask with BMI2.** With BMI2 available, the same mask becomes `bzhi`.

7. **Even/odd split.** `pack`'s loop (`generic.rs:179`) splits coefficients into evens and odds
   with `vshufps`. That is inlined into `RqElement::ntt`, `TqElement::new`, `byte_decode`,
   `sample_ntt` and `sample_ntt_x4`. Line 209 is the same narrowing as item 4, VEX-encoded.

Items 1 and 2 are the AVX2 build that `.cargo/config.toml` produces. Items 3-7 are the serial
backend, with 6 and 7 appearing only when it is built for x86-64-v3. Items 1, 2, 3 and 4 are LLVM
choosing an instruction the source didn't ask for. kopis fixed the same kind of rewrite by pinning
the intended instruction with `asm!`.

## False positive: the serial NTT's `div`

`div` in `generic::ntt` and `generic::ntt_inverse` (serial, serial-v3), from
`src/algebraic/poly/arch/generic.rs:46, 76`. `(0..256).step_by(2 * len)` computes its trip count
with `div_ceil`, dividing 256 by `2 * len`. `len` comes from the constant `NTT_SERIES`, so both
operands are public and the divide leaks nothing.

It still fails the scan because it is not allowlisted, deliberately: `generic::ntt` handles secret
coefficients, and an entry covering it would also hide any later divide on secret data in the
same function (`--selftest` rejects such an entry). Rewriting the loop as
`while start < 256 { ...; start += 2 * len }` would remove the divide and the finding.

## Allowlisted (public operands)

These are in `instr-allowlist.txt` with reasons. Listed here so the report covers every hit.

| Instruction | Source | Why public |
|---|---|---|
| `div` | `src/PKE.rs:386` (`TqMatrix::expand`) | `(n % k, n / k)`: loop counter and module rank |
| `div` | `src/encoding.rs:145` (`RqVector::decode_decompress`) | `chunks_exact(32 * d)`: ciphertext length and `d` |
| `div` | `core::slice::iter` (`ChunksExact`), `core::iter::adapters::zip` | slice lengths |
| `popcnt` | `src/sampling/arch/avx2.rs:99` (`mask.count_ones()`) | rejection sampling of XOF(`rho`); `rho` is public |

`vmovups`, `vmovaps` and `vxorps` are accepted for all code (`X86_EXTRA` in `scan-instrs.py`) as
the VEX forms of the listed `MOVUPS`, `MOVAPS` and `XORPS`.
