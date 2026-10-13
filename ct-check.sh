#!/usr/bin/env bash
#
# Instruction-level constant-time check for mlkem-selkie.
#
# Disassembles the x86-64 build of the crate and its dependencies for the serial and AVX2 backends
# and reports every instruction that is not on Intel's DOIT (Data Operand Independent Timing) list,
# plus divides and calls to software divide routines. See ct-check/scan-instrs.py for the details.
#
# This is the complement of tests/ctgrind.rs, which runs under Valgrind (the `ctgrind` job in
# .github/workflows/ct.yml) and catches secret-dependent branches and memory addresses but is
# blind to variable-latency instructions. Neither replaces the other.
#
# Requires python3, the x86_64-unknown-linux-gnu target, and llvm-objdump (on PATH, or from
# `rustup component add llvm-tools`). Works from any host: the scan only builds rlibs, which need
# no linker.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

SELFTEST=0

usage() {
    cat <<'USAGE'
usage: ./ct-check.sh [--selftest]

Builds the crate four ways and scans each:

  serial      portable backend, baseline x86-64
  serial-v3   portable backend, x86-64-v3 (BMI1/2, LZCNT, POPCNT available)
  avx2        AVX2 backend, x86-64-v3 (what .cargo/config.toml builds)
  avx2-size   AVX2 backend, x86-64-v3, opt-level=s

All four always run; there is no flag to narrow that. A partial run makes a weaker claim while
looking exactly like a full one.

  --selftest    run the negative controls instead: plants divides the scan must find, checks the
                mnemonic classifier, and checks that no allowlist entry covers secret-handling
                code. Passes only if the planted problems ARE found.
  -h, --help    this message

Exit status is 0 if every hit is covered by ct-check/instr-allowlist.txt, 1 otherwise.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --selftest) SELFTEST=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ct-check.sh: unrecognised argument '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "ct-check.sh: python3 is needed for the instruction scan" >&2
    exit 2
fi

ARGS=()
[[ $SELFTEST -eq 1 ]] && ARGS+=(--selftest)

set +e
python3 ct-check/scan-instrs.py "${ARGS[@]+"${ARGS[@]}"}"
STATUS=$?
set -e

echo
if [[ $STATUS -eq 0 ]]; then
    echo "=== ct-check: PASS (instruction scan; run tests/ctgrind.rs under Valgrind for branches and addresses) ==="
else
    echo "=== ct-check: FAIL ===" >&2
fi
exit $STATUS
