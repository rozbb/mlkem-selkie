#!/usr/bin/env python3
"""Scans mlkem-selkie's compiled x86-64 code for instructions whose latency depends on operands.

This is the half of constant-time checking that Valgrind cannot do. Memcheck (tests/ctgrind.rs)
reports branches and memory addresses that depend on a secret, which is most leaks, but it is
blind to a `div` whose divisor is secret: the taint flows through the quotient without ever
reaching a branch. Nothing in the definedness model notices that the instruction took a different
number of cycles.

So this pass works the other way round, on the instruction stream instead of the data. It cannot
tell a secret operand from a public one — that is what the allowlist is for.

x86 is checked against an allowlist rather than a denylist: Intel's published DOIT instructions
(`x86-doit.txt`) plus the few in `X86_EXTRA`. Anything else is reported, including instructions
nobody thought to put on a denylist.

Two failure modes are worth knowing about, because both fail *toward* a clean report:

  * the host `objdump` may be built for another architecture and print nothing at all, exiting 0
    while doing so. We use `llvm-objdump` and assert we actually saw code.
  * the API is generic over the parameter set, so `libmlkem_selkie.rlib` on its own need not hold
    every instantiation. That is what `ct-check/probe` is for; we disassemble it alongside
    mlkem-selkie and every dependency that ends up in the target binary (sha3-selkie included).

Calls to compiler-rt division helpers (`__udivti3`, ...) are flagged too: a divide too wide for the
hardware becomes one of these instead of a `div`. They are found through the call's relocation,
since the callee is not in the rlib.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
PROBE = HERE / "probe"
ALLOWLIST = HERE / "instr-allowlist.txt"
X86_DOIT = HERE / "x86-doit.txt"
TARGET_DIR = REPO / "target" / "ct-scan"

# Always cross-compiled for this target, even on an x86-64 host: an rlib is just an archive, so
# no linker is needed, and pinning it means the scan does the same thing from any host.
TARGET = "x86_64-unknown-linux-gnu"

# If a disassembly yields fewer instructions than this, something went wrong with the tooling
# rather than the code being small; treat it as an error instead of a pass.
MIN_PLAUSIBLE_INSNS = 2000

# (label, RUSTFLAGS, MLKEM_SELKIE_BACKEND). The backend variable makes build.rs fail the build
# rather than quietly pick a different backend from the one the label claims.
#
# An explicit RUSTFLAGS replaces the `-C target-cpu=x86-64-v3` in .cargo/config.toml, so the serial
# config really is baseline x86-64.
CONFIGS = [
    # The portable backend at the x86-64 baseline: what a plain build for a generic target gets.
    ("serial", "", "scalar"),
    # The portable backend with BMI1/2, LZCNT and POPCNT available. The baseline build has none of
    # those, so a `count_ones` or `trailing_zeros` on secret data only shows up here.
    ("serial-v3", "-C target-cpu=x86-64-v3", "scalar"),
    # The AVX2 backend, as built by this repo's .cargo/config.toml.
    ("avx2", "-C target-cpu=x86-64-v3", "simd"),
    # A size-optimized build. At opt-level 3 LLVM vectorizes loops that at `s` stay scalar and use
    # the BMI/LZCNT/POPCNT forms instead, so this sees instructions the default build hides.
    ("avx2-size", "-C target-cpu=x86-64-v3 -C opt-level=s", "simd"),
]

DIV_LIBCALL = (
    "div-libcall",
    re.compile(r"^R_\S+ (__u?(div|mod|divmod)[sdt]i[34])\b"),
    "Call to a software divide: as variable-time as the instruction it replaces",
)

# x86 instructions that are not on Intel's list but are accepted anyway. Each is a claim that the
# instruction's timing does not depend on its data. The scan fails if an entry stops being needed.
X86_EXTRA = {
    # Control flow. A secret-dependent branch is ctgrind's to find.
    "call": "control flow",
    "ret": "control flow",
    "nop": "no operands",
    "ud2": "no operands",
    # LLVM's default encodings for copying and zeroing vectors: every register-to-register copy,
    # every `memcpy`/`memset` it inlines (including in dependencies), and the zeroing idiom. No
    # source change reaches these, and the legacy forms MOVAPS, MOVUPS, and XORPS are listed.
    "vmovaps": "VEX form of MOVAPS, which is listed",
    "vmovups": "VEX form of MOVUPS, which is listed",
    "vxorps": "VEX form of XORPS, which is listed",
}
X86_EXTRA_USED = set()
X86_BRANCH = re.compile(r"^j[a-z]+$")

X86_IGNORED_PREFIXES = {"data16", "cs", "ds", "es", "fs", "gs", "ss", "notrack", "lock"}
X86_REP_PREFIXES = {"rep", "repe", "repz", "repne", "repnz"}
# LLVM's condition-code spellings, mapped to the ones Intel's list uses.
X86_CC = {"e": "z", "ne": "nz", "ae": "nb", "nae": "b", "c": "b", "nc": "nb", "a": "nbe",
          "na": "be", "ge": "nl", "nge": "l", "g": "nle", "ng": "le", "pe": "p", "po": "np"}


def x86_mnemonic(text: str) -> str:
    """The mnemonic of an Intel-syntax instruction, spelled as Intel's DOIT list spells it."""
    words = text.split()
    while words and words[0] in X86_IGNORED_PREFIXES:
        words = words[1:]
    if not words:
        return ""
    m = words[0]
    if m in X86_REP_PREFIXES and len(words) > 1:
        return f"{m}_{words[1]}"
    if m == "movabs":
        return "mov"
    # MOVSD is both a string move (listed) and an SSE scalar move (not).
    if m == "movsd" and "xmm" in text:
        return "movsd(sse)"
    cc = re.match(r"^(cmov|set)([a-z]+)$", m)
    if cc and cc.group(2) in X86_CC:
        return cc.group(1) + X86_CC[cc.group(2)]
    return m


def load_doit(path: Path) -> set:
    return {line.strip().lower() for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")}


def classifier():
    """A function from one disassembled row to the [(category, description)] it falls under."""
    doit = load_doit(X86_DOIT)

    def classify(text):
        if text.startswith("R_"):
            name, rx, desc = DIV_LIBCALL
            return [(name, desc)] if rx.match(text) else []
        m = x86_mnemonic(text)
        if m in X86_EXTRA:
            X86_EXTRA_USED.add(m)
            return []
        if m in doit or X86_BRANCH.match(m):
            return []
        return [(f"non-doit:{m}", "not on Intel's DOIT list (ct-check/x86-doit.txt)")]

    return classify


def check_target_installed():
    out = subprocess.run(["rustup", "target", "list", "--installed"],
                         capture_output=True, text=True)
    if out.returncode == 0 and TARGET not in out.stdout.split():
        raise SystemExit(f"scan-instrs: target {TARGET} is not installed "
                         f"(`rustup target add {TARGET}`)")


def find_llvm_objdump() -> str:
    found = shutil.which("llvm-objdump")
    if found:
        return found
    # Shipped by the `llvm-tools` rustup component. Prefer the active toolchain's copy, but any
    # toolchain's will do — it is only being used as a disassembler.
    sysroot = subprocess.run(["rustc", "--print", "sysroot"],
                             capture_output=True, text=True, check=True).stdout.strip()
    for cand in Path(sysroot).glob("lib/rustlib/*/bin/llvm-objdump"):
        return str(cand)
    rustup_home = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup"))
    for cand in sorted(rustup_home.glob("toolchains/*/lib/rustlib/*/bin/llvm-objdump")):
        return str(cand)
    raise SystemExit(
        "scan-instrs: llvm-objdump not found.\n"
        "  Install it with `rustup component add llvm-tools`, or put llvm-objdump on PATH.\n"
        "  The system `objdump` is not a substitute: one built for another architecture prints\n"
        "  nothing, successfully."
    )


def build(label: str, rustflags: str, backend: str) -> list:
    """Builds the probe for one configuration; returns its rlib and those of every dependency
    compiled for TARGET (build-time dependencies such as build scripts are built for the host and
    never reach the binary)."""
    # Seeded from the repo's lock every time, so the dependency versions scanned are the ones the
    # crate is tested against. Cargo adds the probe and drops the dev-dependencies.
    shutil.copyfile(REPO / "Cargo.lock", PROBE / "Cargo.lock")

    # The allowlist matches on symbol names, so the mangling is pinned rather than left to the
    # toolchain's default, which has changed between releases.
    env = {**os.environ,
           "RUSTFLAGS": f"{rustflags} -C symbol-mangling-version=v0",
           "MLKEM_SELKIE_BACKEND": backend,
           # One directory per config, so switching RUSTFLAGS does not rebuild everything each run.
           "CARGO_TARGET_DIR": str(TARGET_DIR / label)}
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    proc = subprocess.run(
        ["cargo", "build", "--manifest-path", str(PROBE / "Cargo.toml"), "--release",
         "--target", TARGET, "--message-format=json-render-diagnostics"],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"scan-instrs: build failed for {label} "
                         f"(RUSTFLAGS={rustflags!r}, MLKEM_SELKIE_BACKEND={backend})")

    rlibs = []
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        rlibs += [f for f in msg.get("filenames", [])
                  if f.endswith(".rlib") and f"/{TARGET}/" in f]
    if not any("libmlkem_selkie-" in r for r in rlibs):
        raise SystemExit(f"scan-instrs: {label} produced no libmlkem_selkie rlib to scan")
    return rlibs


def disassemble(objdump: str, rlibs: list):
    """Yields (symbol, instruction-text) and the total instruction count. Relocations are yielded
    as rows too, as `R_<type> <target>`, but not counted. Intel syntax, whose mnemonics carry no
    operand-size suffix and so match Intel's DOIT list directly."""
    proc = subprocess.run([objdump, "-d", "-r", "--demangle", "--no-show-raw-insn", "-M", "intel",
                           *rlibs], capture_output=True, text=True)
    sym, total, rows = None, 0, []
    for line in proc.stdout.splitlines():
        header = re.match(r"^[0-9a-f]+ <(.+)>:", line)
        if header:
            sym = header.group(1)
            continue
        insn = re.match(r"^\s*[0-9a-f]+:\s+(\S.*)$", line)
        if not insn or sym is None:
            continue
        text = " ".join(insn.group(1).split())
        if not text.startswith("R_"):
            total += 1
        rows.append((sym, text))
    return rows, total


def load_allowlist(path: Path):
    entries = []
    if not path.is_file():
        return entries
    for raw in path.read_text().splitlines():
        # A comment is a `#` at the start or after whitespace: demangled closures (`{closure#1}`)
        # have one inside the symbol.
        line = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            raise SystemExit(f"scan-instrs: malformed allowlist line: {raw!r}")
        entries.append((parts[0], parts[1], parts[2]))
    return entries


# --------------------------------------------------------------------------------------------
# Self-test
#
# The scan's failure mode is silence: a regex that stopped matching, a disassembler whose output
# format moved, or an allowlist entry broad enough to swallow a real finding all produce a clean
# report rather than an error. None of that is visible from a passing run, so the checks below
# plant things the scanner is required to find.
# --------------------------------------------------------------------------------------------

# (instruction text, category it must be reported as, or None for "must stay silent")
MATCHER_CASES = [
    ("div ecx", "non-doit:div"),
    ("idiv rbx", "non-doit:idiv"),
    ("div r14b", "non-doit:div"),
    ("pext rcx, rbx, rax", "non-doit:pext"),
    ("pdep eax, ecx, edx", "non-doit:pdep"),
    ("divss xmm0, xmm1", "non-doit:divss"),
    ("vsqrtpd ymm0, ymm1", "non-doit:vsqrtpd"),
    ("sqrtsd xmm0, xmm1", "non-doit:sqrtsd"),
    ("vdivps ymm0, ymm1, ymm2", "non-doit:vdivps"),
    ("rep cmpsb byte ptr [rsi], byte ptr es:[rdi]", "non-doit:rep_cmpsb"),
    ("repe scasb al, byte ptr es:[rdi]", "non-doit:repe_scasb"),
    ("vpgatherdd ymm0, ymmword ptr [rax + 4*ymm1], ymm2", "non-doit:vpgatherdd"),
    ("popcnt ecx, eax", "non-doit:popcnt"),
    ("tzcnt ecx, eax", "non-doit:tzcnt"),
    ("rep stosq qword ptr es:[rdi], rax", "non-doit:rep_stosq"),
    ("lock cmpxchg qword ptr [rdi], rsi", "non-doit:cmpxchg"),
    ("vshufps ymm0, ymm0, ymm1, 0x88", "non-doit:vshufps"),
    ("vunpcklpd ymm0, ymm0, ymm1", "non-doit:vunpcklpd"),
    ("vpmaxsd ymm0, ymm0, ymm1", "non-doit:vpmaxsd"),
    ("movmskps eax, xmm0", "non-doit:movmskps"),
    # On the list, possibly under another spelling.
    ("shl rax, cl", None),
    ("imul rax, rbx", None),
    ("cmove ecx, eax", None),
    ("cmovae ecx, eax", None),
    ("sete al", None),
    ("movabs rax, 0x123456789", None),
    ("rep movsb byte ptr es:[rdi], byte ptr [rsi]", None),
    ("movsd dword ptr es:[rdi], dword ptr [rsi]", None),
    ("vpmullw ymm3, ymm2, ymm1", None),
    ("nop word ptr cs:[rax + rax]", None),
    # In X86_EXTRA, or a branch.
    ("jne 0x40", None),
    ("vxorps xmm0, xmm0, xmm0", None),
    ("vmovups ymmword ptr [rdi], ymm0", None),
    ("R_X86_64_PLT32 __udivti3-0x4", "div-libcall"),
    ("R_X86_64_PLT32 __umodti3-0x4", "div-libcall"),
    ("R_X86_64_PLT32 memcpy-0x4", None),
]

# Symbols that must never be covered by an allowlist entry. If one is, someone has written a
# pattern broad enough to hide a finding in the code that actually touches secrets.
ALLOWLIST_MUST_NOT_COVER = [
    "<mlkem_selkie::DecapsulationKey<mlkem_selkie::parameters::MLKEM768>>::decapsulate",
    "<mlkem_selkie::DecapsulationKey<mlkem_selkie::parameters::MLKEM768>>::generate_derand",
    "<mlkem_selkie::PKE::DecryptionKey<mlkem_selkie::parameters::MLKEM768>>::decrypt",
    "<mlkem_selkie::algebraic::poly::RqElement>::sample_cbd",
    "<mlkem_selkie::algebraic::poly::RqElement>::compress_encode",
    "<mlkem_selkie::algebraic::poly::RqElement>::from_message",
    "mlkem_selkie::algebraic::poly::arch::generic::ntt",
    "mlkem_selkie::algebraic::poly::arch::generic::ntt_inverse",
    "mlkem_selkie::algebraic::poly::arch::avx2::ntt",
    "mlkem_selkie::algebraic::poly::arch::avx2::decompress",
    "<[[u64; 25]; 4] as sha3_selkie::backend::Batch>::permute",
    "<sha3_selkie::backend::State>::permute",
]

# A 32-bit divide, which every x86-64 build has a hardware instruction for, and a 128-bit one,
# which none does (`__udivti3`).
PLANTED_SRC = """#![no_std]
#[no_mangle]
pub extern "C" fn mlkem_ct_planted_divide(a: u32, b: u32) -> u32 {
    a / b
}
#[no_mangle]
pub extern "C" fn mlkem_ct_planted_libcall128(a: u128, b: u128) -> u128 {
    a / b
}
"""


def selftest(objdump: str, allowlist) -> int:
    import tempfile

    failures = []

    # 1. The matchers still classify what they are supposed to, and stay quiet otherwise.
    classify = classifier()
    for text, want in MATCHER_CASES:
        got = [n for n, _ in classify(text)]
        if want is None and got:
            failures.append(f"{text!r} should not be flagged, but matched {got}")
        elif want is not None and want not in got:
            failures.append(f"{text!r} should be flagged as {want}, but matched {got or 'nothing'}")
    print(f"  matchers:   {len(MATCHER_CASES)} cases, "
          f"{len(MATCHER_CASES) - len(failures)} passed")

    # 2. No allowlist entry is broad enough to cover the crate's secret-handling code.
    before = len(failures)
    for sym in ALLOWLIST_MUST_NOT_COVER:
        for cat, pattern, why in allowlist:
            if pattern in sym:
                failures.append(f"allowlist entry [{cat}] {pattern!r} would cover {sym!r} ({why})")
    print(f"  allowlist:  {len(ALLOWLIST_MUST_NOT_COVER)} sensitive symbols, "
          f"{len(failures) - before} covered by an allowlist entry")

    # 3. End to end: compile a real divide under each config's flags and require the scan to
    # report it. This is what catches a disassembler whose output format moved, or one that
    # silently emits nothing.
    before = len(failures)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "planted.rs"
        src.write_text(PLANTED_SRC)
        for label, rustflags, _backend in CONFIGS:
            obj = Path(tmp) / f"planted-{label}.o"
            proc = subprocess.run(
                ["rustc", "--edition", "2021", "--crate-type", "rlib", "-O",
                 "--target", TARGET, *rustflags.split(), "--emit", f"obj={obj}", str(src)],
                capture_output=True, text=True,
            )
            if proc.returncode != 0:
                failures.append(f"{label}: could not compile the planted divide\n{proc.stderr}")
                continue
            rows, total = disassemble(objdump, [str(obj)])
            for want, fn in [("non-doit:div", "planted_divide"), ("div-libcall", "planted_libcall128")]:
                hit = any(
                    name == want and fn in sym
                    for sym, text in rows
                    for name, _ in classify(text)
                )
                if not hit:
                    failures.append(
                        f"{label}: the planted {want} was NOT reported "
                        f"({total} instructions disassembled). The scan would pass vacuously here."
                    )
    print(f"  end-to-end: {len(CONFIGS)} config(s), {len(failures) - before} missed a planted "
          f"divide or divide libcall")

    if failures:
        print("\nFAIL: the instruction scan is not working as intended:\n")
        for f in failures:
            print(f"  {f}")
        return 1
    print("\nPASS: the instruction scan detects planted variable-latency instructions")
    return 0


def main():
    argv = sys.argv[1:]
    if argv not in ([], ["--selftest"]):
        raise SystemExit("usage: scan-instrs.py [--selftest]   (normally run via ./ct-check.sh)")

    objdump = find_llvm_objdump()
    allow = load_allowlist(ALLOWLIST)
    check_target_installed()

    if argv == ["--selftest"]:
        print(f"==> instruction-scan self-test (llvm-objdump: {objdump})")
        return selftest(objdump, allow)

    print(f"==> scanning {TARGET} for non-DOIT instructions (llvm-objdump: {objdump})")
    classify = classifier()
    findings, scanned = [], []
    used = set()
    for label, rustflags, backend in CONFIGS:
        print(f"  building {label}")
        rlibs = build(label, rustflags, backend)
        rows, total = disassemble(objdump, rlibs)
        if total < MIN_PLAUSIBLE_INSNS:
            raise SystemExit(
                f"scan-instrs: {label} disassembled to only {total} instructions, which cannot be "
                f"right.\n  The scan would pass vacuously, so this is an error. Check that "
                f"{objdump}\n  supports x86-64 and that the build produced code."
            )
        allowed = 0
        for sym, text in rows:
            for name, desc in classify(text):
                # Matched a variable-latency category. Either the allowlist says the operands are
                # public, in which case it only gets counted, or it is a finding.
                covering = [(a_cat, a_sym) for a_cat, a_sym, _ in allow
                            if a_cat == name and a_sym in sym]
                if covering:
                    used.update(covering)
                    allowed += 1
                    continue
                findings.append((label, name, desc, text, sym))
        scanned.append((label, total, allowed))

    # The third column is only ever the allowlisted hits: anything not covered by the allowlist is
    # a finding, and is printed in full below rather than folded into a count.
    print("\n    config         instructions   allowlisted")
    for label, total, allowed in scanned:
        print(f"    {label:<12} {total:>14}   {allowed:>11}")

    status = 0
    unused = [(c, a) for c, a, _ in allow if (c, a) not in used]
    if unused:
        print(f"\nFAIL: {len(unused)} allowlist entr(y/ies) matched nothing; remove them:\n")
        for cat, pattern in unused:
            print(f"  {cat} | {pattern}")
        status = 1

    unused_extra = sorted(set(X86_EXTRA) - X86_EXTRA_USED)
    if unused_extra:
        print(f"\nFAIL: {len(unused_extra)} X86_EXTRA entr(y/ies) matched nothing; remove them:\n")
        for m in unused_extra:
            print(f"  {m}")
        status = 1

    if findings:
        # Grouped by (category, symbol), since one non-DOIT shuffle in an unrolled loop can
        # otherwise fill a screen with identical lines.
        groups = {}
        for label, name, desc, text, sym in findings:
            g = groups.setdefault((name, sym), {"desc": desc, "labels": set(), "texts": []})
            g["labels"].add(label)
            if text not in g["texts"]:
                g["texts"].append(text)
        print(f"\nFAIL: {len(findings)} variable-latency instruction(s) not in the allowlist, "
              f"in {len(groups)} (category, symbol) group(s):\n")
        for (name, sym), g in sorted(groups.items()):
            print(f"  {name}  [{', '.join(l for l, *_ in CONFIGS if l in g['labels'])}]")
            print(f"      in {sym}")
            for text in g["texts"][:3]:
                print(f"      e.g. {text}")
            print(f"      {g['desc']}")
        print("\nIf the operands are public, add a line to "
              f"{ALLOWLIST.relative_to(REPO)} saying why. If a non-doit instruction is "
              "data-independent everywhere, add it to X86_EXTRA instead.")
        status = 1

    if status == 0:
        print("\nPASS: no unexpected variable-latency instructions")
    return status


if __name__ == "__main__":
    sys.exit(main())
