# ADR-001: Control-Flow Unflattening Engine Selection

- **Status:** Accepted
- **Date:** 2026-11-25
- **Issue:** [v0ntr3n/de4vmp#5](https://github.com/v0ntr3n/de4vmp/issues/5)
- **Empirical Data:** [docs/unflattening-spike-results.md](./unflattening-spike-results.md)

---

## Context

`de4vmp.V2`'s current `CffUnflattener.cs` eliminates `0 / 40 (0.0%)` CFF `switch` dispatchers across `GClass105::.ctor`, `GClass105::.cctor`, the 10 `Class1344` reader methods, and the first 30 `GClass105` switch handlers in `cleaned-demutate2-cleaned.exe` (`GPMLogin.exe`).

Before investing in a production CFF unflattener, Issue #5 required an empirical head-to-head benchmark comparing:
1. **In-process Pure C# (`AsmResolver 6.0`)** — optionally leveraging `Washi1337/Echo` and/or `Microsoft.Z3`.
2. **Rust `ATRAPSLLC/dotscope` per-method APIs** (`method.ssa` + `dotscope::deobfuscation::unflatten` and `DeobfuscationEngine::process_ssa`).

### Decision Rule (from Issue #5)
1. **Eligibility Gate:** Total wall-clock time on the benchmark set must be **`<= 30 seconds`**.
2. **Selection Rule:** **Default to pure C#** unless Rust `dotscope` achieves **`>= 2x` handler recovery** OR **`>= 5x` speedup**.

---

## Evaluation Against Decision Criteria

| Criterion | Threshold | C# `AsmResolver 6.0` | Rust `dotscope` (`unflatten`) | Rust `dotscope` (`process_ssa`) | Rust Meets Threshold? |
| --- | --- | --- | --- | --- | --- |
| Total wall-clock time | `<= 30 s` | `0.79 s` (PASS) | `0.37 s` (PASS) | `3.03 s` (PASS) | Both eligible |
| Switch / handler recovery | `>= 2x` C# | `0 / 40 (0.0%)` | `0 / 40 (0.0%)` | `0 / 40 (0.0%)` | **NO** (0% vs 0%) |
| Speedup (benchmark loop) | `>= 5x` C# | `24.85 ms` (p50 `0.137 ms`) | `188.38 ms` (7.6x slower) | `2,792.74 ms` (112x slower) | **NO** |
| Speedup (total incl. load) | `>= 5x` C# | `788.71 ms` | `370.23 ms` (2.13x faster) | `3,026.43 ms` (3.84x slower) | **NO** (2.13x < 5x) |
| Peak RSS memory | Lower is better | `196.03 MB` | `507.29 MB` (2.59x) | `509.89 MB` (2.60x) | **NO** |
| `build.yml` packaging | Single-file win-x64 | Zero CI changes | +Rust 1.95, +3m16s build, +16.89 MB native binary | +Rust 1.95, +3m16s build, +16.89 MB native binary | **NO** |

---

## Decision

**Adopt an in-process Pure C# unflattening engine built directly on `AsmResolver 6.0` (no Rust `dotscope` dependency).**

Specifically:
1. **Reject Rust `ATRAPSLLC/dotscope` integration.** Although per-method `dotscope` resolves the whole-assembly stall (`0.37 s` / `3.03 s` vs `> 4m 34s`), it eliminates **0 / 40 (0.0%)** `switch` dispatchers on `GClass105`/`Class1344`, fails both the `>= 2x` recovery and `>= 5x` speedup gates, consumes **2.6x more RAM** (`~508 MB` vs `196 MB`), and imposes a heavy dual-toolchain CI and `16.89 MB` native sidecar/FFI burden on `.github/workflows/build.yml`.
2. **Do not bundle `Washi1337/Echo` into the single-file executable by default.** `Echo` has no built-in CFF unflattener and is licensed under **LGPL-3.0-only**, whose §4(d) relinking requirement conflicts with `build.yml`'s `-p:PublishSingleFile=true` single-file distribution unless `Echo.*.dll` is shipped externally as a replaceable DLL. Writing a focused, zero-external-license CFG + path-sensitive concrete/symbolic state evaluator directly on `AsmResolver 6.0` is simpler, faster, and preserves clean single-file publishing.
3. **Keep `Microsoft.Z3` (MIT) as an optional Tier-2 solver fallback only if needed.** Static IL inspection of `GClass105::.ctor` and `GClass105::method_4` shows that the state transitions blocking both engines are deterministic 32-bit/16-bit arithmetic & bitwise chains (`mul`, `not`, `div.un`, `xor`, `sub`, `shr`, `add`, `conv.i2`, `x % x == 0` identities) across 1–2 local variables. A pure-managed C# path-sensitive abstract/symbolic bitvector evaluator (tracking known constants, `x % x == 0`, `x ^ x == 0`, `conv.i2` width masks, and bounded per-edge state propagation from entry/predecessors) should resolve these in-process with zero native dependencies. If residual MBA/opaque predicates remain unsolvable by algebraic + path-sensitive evaluation, `Microsoft.Z3` (MIT) can be added cleanly via `build.yml`'s existing `-p:IncludeNativeLibrariesForSelfExtract=true`.

---

## Consequences

### Positive
- **Single toolchain & single-file CI preserved:** `.github/workflows/build.yml` remains pure .NET with no Rust 1.95 install, no 3m+ fat-LTO link step, and no 16.89 MB native FFI/sidecar binary.
- **Single in-memory assembly model:** `AsmResolver 6.0` owns both analysis and IL rewriting in-process (~196 MB RSS vs ~700 MB combined if running `AsmResolver` + `dotscope`).
- **Directly targets the real blocker:** Engineering effort goes straight into path-sensitive multi-local state propagation + algebraic identity folding (`x % x == 0`, `~0`, `div.un`, `conv.i2`) on `GClass105`/`Class1344` rather than maintaining an FFI bridge to an engine that still recovered 0/40 switches.

### Trade-offs & Mitigations
- **Custom CFF pass maintenance:** We own the CFG + path-sensitive state-tracking unflattener in `de4vmp.V2.Analysis`. Mitigated by building unit tests against the exact `GClass105` / `Class1344` IL idioms (`rem` self-identity, `not`/`div.un`, `conv.i2`, multi-local state updates) and measuring switch elimination `%` on `cleaned-demutate2-cleaned.exe` as a regression gate.
