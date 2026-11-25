# Independent Audit Report (`v0ntr3n/de4vmp`)

**Baseline Audited:** Commit `d695ae2bfac3170da4d449402fd761a2b7ba7bb6` (`master`)
**Audit Structure:** 5 parallel Phase 1–5 specialist agents + 1 Independent Audit Critic
**Related Reports:** [sample-integrity-report.md](sample-integrity-report.md) | [benchmark-verification.md](benchmark-verification.md) | [remaining-blockers.md](remaining-blockers.md)

---

## 1. Executive Verdict

| Area | Status | Evidence Summary |
| :--- | :--- | :--- |
| **Sample Integrity (`cleaned-demutate2-cleaned.zip`)** | **Confirmed Corrupted** | Independently proven by two forensic agents: 64/157 RVAs land in active `BSJB #3` CIL bodies, 77/157 in orphaned `BSJB #2` CIL bodies, 16/157 in active `#-` `MethodDef` rows; 2.77-billion-position 2-step scan yields **0 hits**; `Class1344::vmethod_0` has zero hidden seed/XOR. See [sample-integrity-report.md](sample-integrity-report.md). |
| **V2 Synthetic Engineering & Fail-Closed Safety** | **Verified (30/30 Tests)** | Baseline 19/19 + 11 new independent tests (full identifier randomization, live CLR-executable mini-VM, malformed inputs, CLI `--engine v2`) pass with hardened `dotnet-ilverify` (`--statistics`, `verifiedCount >= expectedCount`). See [benchmark-verification.md](benchmark-verification.md). |
| **Real-World VMProtect 3.6–3.8+ Compatibility** | **Unsupported (0%)** | Green CI and 30/30 synthetic tests prove **zero** real-world VMProtect 3.6–3.8+ compatibility. Both C# `CffUnflattener` and Rust `ATRAPSLLC/dotscope` eliminate **0/40 (0.0%)** real `GClass105`/`Class1344` switches. Issue #1 remains **OPEN**. |
| **Architecture Decision (ADR-001)** | **Confirmed (Pure C# `AsmResolver 6.0`)** | Rejecting Rust `dotscope` (0/40 switches, 2.6× RSS, +16.89 MB binary) and LGPL-3.0 `Echo` stands, with strict guardrails for multi-local CFF in Issue #6. |

---

## 2. Phase 2 Implementation Audit Findings & Fixes Applied

Every change in commit `d695ae2` was audited line by line. The following confirmed general-purpose bugs were fixed in this remediation pass:

| Component | Bug Identified in `d695ae2` | Fix Applied |
| :--- | :--- | :--- |
| `de4vmp.Core/Services/FunctionService.cs:20` | Unported Draft PR #2 bounds bug: `instructions[i - 1]` throws `ArgumentOutOfRangeException` when `i == 0`. | Added `if (i == 0) continue;` before `instructions[i - 1]`. |
| `tests/de4vmp.V2.Tests/BenchmarkVerificationTests.cs:198-235` & `.github/workflows/v2-benchmarks.yml:38` | `ilverify` lacked `--statistics` verified-method-count check (0-method filter mismatch would exit 0), used synchronous stdout/stderr reads (deadlock risk), unpinned `11.0.0` (fails on pure .NET 8 hosts), and was not called in `AdversarialAuditTests.cs`. | Pinned `dotnet-ilverify --version 8.0.0`, switched to async stdout/stderr + timeout kill, enforced `Methods verified: N >= expectedCount`, and wired `VerifyWithIlVerify` into `AdversarialAuditTests.cs`. |
| `src/de4vmp.V2/Analysis/CffUnflattener.cs` | Fallthrough check skipped `Nop`s that might be branch targets (`L255-268`); `SimplifyOpaquePredicates` lacked `HasBranchTargetInRange` guard (`L68-109`); `int.MinValue % -1` threw `OverflowException` (`L144`); missing `CalculateOffsets()` after `insns.Insert` (`L241`). | Added branch-target guards on skipped `Nop`s and opaque predicate interiors, guarded `int.MinValue % -1`, and called `insns.CalculateOffsets()` after insertion. |
| `src/de4vmp.V2/Emulation/BoundedCilEmulator.cs` | `Div`/`Div_Un`/`Rem`/`Rem_Un` silently returned `0` / `MinValue` on div-by-zero / overflow; invalid branch target or falling off method end returned `CompletedNormally = true`; `Brfalse`/`Brtrue` treated `0u`/`0UL`/`(byte)0` as truthy; open-instance `CreateDelegate` allowed mismatched `System.Object` receiver. | Changed div-by-zero/overflow and invalid branch/fall-off-end to fail closed (`CompletedNormally = false`); unified zero checks via `IsZeroOrNull`; tightened open-instance `IsDelegateSignatureCompatible`. |
| `src/de4vmp.V2/Translation/V2Devirtualizer.cs:353-448` | `TryEvaluatePrecedingConstantInt32` ignored control-flow merges into `[startIdx+1..callIndex]` (diamond CFG bug) and silently folded `int.MinValue / -1` and `% -1`. | Rejected constant evaluation if any branch targets `(startIdx, callIndex]`; returned `false` on signed div/rem overflow. |
| `src/de4vmp.V2/Semantics/HandlerSemanticClassifier.cs:339-364` | Inline `Pop`/`Push` arithmetic fallback did not check `Pop` call count or forbid `Ldc_I4` constants (`Push(Pop() + 1)` could misclassify as `Add`). | Enforced `!insns.Any(i => i.IsLdcI4())` and exact `Pop` call count (`1` for `Neg`, `2` for binary ops). |

### CLI & CI Exit-Code Validation
- `--engine v2` on Tier 3/4 synthetic DLLs: devirtualizes all methods, passes differential equivalence, exits `0`.
- `--engine auto` on Tier 4 DLL: falls back from V1 to V2 cleanly, exits `0`.
- `--engine auto` and `--engine v2` on non-VM DLL (`de4vmp.V2.dll`): exits `3` (`DevirtualizationError`), writes no output file.
- Invalid `--engine` / missing input / non-PE: exits `2` (`InvalidArguments`).
- `.github/workflows/process-sample.yml`: clearly separates `status: devirtualized` (exit `0`) from `status: unsupported_target` (exit `3`, no output artifact).

---

## 3. Phase 4 GitHub Issue Reconciliation (`#1–#8` & Draft PR `#2`)

| Issue / PR | State | Reconciliation Verdict |
| :--- | :--- | :--- |
| **[#1](https://github.com/v0ntr3n/de4vmp/issues/1)** | **OPEN** | Parent tracker; remains open until real-world VMP 3.6–3.8+ compatibility is reproducibly verified. |
| **[Draft PR #2](https://github.com/v0ntr3n/de4vmp/pull/2)** | **CLOSED (Superseded)** | Superseded by `d695ae2` (`de4vmp.V2` + unified `net8.0` solution). Its one unported V1 bugfix (`FunctionService.cs:20` `i == 0` guard) has now been ported to `master`. |
| **[#3](https://github.com/v0ntr3n/de4vmp/issues/3)** | **CLOSED** | Substantively complete; all targeted bugs fixed and `ilverify` gate hardened in this pass. |
| **[#4](https://github.com/v0ntr3n/de4vmp/issues/4)** | **CLOSED (with falsification addendum)** | Criteria #1–#2 met; Criterion #3 (decoding >=10 VM ops for >=3 methods into valid `dictionary_0` tokens) was **falsified by sample corruption** (`CORRUPTED_POST_REWRITE_NO_VMP_BYTECODE_SECTION`) and formally deferred to #7 on an intact sample. |
| **[#5](https://github.com/v0ntr3n/de4vmp/issues/5)** | **CLOSED** | Complete (`docs/unflattening-spike-results.md` + `docs/adr-001-unflattening-engine.md`). |
| **[#6](https://github.com/v0ntr3n/de4vmp/issues/6)** | **OPEN** | Synthetic criteria met; real-binary multi-local CFF unflattening and >=90% stateful `GClass105` handler classification remain open. |
| **[#7](https://github.com/v0ntr3n/de4vmp/issues/7)** | **OPEN** | Synthetic criteria met; real-binary PE-RVA stream decoding and >=80% recompilation require an uncorrupted VMP 3.6–3.8+ sample. |
| **[#8](https://github.com/v0ntr3n/de4vmp/issues/8)** | **CLOSED** | Complete (unified `.NET 8.0` + `AsmResolver 6.0.0`, `--engine auto|v1|v2`, all 4 CI workflows green, `ilverify` hardened). |

---

## 4. Phase 5 Architecture Review

- **Keep Pure C# `AsmResolver 6.0` (MIT):** Single toolchain, `<5 s` build, single-file `win-x64` publishing intact, `196 MB` RSS vs `507 MB` for Rust `dotscope`.
- **Rejected Alternatives:** `ATRAPSLLC/dotscope` (0/40 switches on `GClass105`, +16.89 MB native binary, dual-toolchain CI), `Washi1337/Echo` (LGPL-3.0 §4(d) single-file friction, no built-in CFF unflattener), `ICSharpCode.Decompiler` (read-only SRM model, wrong layer).
- **Optional Future Fallback:** MIT `Microsoft.Z3` only as a bounded Tier-2 SMT fallback if pure C# bitvector expression simplification leaves residual MBA/opaque predicates in Issue #6.

---

## 5. Independent Critic Challenge

An independent critic challenged all five audit phases:

1. **Forensic Conclusion — Airtight:** External I/O or runtime unpacker hypotheses are refuted (`Class1344` uses exclusively `*(uint*)smethod_0(addr)`, and `<Module>::.cctor` is itself one of the 157 corrupted call sites at RVA `0x00C84DDE` inside `#-` metadata). While a consecutive 2-step scan would miss handlers that consume an immediate operand at step 0, **0/157** call sites even produce a `0x06xxxxxx` `MethodDef` prefix at step 0.
2. **`ilverify` Gate — Hardened in CI, Local Caveat Remains:** Enforcing `verifiedCount >= expectedCount` + `--version 8.0.0` + async I/O closes the CI bypasses. Residual governance note: `v2-benchmarks.yml` should be configured as a **required branch-protection check** on `master`, and local runs without `ilverify` installed still skip unless `DE4VMP_REQUIRE_ILVERIFY=1` or a `.config/dotnet-tools.json` manifest is enforced.
3. **30/30 Synthetic Tests — Zero Real-World VMP Compatibility Proven:** Even the independently constructed live CLR-executable mini-VM still exercises the synthetic 12-byte header contract and 12–33 handlers, whereas real VMP 3.8 has 5,352 reflection-registered handlers, 10 distinct `Class1344` rolling ciphers, and multi-local CFF.
4. **Issue Reconciliation — Confirmed:** Keeping #4 closed with a falsification addendum avoids an unclosable zombie ticket while preserving full traceability under #1 and #7; closing Draft PR #2 after porting `FunctionService.cs:20` eliminates the stale `net7.0` test project.
5. **ADR-001 Architectural Guardrails:** Pure C# `AsmResolver 6.0` has no built-in SSA IR. Implementing Issue #6 cleanly requires a bounded CFG + multi-local bitvector/abstract interpreter (with memoized `(block, stateVector)` budgets and `ilverify` verification across all 5,352 handlers), not ad-hoc additions to the existing peephole scanner.
