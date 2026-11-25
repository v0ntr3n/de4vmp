# Remaining Blockers & Prioritized Implementation Backlog

**Parent Tracker:** [Issue #1](https://github.com/v0ntr3n/de4vmp/issues/1) (`OPEN`)
**Open Child Issues:** [Issue #6](https://github.com/v0ntr3n/de4vmp/issues/6) (`OPEN`), [Issue #7](https://github.com/v0ntr3n/de4vmp/issues/7) (`OPEN`)

---

## 1. Hard Blockers to Real-World VMProtect 3.6–3.8+ Compatibility

1. **Corrupted Repository Sample (P0 — Data Blocker for #7 & #1):**
   - `samples/cleaned-demutate2-cleaned.zip` is forensically proven missing its original VMP bytecode section (see [sample-integrity-report.md](sample-integrity-report.md)).
   - **Action Required:** Obtain an authorized, intact (un-rewritten, or cleanly dumped without `dnlib`/`de4dot` section stripping) VMP 3.6–3.8+ `.NET` test binary stored in private storage (`process-private-input.yml`) or build an authorized synthetic VMP-3.8-equivalent fixture (headerless PE-RVA stream + 10 `Class1344`-style rolling-XOR/rotate ciphers + multi-local CFF).
2. **Multi-Local CFF Unflattening (P0 — Algorithmic Blocker for #6):**
   - Both `de4vmp.V2`'s peephole `CffUnflattener.cs` and `ATRAPSLLC/dotscope`'s `unflatten`/`process_ssa` eliminated **0 / 40 (0.0%)** switches on `GClass105`/`Class1344` (`docs/unflattening-spike-results.md`).
   - Real `GClass105` handlers update coupled state locals via multi-instruction arithmetic (`ldloc.3 * ldloc.0`, `not`, `div.un`, `conv.i2`, `x % x == 0`, `rem.un N`).
   - **Action Required:** Build a bounded CFG + path-sensitive multi-local bitvector/abstract state evaluator on `AsmResolver 6.0` (with `(block, stateVector)` memoization, EH-boundary preservation, `ilverify` validation, and optional MIT `Microsoft.Z3` Tier-2 fallback gated by strict per-edge timeouts).
3. **Stateful `instance void()` Handler Summarization & Cross-Type Emulation (P1 — Blocker for #6):**
   - Real `GClass105` has 5,352 stateful `instance void()` handlers mutating nested `Class1344` (stream), `Class1345` (stack), and `Class1343` (locals/args) objects, plus 182 recursive VM-to-VM call handlers.
   - `BoundedCilEmulator` currently fails closed on cross-type calls (`GClass105` → `Class1344`/`Class1345`) and `HandlerSemanticClassifier` assumes single-type `int[]` VM fields.
   - **Action Required:** Allowlist nested/same-assembly VM helper types in `BoundedCilEmulator` (with step/heap caps) and classify unflattened handlers by their **normalized VM-state delta** (stack pop/push effect + `Class1344` reads + CLR member ops).
4. **Headerless PE-RVA Stream Decoding & Per-Entry `Class1344` Cipher Recovery (P1 — Blocker for #7):**
   - `V2Devirtualizer.cs` still assumes a 12-byte `[localCount][insnCount][ehCount]` header and linear `key += step` XOR.
   - **Action Required:** Implement PE-RVA stream reading (`PeFile.TryCreateReaderAtRva`), automated extraction of per-entry `Class1344` rolling-key (`uint_1 ^= decryptedToken`) bit/byte ciphers (building on the pure-IL evaluator already proven in `scripts/inspect-vmp38.ps1`), and dynamic VM CFG/EH discovery without a synthetic method header.

---

## 2. Prioritized Implementation Backlog

| Priority | Item | Issue | Measurable Exit Gate |
| :---: | :--- | :---: | :--- |
| **P0** | Implement bounded CFG + multi-local bitvector CFF unflattener in C# (`AsmResolver 6.0`) | #6 | Eliminates >=90% of switches across `GClass105` + `Class1344` in `<= 30s` total; 0 `dotnet-ilverify` errors on unflattened methods. |
| **P0** | Provide an authorized, uncorrupted VMP 3.6–3.8+ test fixture (or private CI fixture) | #7 / #1 | `scripts/inspect-vmp38.ps1` decodes >=10 consecutive valid `dictionary_0` handler tokens on >=3 distinct virtualized methods. |
| **P1** | Implement stateful `instance void()` VM-state-delta handler classifier (with nested VM helper emulation) | #6 | Classifies >=90% of active `GClass105` handlers with **0 silent misclassifications** (verified via differential emulation). |
| **P1** | Implement PE-RVA stream reader + per-entry `Class1344` cipher recovery + headerless VM CFG/EH lifting | #7 | Recompiles >=80% of valid virtualized methods in an intact VMP 3.6–3.8+ binary with **0 `dotnet-ilverify` errors**. |
| **P2** | CI & Governance Hardening: enable `v2-benchmarks.yml` as required branch-protection check, add `.config/dotnet-tools.json` for local `ilverify`, and add `--engine v1/v2/invalid` cases to `scripts/smoke-test.ps1` | #8 / Hygiene | `dotnet tool restore` + `dotnet test` enforces `ilverify` locally and in CI with zero silent skips. |
| **P2** | Fix residual non-blocking emulator/classifier edge cases (`InitializeArray` multi-byte element widths, qualified static field keys, `BrTrue`/`BrFalse` polarity CFG check, `V2Devirtualizer` `CancellationToken` propagation) | Hygiene | Regression unit tests for each edge case pass with 0 warnings. |
