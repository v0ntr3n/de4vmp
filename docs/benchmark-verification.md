# Independent Benchmark Verification Report (`de4vmp.V2`)

**Audited Baseline:** `d695ae2` + Phase 2 bugfix/hardening remediation pass
**Verification Scope:** Authorized, self-authored synthetic `.NET 8.0` fixtures + `dotnet-ilverify` (`8.0.0`) + CLI `--engine v2` end-to-end runs.

> [!IMPORTANT]
> Passing all **30 / 30** tests below verifies internal V2 engineering correctness (name-invariance, fail-closed safety, CLI exit codes, and synthetic-contract semantic equivalence). It does **not** establish compatibility with real-world VMProtect 3.6–3.8+ binaries.

---

## 1. Test Suite Results Summary

- **Command:** `dotnet test de4vmp.sln -c Release`
- **Local Result:** **30 / 30 passed**, 0 failed, 0 skipped, 0 warnings in `de4vmp.V2` / `de4vmp.V2.Tests` (duration `~1.0 s`).
- **CI `dotnet-ilverify` Enforcement:** `.github/workflows/v2-benchmarks.yml` installs pinned `dotnet-ilverify --version 8.0.0`, sets `DE4VMP_REQUIRE_ILVERIFY=1`, passes `--statistics`, and asserts `Methods verified: N >= expectedMethodCount` (blocking silent 0-method filter mismatches).

| Test Suite | Test Count | Focus | Result |
| :--- | :---: | :--- | :---: |
| [BenchmarkVerificationTests.cs](file:///c:/Users/Tranv/Documents/AI_M/de4vmp/tests/de4vmp.V2.Tests/BenchmarkVerificationTests.cs) | 5 | Tiers 1–4 end-to-end devirtualization + `ilverify` + differential equivalence + fail-closed tampered handler | **5 / 5 PASS** |
| [AdversarialAuditTests.cs](file:///c:/Users/Tranv/Documents/AI_M/de4vmp/tests/de4vmp.V2.Tests/AdversarialAuditTests.cs) | 14 | Renamed helpers (`m_01..m_21`), reflection `MetadataToken` discovery, complex `rem.un` CFF bail-out, `ldloca.s`, cross-type fail-closed, 64-bit `Int64` math, instance `Ldarg`/object `Beq`, computed offsets, renamed resource/keys, dynamic CFF fallthrough, truncated stream + `ilverify` | **14 / 14 PASS** |
| [IndependentAuditTests.cs](file:///c:/Users/Tranv/Documents/AI_M/de4vmp/tests/de4vmp.V2.Tests/IndependentAuditTests.cs) | 11 | Full randomized identifiers (Tiers 2–4), malformed inputs (random bytes, invalid token `0x06FFFFFF`, OOB branch/EH, non-VM DLL), live CLR-executable mini-VM pre/post equivalence, live CLR-executable CFF loop pre/post equivalence, CLI `--engine v2` end-to-end | **11 / 11 PASS** |
| **Total** | **30** | | **30 / 30 PASS** |

---

## 2. Independent Verification Dimensions Covered (`IndependentAuditTests.cs`)

1. **Full Identifier Randomization (Tiers 2, 3, and 4 — 3 cases):**
   - Randomized every namespace, type name, nested delegate name, field name (`KeySeed`, `KeyStep`, `BytecodeBlob`, VM state fields), method name (all 21 helpers, handlers, `*_Core`, entry methods, targets), and manifest resource name with deterministic hex tokens.
   - Verified 100% handler discovery, 100% classification (0 `Unknown`), CFF switch elimination on Tiers 3–4, 100% devirtualization, and bit-identical differential behavioral equivalence against `ReferenceSuite`.
2. **Malformed Inputs & Fail-Closed Negative Tests (5 cases):**
   - PRNG-corrupted resource bytes at valid call-site offsets -> `MethodsDevirtualized == 0`, no exception.
   - Invalid metadata token `0x06FFFFFF` -> `MethodsDevirtualized == 0`, diagnostic reports `0x06FFFFFF`, no exception.
   - Out-of-range branch targets (`9999`, `-1`) -> `MethodsDevirtualized == 0`, diagnostic reports `"branch target ... out of range"`.
   - Out-of-range EH clause `[0..50)`/`[50..99)` -> `MethodsDevirtualized == 0`, diagnostic reports `"EH region out of range"`.
   - Non-VM assembly (`de4vmp.V2.dll`) -> all counters `0`, all method instruction sequences byte-for-byte unmodified.
3. **True Pre- vs. Post-Transformation Execution Equivalence (2 cases):**
   - **Live CLR-Executable Mini-VM (`AuditMiniVm.LiveInterpreter`):** Independently constructed executable 8-bit stack VM with polymorphic `Add` (`a - (-b)`) and `Xor` (`(a | b) - (a & b)`). Executed **both** the original virtualized DLL on the live .NET 8 CLR and the `V2Devirtualizer`-produced native CIL DLL across boundary + 100 randomized inputs -> bit-for-bit identical results, 0 remaining calls to `LiveInterpreter`.
   - **Live CLR-Executable CFF Loop (`AuditCff.LoopTarget.Run`):** Executed both flattened and `CffUnflattener`-transformed DLLs across boundary + 100 randomized inputs -> 0 remaining `switch` instructions, bit-for-bit identical results.
4. **CLI `--engine v2` End-to-End Verification (1 case):**
   - `de4vmp --engine v2 --ci --no-banner -i <Tier3.dll> -o <out.dll>` -> exit code `0`, output DLL passes full differential equivalence.
   - `de4vmp --engine v2 --ci --no-banner -i <de4vmp.V2.dll> -o <out.dll>` -> exit code `3`, no output file created.

---

## 3. Known Benchmark Boundaries (Not Yet Covered)

- **Real-world scale:** Synthetic tests use 12–33 handlers; real VMP 3.8 (`GClass105`) has 5,352 handlers and 182 recursive internal VM calls.
- **Multi-local CFF:** `CffUnflattener` still eliminates `0/40` real `GClass105`/`Class1344` switches (tracked in Issue #6).
- **Real VMP wire format:** Synthetic fixtures use a 12-byte `[localCount][insnCount][ehCount]` header + linear `key += step` XOR; real VMP 3.8 uses headerless PE-RVA streams + 10 per-entry `Class1344` rolling-XOR/rotate/byte-swap ciphers (tracked in Issue #7).
