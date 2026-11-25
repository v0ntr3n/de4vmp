# Unflattening Engine Empirical Spike Results (Issue #5)

- **Issue:** [v0ntr3n/de4vmp#5](https://github.com/v0ntr3n/de4vmp/issues/5)
- **Target Sample:** `samples/cleaned-demutate2-cleaned.zip` -> `cleaned-demutate2-cleaned.exe` (`GPMLogin.exe`, static analysis only — **zero host-CLR execution**)
- **Platform:** Windows x64, .NET 8.0 (`Release`), Rust `dotscope v0.10.0` (`--release`, `lto = "fat"`, `opt-level = 3`)

---

## 1. Benchmark Target Set (Exact 42-Method Token Parity)

Both harnesses loaded `cleaned-demutate2-cleaned.exe` statically and evaluated the **exact same 42 metadata tokens**:

| Category | Count | Methods / Tokens | Methods with `switch` |
| --- | ---: | --- | ---: |
| `GClass105` constructors | 2 | `GClass105::.ctor` (`0x06002DB2`), `GClass105::.cctor` (`0x06003993`) | 2 |
| `Class1344` readers | 10 | `method_3` (`0x06003A91`), `CE2E0511` (`0x06003AAF`), `D483C6B8` (`0x06003A8B`), `method_29` (`0x06003AB9`), `A8A5451D` (`0x06003AC5`), `method_26` (`0x06003AB4`), `method_34` (`0x06003AC2`), `method_28` (`0x06003AB8`), `method_5` (`0x06003A93`), `BC017D36` (`0x06003AC6`) | 8 (`method_29` and `method_26` have 0 switches) |
| `GClass105` switch handlers | 30 | First 30 non-ctor/cctor `GClass105` methods with `switch` sorted by metadata token ascending (`0x0600249F` `method_0` through `0x060024C4` `D5274A9E`) | 30 |
| **Total** | **42** | **42 methods** | **40 switches total** |

---

## 2. Measured Performance & Recovery Results

| Metric | Prototype 1: C# `AsmResolver 6.0` + `CffUnflattener` | Prototype 2A: Rust `dotscope` (`method.ssa` + `unflatten`) | Prototype 2B: Rust `dotscope` (`method.ssa` + `process_ssa`) |
| --- | ---: | ---: | ---: |
| **30s Eligibility Gate** | **PASS** (0.79 s) | **PASS** (0.37 s) | **PASS** (3.03 s) |
| **Assembly Load Time** | `76.99 ms` | `174.52 ms` | `223.22 ms` |
| **SSA Build Time (42 methods)** | N/A (IL-level) | `93.13 ms` (0 failures) | `94.31 ms` (0 failures) |
| **Unflatten / Pass Time (42 methods)** | `24.85 ms` | `93.24 ms` | `2,696.64 ms` |
| **Benchmark Loop Wall-Clock (42 methods)** | **`24.85 ms`** | `188.38 ms` (7.6x slower) | `2,792.74 ms` (112x slower) |
| **Total Wall-Clock (incl. load + scan)** | `788.71 ms` | `370.23 ms` (2.13x faster) | `3,026.43 ms` (3.84x slower) |
| **Per-Method Latency p50** | **`0.137 ms`** | `1.92 ms` | `24.09 ms` |
| **Per-Method Latency p95** | **`2.432 ms`** | `23.05 ms` | `401.40 ms` |
| **Per-Method Latency max** | **`10.198 ms`** (JIT warmup on `.ctor`) | `43.70 ms` (`method_5`) | `676.87 ms` (`method_5`) |
| **Peak RSS Memory** | **`196.03 MB`** | `507.29 MB` (2.59x higher) | `509.89 MB` (2.60x higher) |
| **CFF Switches Eliminated** | **0 / 40 (0.0%)** | **0 / 40 (0.0%)** | **0 / 40 (0.0%)** |
| **Methods Fully Unflattened** | **0 / 40 (0.0%)** | **0 / 40 (0.0%)** | **0 / 40 (0.0%)** |
| **Partial Edge Rewrites (`CHANGED`)** | 0 / 40 | 6 / 40 (`method_4`, `method_5`, `method_9`, `method_14`, `method_19`, `CC0506BB`) | N/A (all 42 returned `OK`, 0 switches removed) |

### Key Observations

1. **Per-method `dotscope` eliminates the whole-assembly stall:** Whereas `dotscope`'s whole-assembly `deobfuscate` example stalled past 4m 34s on `cleaned-demutate2-cleaned.exe` (5,365 methods in `GClass105` alone), calling `method.ssa(&assembly)` + `unflatten(&ssa, &UnflattenConfig::default())` per method finishes 42 methods in **0.37 s** (`3.03 s` for full `process_ssa`). Both modes comfortably pass the `<= 30 s` eligibility gate.
2. **Both engines eliminated `0 / 40 (0.0%)` switch dispatchers.** Even with `dotscope`'s full SSA optimization + CFF pass pipeline (`process_ssa`), **not a single `switch` dispatcher was eliminated**.
3. **Why both engines failed (root cause from IL inspection):**
   Static disassembly of `GClass105::.ctor` and `GClass105::method_4` reveals mutated multi-step arithmetic & bitwise state transitions feeding `rem.un 7; switch`:
   - `GClass105::.ctor` (`IL_0020`–`IL_0037`):
     ```cil
     ldc.i4 1152491556
     ldloc.3
     ldloc.0
     mul
     ldc.i4 -21274743
     mul
     not
     div.un
     not
     xor
     conv.i2
     stloc.0
     ldloc.0
     ldc.i4.7
     rem.un
     switch (7 targets)
     ```
   - `GClass105::method_4` (`IL_0040`–`IL_005C`):
     ```cil
     ldloc.s V_7
     ldloc.s V_7
     rem          // x % x == 0 (algebraic identity)
     not          // ~0 == 0xFFFFFFFF
     div.un       // unsigned division by 0xFFFFFFFF
     ldc.i4 -1694190453
     sub
     ldc.i4.s 29
     shr
     ldc.i4 -1909363281
     add
     stloc.s V_7
     ldloc.s V_7
     ldc.i4.7
     rem.un
     switch (7 targets)
     ```
   - `de4vmp.V2`'s `CffUnflattener.cs` only folds single `ldc.i4` or 2-operand `ldc.i4 A; ldc.i4 B; op` expressions, so it bails out immediately.
   - `dotscope`'s `unflatten` / `process_ssa` partially rewrote edges in 6 methods (`method_4`, `method_5`, `method_9`, `method_14`, `method_19`, `CC0506BB`), but left residual edges unresolved (due to multi-local dependencies such as `ldloc.3 * ldloc.0`, `conv.i2` narrowing, and `x % x -> ~0 -> div.un` chains), causing `dotscope`'s safe partial-recovery design to keep every `switch` dispatcher intact.

---

## 3. Reproducible Benchmark Commands

> All commands operate strictly statically on `cleaned-demutate2-cleaned.exe` extracted to a temporary scratch directory (deleted after benchmarking).

### Prototype 1 (C# `AsmResolver 6.0` + `de4vmp.V2.Analysis.CffUnflattener`)
```powershell
dotnet build -c Release CsSpike.csproj
.\bin\Release\net8.0\CsSpike.exe <temp>\cleaned-demutate2-cleaned.exe
```

### Prototype 2 (Rust `ATRAPSLLC/dotscope` per-method spike)
```powershell
cargo build --release --example vmp_spike
.\target\release\examples\vmp_spike.exe <temp>\cleaned-demutate2-cleaned.exe --mode unflatten
.\target\release\examples\vmp_spike.exe <temp>\cleaned-demutate2-cleaned.exe --mode process_ssa
```

---

## 4. `build.yml` Single-File Packaging & Ecosystem Impact

`.github/workflows/build.yml` currently publishes a single self-contained Windows x64 executable using only the .NET SDK:

```powershell
dotnet publish de4vmp/de4vmp.csproj -c Release -r win-x64 --self-contained true --no-restore `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish/win-x64
```

| Dimension | Pure C# (`AsmResolver 6.0` custom CFG/SSA/symbolic pass) | C# + `Washi1337/Echo` (+ optional `Microsoft.Z3`) | Rust `ATRAPSLLC/dotscope` (FFI `cdylib` or sidecar) |
| --- | --- | --- | --- |
| **CI Toolchains (`build.yml`)** | .NET SDK only (unchanged) | .NET SDK only (unchanged) | Adds Rust `>= 1.95` toolchain + Cargo cache to `windows-latest` |
| **Release Build Overhead** | Negligible (< 5 s) | Negligible (< 5 s) | **+3m 16s** incremental release link (`lto = "fat"`) |
| **Single-File Binary Impact** | **+0 MB** native payload, pure managed | `Echo` is pure managed; `Microsoft.Z3` adds ~15–20 MB native `libz3.dll` (supported via existing `IncludeNativeLibrariesForSelfExtract=true`) | **+16.89 MB** native binary (`vmp_spike.exe` = 17,705,472 bytes) + FFI/IPC marshaling layer |
| **License Compliance** | Permissive (MIT / repo license) | **LGPL-3.0-only** for `Echo`: §4(d) conflicts with opaque single-file bundling unless `Echo.*.dll` is excluded from single-file (`ExcludeFromSingleFile`) so users can relink/replace it; `Microsoft.Z3` is MIT | Apache-2.0 (permissive) |
| **Built-in CFF Pass** | Must implement in C# (tailored to VMP/ConfuserEx patterns) | **No built-in CFF pass** (provides CFG/DFG/symbolic primitives only) | Built-in CFF pass, but **0/40 (0.0%)** switches eliminated on `GClass105`/`Class1344` |
| **Peak RSS on `GPMLogin.exe`** | **~196 MB** | ~200–250 MB (estimated, single AsmResolver model) | **~507–510 MB** (dual PE/metadata model if paired with AsmResolver -> ~700 MB combined) |
