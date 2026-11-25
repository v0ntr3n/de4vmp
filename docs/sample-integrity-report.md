# Independent Sample Integrity Report (`samples/cleaned-demutate2-cleaned.zip`)

**Audited Commit:** `d695ae2bfac3170da4d449402fd761a2b7ba7bb6`
**Methodology:** Two independent static forensic agents (raw Python PE/ECMA-335 parser + AsmResolver 6.0.0 cross-check). **Zero host-CLR execution**; original files unmodified.

---

## 1. File Hashes, Sizes & Provenance

| Artifact | Size (bytes) | SHA-256 | Notes |
| :--- | ---: | :--- | :--- |
| `samples/cleaned-demutate2-cleaned.zip` | `10,436,715` | `98d45ab38086cd50e99a20a012f8903ad2a43a84e2557fd6ec25fc2981ec4e09` | Single DEFLATE entry (`CRC-32: 0x95EDD7FD`, timestamp `2026-11-25 14:40:26`) |
| `cleaned-demutate2-cleaned.exe` (extracted) | `17,627,136` (`0x10CF800`) | `54519231ae9e61a14cf2ca9e4b48de09cf22359b35f500c614b801ec6c4ef35c` | PE32+ (`AMD64`), `GPMLogin, Version=4.3.0.0`, CLR `v4.0.30319` |

- **Git provenance (`git log --all --stat -- samples/`):** Only one binary commit exists in repository history (`9286d40808542afbaff2290e121617c4489e2301`, `"Add zipped sample cleaned-demutate2-cleaned.zip"`). No original uncleaned binary or intermediate dump exists in git history.

---

## 2. PE Section Table, Overlay & `BSJB` Metadata Audit

| # | Section | VirtualAddress | VirtualSize | PointerToRawData | SizeOfRawData | Shannon Entropy |
| :-: | :--- | :---: | ---: | :---: | ---: | ---: |
| 0 | `.text` | `0x00002000` | `0x00A14EDC` (`10,571,484`) | `0x00000400` | `0x00A15000` (`10,571,776`) | `6.8603` |
| 1 | `.rsrc` | `0x00A18000` | `0x00018CB2` (`101,554`) | `0x00A15400` | `0x00018E00` (`101,888`) | `4.9827` |
| 2 | `.text` | `0x00A32000` | `0x0033EC88` (`3,402,888`) | `0x00A2E200` | `0x0033EE00` (`3,403,264`) | `6.5372` |
| 3 | `.text` | `0x00D72000` | `0x003626B9` (`3,548,857`) | `0x00D6D000` | `0x00362800` (`3,549,184`) | `6.6172` |

- **PE Overlay:** `0` bytes (`0x00D6D000 + 0x00362800 == 0x010CF800 == 17,627,136`).
- **CLR Header (`RVA 0x00002000`, `FO 0x00000400`):** `CorFlags = 0x00000000` (`ILONLY` unset), `EntryPointToken = 0x060000EF`, active `MetaData = RVA 0x00C428EC` (`Size = 0x0012D110`, `FO 0x00C3EAEC`), `Resources = RVA 0x006DC8E0` (`Size = 0x0020D4EB`).
- **Active `#-` Metadata Consistency:** All 31 present tables sum to `691,326 / 691,328` bytes (2B alignment padding); `TypeDef`/`Field`/`Method`/`Param` list pointers are monotonic; all 15,390 non-zero `MethodDef` RVAs map cleanly to PE sections.
- **`BSJB` Metadata Signatures (3 total):**
  1. **`BSJB #1` (`FO 0x008862B8`, `RVA 0x00887EB8`):** Embedded 5,632-byte `.NET` PE **`RestarterV2`** inside `FE90F78B.resources` (`MZ` at `FO 0x00885F68`). *(Correction to `docs/vmp38-spec.md`: this is NOT an orphaned `GPMLogin` metadata pass.)*
  2. **`BSJB #2` (`FO 0x008E81CC`, `RVA 0x008E9DCC`):** Orphaned prior-pass `GPMLogin` `#-` metadata (`0x12D110` bytes, SHA-256 `96ed6766...`, differing from active `BSJB #3` in `13,767` bytes).
  3. **`BSJB #3` (`FO 0x00C3EAEC`, `RVA 0x00C428EC`):** Active `GPMLogin` `#-` metadata (`0x12D110` bytes, SHA-256 `103ea461...`).

---

## 3. Independent Forensic Proof of Missing VM Bytecode

1. **Relocated DOS-Header `FieldRVA` (`EB275028::byte_0`, `0x04000DB1`):**
   - `FieldRVA` Row #14 points to `RVA 0x00002258` (`FO 0x00000658`), NOT `RVA 0x00000000`.
   - Raw bytes at `FO 0x00000658`: `4D 00 00 00 00 00 00 00 | 4D 5A 90 00 03 00 00 00 | 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00` (relocated 1-byte `'M'` and adjacent 8B/16B DOS-header copies produced by `dnlib`/`de4dot` rewriting).
2. **All 157 Call-Site RVAs Point Into Plaintext CIL or Active `#-` Metadata:**
   - **64 / 157** land inside **active `BSJB #3` `MethodDef` CIL bodies** (`54` in `.text[0]` + `10` in `.text[2]`), including `GClass105`'s own active VM handlers (`A28D619F::smethod_0` RVA `0x00AA0C45` lands at `IL_0215` of `GClass105::method_661`; `A28D619F::smethod_3` RVA `0x00A9DFAD` lands at `IL_0075` of `GClass105::method_636`).
   - **77 / 157** land inside **orphaned `BSJB #2` CIL bodies** in `.text[0]` *(refines `docs/vmp38-spec.md`, which grouped all 131 `.text[0]` RVAs as active CIL)*.
   - **16 / 157** land inside **active `#-` `Table 0x06 (MethodDef)`** (`Row #6858 .. Row #9716`), including `<Module>::.cctor` (`RVA 0x00C84DDE`, Row #6946).
3. **No Hidden Encrypted Blob Anywhere in the 17.6 MB PE:**
   - **0 / 3,876** 4 KB blocks outside Managed Resources have Shannon entropy `> 7.4`.
   - Static `ResourceReader` (`0xBEEFCACE`) inspection confirms `GPMLogin.g.resources` contains standard PNG/JPG/ICO/GIF/BAML UI assets, and `FE90F78B.resources` contains 8 plaintext JSON/text arrays + `RestarterV2` (5.6 KB `.NET` PE).
4. **Alternative RVA-Base & Full-File Scan Negatives:**
   - Testing 11 RVA-base deltas (`0`, `±0x2258`, `±0x2000`, `±0x1C00`, `+0xA32000`, `+0xD72000`, `+0x6DC8E4`, `+0x88798C`) produced **0 / 157** valid `GClass105` handler tokens (`0x0600249F..0x06003992`).
   - Exhaustive 1-byte-stride 2-step scan across all `17,627,136` bytes for all 157 call sites (`2.77 × 10^9` positions) yielded **0 hits** (and **0 / 157** even yield a `0x06xxxxxx` prefix at step 0).
5. **Direct IL Proof of Zero Hidden Key/Seed:**
   - Module-wide `stfld`/`ldflda` scan confirms `Class1344::vmethod_0(object)` (`0x06003A8E`) is the sole initializer of `uint_0` (`IL_087D`: exact `rva`) and `uint_1` (`IL_01C3`: exact copy of `uint_0`), with zero hidden XOR/seed before `GClass105::ACA9C11A` invokes `method_34()`.

---

## 4. Classification & Verdict

- **Failure Type:** **Missing Data / Corrupted Post-Rewrite Artifact** (NOT an analysis bug, NOT invalid active metadata, NOT an unsupported PE format).
- **Verdict:** **`Reproducibly proven by independent evidence`.** The original VMProtect bytecode section was stripped when `cleaned-demutate2-cleaned.exe` was rewritten multiple times by `dnlib`/`de4dot`. An intact, un-rewritten authorized VMP 3.6–3.8+ binary is required to verify end-to-end real-world bytecode decoding (#7).
