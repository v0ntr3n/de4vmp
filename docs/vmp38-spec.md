# VMProtect 3.8 .NET Static VM Specification (`cleaned-demutate2-cleaned.exe` / `GPMLogin.exe`)

> **Safety & Methodology:** All findings in this specification were produced **100% statically** using AsmResolver 6.0.0 (`scripts/inspect-vmp38.ps1`) with **zero host-CLR execution** of `cleaned-demutate2-cleaned.exe`. All obfuscated control-flow-flattened methods (`Class1344` readers, `Class1344::vmethod_0`, `GClass105::.cctor`, `EB275028`) were analyzed via a pure-IL static symbolic/concrete evaluator operating solely on AsmResolver `CilInstruction` ASTs.

---

## 1. Executive Summary

| Property | Value |
| --- | --- |
| Sample archive | `samples/cleaned-demutate2-cleaned.zip` |
| Extracted PE binary | `cleaned-demutate2-cleaned.exe` (`17,627,136` bytes) |
| Module / Assembly | `GPMLogin.exe` / `GPMLogin` (`.NET v4.0.30319`, `ImageBase = 0x140000000`) |
| VM Runtime Type | `GClass105` (`0x02001230`) — **5,365** methods (`5,352` handlers + `10` entries + `1` `.ctor` + `1` `.cctor` + `1` helper) |
| Handler Dispatch Table | `GClass105::dictionary_0` (`Dictionary<uint, GClass105+D3031586>`), populated via `BindingFlags = 0x26` (`DeclaredOnly \| Instance \| NonPublic`) |
| Bytecode Stream Reader | `GClass105+Class1344` — **10 / 10** 32-bit `ldind.u4` readers recovered and verified bit-for-bit against pure-IL execution |
| RVA Mapper | `EB275028::smethod_0(uint rva)` — pure PE RVA-to-VA/file-offset mapping (zero XOR/delta/decryption) |
| External VM Entry Call Sites | **157 / 157** constant `ldc.i4` calls (**157 unique RVAs**, `0` duplicated, `0` external non-constant calls) |
| Internal Recursive VM Calls | **182** non-constant calls inside `GClass105` handlers (each preceded by `unbox.any System.Int32`) |
| Machine-Readable Inventory | [`docs/vmp38-inventory.json`](vmp38-inventory.json) (reproduced by `pwsh -File scripts/inspect-vmp38.ps1`) |

> [!WARNING]
> **Critical Sample Integrity Finding (`CORRUPTED_POST_REWRITE_NO_VMP_BYTECODE_SECTION`):**
> Although the VMProtect 3.8 interpreter (`GClass105`, `Class1344`, `EB275028`) and all 157 call sites are fully intact and 10/10 reader ciphers were verified bit-for-bit against pure-IL execution, **0 / 157** call sites decode to valid `GClass105` `dictionary_0` tokens in `cleaned-demutate2-cleaned.exe` (and **0 / 157** even decode to a `0x06xxxxxx` `MethodDef` prefix). Forensic PE analysis (Section 7) proves that `cleaned-demutate2-cleaned.exe` was rewritten three times by `dnlib`/`de4dot` (leaving **3 `.text` sections**, **3 `BSJB` metadata headers**, and **0 `.vmp0`/`.vmp1` sections**), which stripped the original VM bytecode section, relocated `EB275028::byte_0` from RVA `0x00000000` to `0x00002258`, and left all 157 call-site RVAs pointing into unencrypted CIL bodies or active `#-` metadata tables.

---

## 2. PE Layout & Forensic Reconstruction

`cleaned-demutate2-cleaned.exe` contains **4 PE sections** (three sections named `.text` and one `.rsrc`) and **no `.vmp0`/`.vmp1` bytecode section**:

| Section | RVA Range | Virtual Size | File Offset | Raw Size | Characteristics | Contents |
| --- | --- | --- | --- | --- | --- | --- |
| `.text[0]` | `0x00002000 .. 0x00A16EDC` | `0x00A14EDC` | `0x00000400` | `0x00A15000` | `0x60000020` | CLI header, 16 `FieldRVA`s (`0x2048..0x2298`), 6,829 active CIL bodies (`0x2298..0x6DC8B4`), 2 managed resources (`0x6DC8E0..0x887EB8`), orphaned `BSJB #1` (`0x887EB8`), orphaned `BSJB #2` (`0x8E9DCC`) |
| `.rsrc[1]` | `0x00A18000 .. 0x00A30CB2` | `0x00018CB2` | `0x00A15400` | `0x00018E00` | `0x40000040` | Win32 native resources |
| `.text[2]` | `0x00A32000 .. 0x00D70C88` | `0x0033EC88` | `0x00A2E200` | `0x0033EE00` | `0x60000020` | 2,541 active CIL bodies (`0xA32000..0xC427E8`), **active `BSJB #3` metadata** (`0xC428EC..0xD6FA00`, uncompressed `#-` stream) |
| `.text[3]` | `0x00D72000 .. 0x010D46B9` | `0x003626B9` | `0x00D6D000` | `0x00362800` | `0x60000020` | 1,921 active CIL bodies (`0xD72000..0x10D4504`) |

### `BSJB` Metadata Headers Observed
| Pass | File Offset | RVA | Section | Status |
| --- | --- | --- | --- | --- |
| `BSJB #1` | `0x008862B8` | `0x00887EB8` | `.text[0]` | Orphaned (prior `cleaned` pass) |
| `BSJB #2` | `0x008E81CC` | `0x008E9DCC` | `.text[0]` | Orphaned (`demutate2` pass) |
| `BSJB #3` | `0x00C3EAEC` | `0x00C428EC` | `.text[2]` | **Active** (`#-`, `#Strings`, `#US`, `#GUID`, `#Blob`) |

---

## 3. `EB275028` RVA-to-VA / File-Offset Mapper

Type `EB275028` (`0x02000259`) has 2 fields and 4 methods:
- `struct25_0 : Class1026+Struct25[]` (`0x04000DB0`, `Private, Static, InitOnly`) — cached array of 40-byte `IMAGE_SECTION_HEADER` structs (`uint_0` = `VirtualSize`, `uint_1` = `VirtualAddress`, `C603A036` = `SizeOfRawData`, `CD906516` = `PointerToRawData`).
- `byte_0 : System.Byte` (`0x04000DB1`, `Public, Static, InitOnly, HasFieldRva`) — anchor byte intended to point at RVA `0x00000000` (the PE image base / `'M'` of `'MZ'`).
- `smethod_1() : long` (`0x06000C0C`) — executes `ldsflda EB275028::byte_0; conv.u; conv.u8; ret`, returning `(long)(ulong)&byte_0`.
- `NtQueryVirtualMemory(...)` — P/Invoke used by `.cctor`.

### `EB275028::.cctor` (`0x06000C0D`)
1. Calls `V_3 = smethod_1()` (`&byte_0`).
2. Checks `Environment.OSVersion.Platform == PlatformID.Win32NT` (`2`).
3. On Windows, allocates a `MEMORY_BASIC_INFORMATION` buffer (`EB275028+C5B39E98` on 32-bit, `EB275028+BB2E1925` on 64-bit) and calls `NtQueryVirtualMemory(-1, (IntPtr)V_3, 0, buf, size, out retLen)`.
4. Checks whether `Type & 0x01000000` (`MEM_IMAGE` / `SEC_IMAGE`) is set:
   - If `MEM_IMAGE` is set, leaves `struct25_0 == null` (meaning the PE is mapped by the Windows loader at virtual RVAs).
   - If not `MEM_IMAGE` (e.g., `Assembly.Load(byte[])` or non-Windows), parses the DOS header at `V_3` (`Struct27::ushort_0 == 0x5A4D` `'MZ'`), reads `e_lfanew` (`Struct27::uint_0`), validates the PE signature (`F2A134A8::CD80DF1F == 0x00004550`), and copies all `NumberOfSections` `IMAGE_SECTION_HEADER` entries into `EB275028::struct25_0`.

### `EB275028::smethod_0(uint rva)` (`0x06000C0B`)
Pure PE RVA mapping with **zero XOR, delta, relocation, or decryption**:
- **Case 1 (`struct25_0 == null`, `SEC_IMAGE`):**
  `return new IntPtr(smethod_1() + (ulong)rva);`
- **Case 2 (`struct25_0 != null`, raw file image):**
  Iterates `s` in `struct25_0`:
  - If `rva >= s.uint_1` (`VirtualAddress`) and `rva < s.uint_1 + s.uint_0` (`VirtualAddress + VirtualSize`):
    `offset = s.CD906516 + rva - s.uint_1` (`PointerToRawData + rva - VirtualAddress`).
  - Returns `new IntPtr(smethod_1() + (ulong)offset)`.
  - Throws `BadImageFormatException` if no section contains `rva` (and `rva != 0`).

### Relocated `byte_0` Artifact in `cleaned-demutate2-cleaned.exe`
In `cleaned-demutate2-cleaned.exe`, `EB275028::byte_0` has `FieldRVA = 0x00002258` (file offset `0x00000658`) with bytes `4D 00 00 00 00 00 00 00 4D 5A 90 00 03 00 00 00`. During PE rebuilding, `dnlib`/`de4dot` copied the 1-byte `0x4D` (`'M'`) from RVA `0x00000000` into `.text[0]` at `0x00002258` (alongside `B42E8EB0::struct23_0` at `0x2260` and `B42E8EB0::E024538C` at `0x2268`). Consequently, `*(ushort*)&byte_0 == 0x004D != 0x5A4D`, which would trigger `BadImageFormatException` in `.cctor` if executed.

---

## 4. `GClass105` Method Classification (5,365 / 5,365 = 100%)

Every method declared on `GClass105` (`0x02001230`) is classified below:

| Category | Count | Visibility / Flags | Signature | Notes |
| --- | ---: | --- | --- | --- |
| Active VM Handlers | **5,352** | `Private, HideBySig` (instance) | `instance System.Void *()` | Token range `0x0600249F .. 0x06003992`; registered in `dictionary_0` |
| VM Entry Methods | **10** | `Public, HideBySig` (instance) | `instance System.Object *(System.Object, System.Int32)` | Dispatch loops calling the 10 `Class1344` readers |
| Instance Constructor | **1** | `Public, SpecialName, RTSpecialName` | `instance System.Void *()` | `.ctor` — initializes VM stack, locals, exception stack, `class1344_0` |
| Static Constructor | **1** | `Private, Static, SpecialName, RTSpecialName` | `System.Void *()` | `.cctor` — populates `dictionary_0` and reflection caches |
| Other Static Helper | **1** | `Private, Static, HideBySig` | `System.Object *(System.Int32)` | `D62F78B5` (`0x06003497`) — cached `Module.ResolveMember(int)` token resolver backed by `D3AE7D03` |
| **Total** | **5,365** | — | — | **100% accounted for** |

### `GClass105::.cctor` `BindingFlags` Verification
Symbolic/concrete pure-IL tracing of `GClass105::.cctor` recovers the exact `Type.GetMethods(BindingFlags)` call:
```csharp
MethodInfo[] methods = typeof(GClass105).GetMethods(
    (BindingFlags)0x00000026 // BindingFlags.DeclaredOnly (0x02) | BindingFlags.Instance (0x04) | BindingFlags.NonPublic (0x20)
);
foreach (MethodInfo mi in methods) {
    var del = (GClass105.D3031586)Delegate.CreateDelegate(typeof(GClass105.D3031586), mi, throwOnBindFailure: false);
    if (del != null)
        dictionary_0[(uint)mi.MetadataToken] = del;
}
```
Because `0x26` excludes `Public` (the 10 VM entry methods and `.ctor`) and `Static` (`.cctor` and `D62F78B5`), it selects **all 5,352** private instance `void()` handlers and binds each to an open-instance `D3031586` delegate (`void Invoke(GClass105)`) keyed by `(uint)mi.MetadataToken`.

---

## 5. `Class1344` Bytecode Stream & All 10 Reader Specifications (10 / 10 = 100%)

### Stream Initialization (`Class1344::vmethod_0(object)`)
Each of the 10 VM entry methods begins by executing:
```csharp
this.class1344_0.vmethod_0((object)rva); // arg2 boxed as System.Int32
```
Pure-IL tracing of `Class1344::vmethod_0` (for a boxed `Int32` argument) confirms:
1. `V_7 = Convert.ToInt32(arg1)`
2. `this.uint_0 = (uint)V_7` (initial `vIP` RVA)
3. `this.uint_1 = this.uint_0` (initial rolling 32-bit key = initial `vIP` RVA)

### Common Reader Properties
All **10 / 10** `Class1344` handler-token readers share:
- **Load width:** 32-bit unsigned (`ldind.u4`, 4 bytes) via `*(uint*)EB275028::smethod_0(addr)`
- **Pointer field:** `Class1344::uint_0` (`vIP`), advancing by either **post-increment (`+4`)** (read at `vIP`, then `vIP += 4`) or **pre-decrement (`-4`)** (`vIP -= 4`, then read at `vIP`)
- **Rolling key field:** `Class1344::uint_1` (`key`), initialized to the entry RVA and updated after every read via `key = key ^ decryptedToken`
- **Bit-for-bit verification:** Every closed-form formula below was concretely cross-checked against pure-IL execution of the actual obfuscated `Class1344` CIL instructions on `(vIP = 0x00123456, KEY = 0x9ABCDEF0, RAW = 0xCAFEBABE)` — **10 / 10 exact matches**.

### Complete 10-Reader Table

| # | Reader Method | Token | Insns | Paired VM Entry | `ldind` | Pointer Step | Exact Decryptor Pipeline (`x = raw ^ key`, then `key ^= x`) | Concrete Self-Test (`RAW=0xCAFEBABE`) |
| ---: | --- | --- | ---: | --- | --- | --- | --- | --- |
| 1 | `method_3` | `0x06003A91` | 298 | `method_244` (`0x06002626`) | `ldind.u4` | pre-dec `-4` | `x += 1` -> `ROL32(x, 1)` -> `BSWAP32(x)` -> `x = -x` -> `x += 0x05B7E7BA` -> `ROR32(x, 3)` | `0x4CDDEC63` (PASS) |
| 2 | `CE2E0511` | `0x06003AAF` | 348 | `method_436` (`0x06002750`) | `ldind.u4` | post-inc `+4` | `BSWAP32(x)` -> `x += 0x9D8143B6` -> `ROR32(x, 2)` -> `x = ~x` -> `x ^= 0x0F3C8B3C` -> `x = -x` | `0xB5C5EABE` (PASS) |
| 3 | `D483C6B8` | `0x06003A8B` | 184 | `DB92AB3B` (`0x06002846`) | `ldind.u4` | post-inc `+4` | `x += 0x74050EAF` -> `x ^= 0x6B29641D` -> `x -= 0x0D27CF98` -> `ROL32(x, 3)` | `0x12323A45` (PASS) |
| 4 | `method_29` | `0x06003AB9` | 51 | `method_873` (`0x06002A1B`) | `ldind.u4` | pre-dec `-4` | `x ^= 0xF217FE3F` -> `x -= 0x58899E14` -> `x = ~x` -> `x -= 1` | `0xB63403A1` (PASS) |
| 5 | `A8A5451D` | `0x06003AC5` | 354 | `D91D7A34` (`0x06002F00`) | `ldind.u4` | pre-dec `-4` | `x += 0x14B7A4A4` -> `ROL32(x, 3)` -> `x = -x` -> `x -= 0xB92E84AC` -> `x ^= 0xCF1821BC` -> `x += 0xFE899189` | `0xCEA2A406` (PASS) |
| 6 | `method_26` | `0x06003AB4` | 33 | `ADAB18AE` (`0x06002FA9`) | `ldind.u4` | post-inc `+4` | `x = -x` -> `x += 0xCCB60D24` -> `x = ~x` -> `x -= 0x2B9392A2` | `0x57F8C487` (PASS) |
| 7 | `method_34` | `0x06003AC2` | 370 | `ACA9C11A` (`0x0600306C`) | `ldind.u4` | post-inc `+4` | `BSWAP32(x)` -> `ROR32(x, 3)` -> `x -= 1` -> `BSWAP32(x)` | `0x4988CC09` (PASS) |
| 8 | `method_28` | `0x06003AB8` | 311 | `method_2334` (`0x06003334`) | `ldind.u4` | post-inc `+4` | `ROL32(x, 2)` -> `BSWAP32(x)` -> `ROL32(x, 3)` -> `x ^= 0xCE90C317` -> `x = -x` -> `x ^= 0x9D3F7531` | `0x60D803D3` (PASS) |
| 9 | `method_5` | `0x06003A93` | 177 | `method_2491` (`0x06003421`) | `ldind.u4` | pre-dec `-4` | `x += 0x96184602` -> `x = -x` -> `x += 0xC698DF0E` -> `x = -x` | `0x1FC1CB42` (PASS) |
| 10 | `BC017D36` | `0x06003AC6` | 310 | `method_2845` (`0x06003651`) | `ldind.u4` | pre-dec `-4` | `x ^= 0xBB35B2AC` -> `ROL32(x, 1)` -> `x += 1` -> `x = ~x` | `0x29105239` (PASS) |

---

## 6. VM Entry Call Site Inventory (157 / 157 = 100%)

Every external call to any of the 10 `GClass105` VM entry methods is enumerated in full (caller, token, signature, instruction count, IL offset, entry method, `ldc.i4` RVA, PE section, target sub-region, uniqueness) in [`docs/vmp38-inventory.json`](vmp38-inventory.json) under `vmEntryCallSites.callSites`.

### Summary Statistics
- **External constant (`IsLdcI4()`) call sites:** **157 / 157** (`100%`)
- **External non-constant (`!IsLdcI4()`) call sites:** **0**
- **Internal `GClass105` non-constant call sites:** **182** (recursive VM-to-VM call handlers, each preceded by `unbox.any System.Int32`)
- **RVA uniqueness:** **157 unique RVAs**, **0 duplicated RVAs**

### Distribution by VM Entry Method
| VM Entry Method | Reader Method | Direction | Call Sites |
| --- | --- | --- | ---: |
| `ADAB18AE` | `method_26` | post-inc `+4` | 41 |
| `method_2334` | `method_28` | post-inc `+4` | 20 |
| `DB92AB3B` | `D483C6B8` | post-inc `+4` | 17 |
| `method_436` | `CE2E0511` | post-inc `+4` | 15 |
| `ACA9C11A` | `method_34` | post-inc `+4` | 13 |
| `method_2845` | `BC017D36` | pre-dec `-4` | 13 |
| `method_873` | `method_29` | pre-dec `-4` | 13 |
| `method_2491` | `method_5` | pre-dec `-4` | 10 |
| `D91D7A34` | `A8A5451D` | pre-dec `-4` | 8 |
| `method_244` | `method_3` | pre-dec `-4` | 7 |
| **Total** | — | — | **157** |

### Distribution by PE Section & Target Sub-Region
| PE Section | Target Sub-Region | RVA Range | Call Sites |
| --- | --- | --- | ---: |
| `.text[0]` | `ActiveCilBodies(.text[0])` | `0x00005BD8 .. 0x000CD939` | 131 |
| `.text[2]` | `ActiveCilBodies(.text[2])` | `0x00A9B6E8 .. 0x00AA0C45` | 10 |
| `.text[2]` | `ActiveMetadata(#-)` | `0x00C84DDE .. 0x00C910A7` | 16 |
| **Total** | — | — | **157** |

---

## 7. End-to-End Static Decoding Verification & Forensic Root-Cause Proof

Applying the exact recovered `EB275028::smethod_0` RVA-to-file-offset mapping + `Class1344::vmethod_0` initialization (`uint_0 = rva; uint_1 = rva`) + `Class1344` decryptor across **all 157 call sites** yields:
- **Valid `dictionary_0` handler token hits at `step 0`:** **0 / 157**
- **`0x06xxxxxx` (`MethodDef`) prefix hits at `step 0`:** **0 / 157**

Below are the exact 10-step `(vIP, fileOffset, keyBefore, rawU32, decryptedToken, resolvedHandlerMethodName)` static decoding traces for 3 distinct virtualized methods using 3 distinct entry/reader pairs:

### Trace 1: `<Module>::.cctor` via `ADAB18AE` / `Class1344::method_26` (post-inc `+4`, initial RVA `0x00C84DDE` in `.text[2]` active `#-` metadata)
| Step | `vIP` | File Offset | `key` (before) | `rawU32` | `decryptedToken` | `resolvedHandlerMethodName` |
| ---: | --- | --- | --- | --- | --- | --- |
| 0 | `0x00C84DDE` | `0x00C80FDE` | `0x00C84DDE` | `0x00000000` | `0x087EAE17` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 1 | `0x00C84DE2` | `0x00C80FE2` | `0x08B6E3C9` | `0x01C30003` | `0x112C4403` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 2 | `0x00C84DE6` | `0x00C80FE6` | `0x199AA7CA` | `0x0003131D` | `0x21501510` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 3 | `0x00C84DEA` | `0x00C80FEA` | `0x38CAB2DA` | `0x00002CCC` | `0x4080FE4F` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 4 | `0x00C84DEE` | `0x00C80FEE` | `0x784A4C95` | `0xD19822A8` | `0xB188CE76` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 5 | `0x00C84DF2` | `0x00C80FF2` | `0xC9C282E3` | `0x0000000A` | `0xD178E322` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 6 | `0x00C84DF6` | `0x00C80FF6` | `0x18BA61C1` | `0x41E70013` | `0x6113C20B` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 7 | `0x00C84DFA` | `0x00C80FFA` | `0x79A9A3CA` | `0x2CD20000` | `0x5D320403` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 8 | `0x00C84DFE` | `0x00C80FFE` | `0x249BA7C9` | `0x22AA0000` | `0x0DE80802` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 9 | `0x00C84E02` | `0x00C81002` | `0x2973AFCB` | `0x00000000` | `0x312A1004` | `<INVALID_NOT_IN_DICTIONARY_0>` |

### Trace 2: `FB94C222::CBB2F71C` via `ACA9C11A` / `Class1344::method_34` (post-inc `+4`, initial RVA `0x00024064` in `.text[0]` active CIL bodies)
| Step | `vIP` | File Offset | `key` (before) | `rawU32` | `decryptedToken` | `resolvedHandlerMethodName` |
| ---: | --- | --- | --- | --- | --- | --- |
| 0 | `0x00024064` | `0x00022464` | `0x00024064` | `0x012C0400` | `0xBF85882C` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 1 | `0x00024068` | `0x00022468` | `0xBF87C848` | `0x7D17022A` | `0x1752594C` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 2 | `0x0002406C` | `0x0002246C` | `0xA8D59104` | `0x040002C3` | `0xB47AF298` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 3 | `0x00024070` | `0x00022470` | `0x1CAF639C` | `0x00134A7E` | `0x8237459C` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 4 | `0x00024074` | `0x00022474` | `0x9E982600` | `0x06872004` | `0xF2C38000` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 5 | `0x00024078` | `0x00022478` | `0x6C5BA600` | `0x729A0000` | `0x22D814C0` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 6 | `0x0002407C` | `0x0002247C` | `0x4E83B2C0` | `0x70004F49` | `0x66B03FD1` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 7 | `0x00024080` | `0x00022480` | `0x28338D11` | `0x225D6F18` | `0xC04D3C41` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 8 | `0x00024084` | `0x00022484` | `0xE87EB150` | `0x7E0A0600` | `0x91EE16CA` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 9 | `0x00024088` | `0x00022488` | `0x7990A79A` | `0x0400134A` | `0x0E9216BA` | `<INVALID_NOT_IN_DICTIONARY_0>` |

### Trace 3: `FB94C222::method_7` via `DB92AB3B` / `Class1344::D483C6B8` (post-inc `+4`, initial RVA `0x00005BD8` in `.text[0]` active CIL bodies)
| Step | `vIP` | File Offset | `key` (before) | `rawU32` | `decryptedToken` | `resolvedHandlerMethodName` |
| ---: | --- | --- | --- | --- | --- | --- |
| 0 | `0x00005BD8` | `0x00003FD8` | `0x00005BD8` | `0x06CB2004` | `0x2690F7F0` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 1 | `0x00005BDC` | `0x00003FDC` | `0x2690AC28` | `0x6F9A0000` | `0x47F87996` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 2 | `0x00005BE0` | `0x00003FE0` | `0x6168D5BE` | `0x0600233B` | `0x18FC8C8D` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 3 | `0x00005BE4` | `0x00003FE4` | `0x79945933` | `0x0208331E` | `0xBB02694B` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 4 | `0x00005BE8` | `0x00003FE8` | `0xC2963078` | `0x08002803` | `0x44539CFA` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 5 | `0x00005BEC` | `0x00003FEC` | `0x86C5AC82` | `0x7E2A0600` | `0xD5B06CA7` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 6 | `0x00005BF0` | `0x00003FF0` | `0x5375C025` | `0x0400134A` | `0x995DB35C` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 7 | `0x00005BF4` | `0x00003FF4` | `0xCA287379` | `0x0002B120` | `0x3EF72BEA` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 8 | `0x00005BF8` | `0x00003FF8` | `0xF4DF5893` | `0x03029A00` | `0x9D1F2E3F` | `<INVALID_NOT_IN_DICTIONARY_0>` |
| 9 | `0x00005BFC` | `0x00003FFC` | `0x69C076AC` | `0x0007FF28` | `0x4DF164B5` | `<INVALID_NOT_IN_DICTIONARY_0>` |

### Why Decoding Fails on `cleaned-demutate2-cleaned.exe` (4 Independent Proofs)
1. **Raw bytes at call-site RVAs are plaintext CIL / metadata:** In Trace 2 (`0x00024064`), `rawU32` values contain `0x040002C3` (`FieldDef`), `0x70004F49` (`UserString`), `0x72` (`ldstr`), and `0x7E` (`ldsfld`). In Trace 3 (`0x00005BD8`), `rawU32` values contain `0x0600233B` (`MethodDef`) and `0x0400134A` (`FieldDef`). In Trace 1 (`0x00C84DDE`), the RVA lands directly inside the active `#-` metadata table (`0x00C428EC .. 0x00D6FA00`).
2. **Three-pass `dnlib`/`de4dot` rewrite stripped the VMP bytecode section:** The binary contains 3 `.text` sections, 3 `BSJB` metadata headers (`0x887EB8`, `0x8E9DCC`, `0xC428EC`), and 0 `.vmp0`/`.vmp1` sections. All 44 high-entropy (`> 7.75`) 16 KB blocks in the entire 17.6 MB file reside inside `GPMLogin.g.resources` / `FE90F78B.resources` (standard `0xBEEFCACE` .NET `ResourceReader` bundles).
3. **`EB275028::byte_0` was relocated from RVA `0x00000000` to `0x00002258`:** Its 1-byte `0x4D` (`'M'`) payload proves `dnlib` re-emitted `FieldRVA` entries without preserving the original PE layout.
4. **Full-file byte scan confirms no shifted bytecode blob:** Scanning all 17,627,136 bytes for valid `dictionary_0` token pairs produces zero valid bytecode matches.

### Implications for `de4vmp.V2`
- The **VMP 3.8 VM specification** (10-reader `Class1344` dispatch, `uint_0`/`uint_1` rolling XOR cipher, `BindingFlags = 0x26` `GClass105` handler table, `EB275028` pure RVA mapping) is now **100% specified and machine-verified**.
- `de4vmp.V2` should detect corrupted/stripped post-`de4dot` binaries early (e.g., checking `EB275028::byte_0` `FieldRVA != 0`, checking if call-site RVAs land inside active CIL/metadata, or verifying `step 0` token membership in `dictionary_0`) and emit a clear diagnostic rather than silently mis-decoding CIL/metadata bytes as VM opcodes.
- End-to-end devirtualization of `GPMLogin.exe` requires the **un-rewritten** (or section-preserving) VMP 3.8 binary where the original `.vmp` bytecode section and `FieldRVA = 0x00000000` layout are intact.
