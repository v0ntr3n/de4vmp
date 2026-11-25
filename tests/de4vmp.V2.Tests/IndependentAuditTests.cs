using System.Diagnostics;
using System.Reflection;
using System.Runtime.Loader;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using de4vmp.V2.Analysis;
using de4vmp.V2.Models;
using de4vmp.V2.Tests.Fixtures;
using de4vmp.V2.Translation;
using Xunit;
using FieldAttributes = AsmResolver.PE.DotNet.Metadata.Tables.FieldAttributes;
using ManifestResourceAttributes = AsmResolver.PE.DotNet.Metadata.Tables.ManifestResourceAttributes;
using MethodAttributes = AsmResolver.PE.DotNet.Metadata.Tables.MethodAttributes;
using MethodImplAttributes = AsmResolver.PE.DotNet.Metadata.Tables.MethodImplAttributes;
using TypeAttributes = AsmResolver.PE.DotNet.Metadata.Tables.TypeAttributes;

namespace de4vmp.V2.Tests;

/// <summary>
/// Independent Phase 3 benchmark &amp; robustness audit suite:
///   1. Full identifier randomization across Tiers 2-4 (every type, namespace, field, method, resource).
///   2. Malformed inputs &amp; negative tests (random resource bytes, invalid token 0x06FFFFFF, out-of-range branches/EH, non-VM DLL).
///   3. Pre- vs post-transformation behavioral equivalence on independently constructed, CLR-executable mini-VM &amp; CFF methods.
///   4. CLI `--engine v2` end-to-end verification (exit 0 on Tier 3 + working output; exit 3 on non-VM DLL).
/// </summary>
public sealed class IndependentAuditTests {
    private sealed class CollectibleContext : AssemblyLoadContext {
        public CollectibleContext() : base(isCollectible: true) { }
        protected override Assembly? Load(AssemblyName assemblyName) => null;
    }

    // =========================================================================
    // 1. Full Identifier Randomization Across Tiers 2, 3, and 4
    // =========================================================================

    [Theory]
    [InlineData(SyntheticTier.Tier2_32BitDictEncryptedPolymorphic)]
    [InlineData(SyntheticTier.Tier3_CffAndOpaquePredicates)]
    [InlineData(SyntheticTier.Tier4_MultiEntryObjectsAndEh)]
    public void RandomizedIdentifiers_AllSymbolsObfuscated_DevirtualizesWith100PercentEquivalence(SyntheticTier tier) {
        string workDir = CreateTempDir($"rand-ids-{tier}");
        try {
            string origPath = Path.Combine(workDir, $"Orig_{tier}.dll");
            string obfPath = Path.Combine(workDir, $"Obf_{tier}.dll");
            string devirtPath = Path.Combine(workDir, $"Devirt_{tier}.dll");

            var truth = new SyntheticVmCompiler().Generate(tier, origPath);
            var module = ModuleDefinition.FromFile(origPath);

            var rng = new Random(0x5EED_0000 + (int)tier);
            string NextHexName(string prefix) => $"{prefix}_{rng.Next():X8}{rng.Next():X8}";

            // Track renamed target type & methods so we can invoke them post-devirtualization
            string? randomizedTargetTypeFullName = null;
            var targetMethodRenameMap = new Dictionary<string, string>(StringComparer.Ordinal);

            // Randomize EVERY type (and nested type), field, and non-special method in the module
            foreach (var type in module.GetAllTypes()) {
                if (type.IsModuleType)
                    continue;

                bool isTargetType = type.Name == "VirtualizedTargets";
                if (!type.IsNested) {
                    type.Namespace = NextHexName("ns");
                }
                type.Name = NextHexName("T");

                if (isTargetType) {
                    randomizedTargetTypeFullName = $"{type.Namespace}.{type.Name}";
                }

                foreach (var field in type.Fields) {
                    field.Name = NextHexName("f");
                }

                foreach (var method in type.Methods) {
                    // Preserve CLR runtime-special names (.ctor, .cctor) and delegate Invoke
                    if (method.IsConstructor || method.Name == "Invoke")
                        continue;

                    string oldName = method.Name ?? string.Empty;
                    string newName = NextHexName("m");
                    method.Name = newName;

                    if (isTargetType) {
                        targetMethodRenameMap[oldName] = newName;
                    }
                }
            }

            // Randomize EVERY manifest resource name (including VmBytecode)
            foreach (var res in module.Resources) {
                res.Name = NextHexName("res");
            }

            Assert.NotNull(randomizedTargetTypeFullName);
            Assert.Equal(truth.VirtualizedMethods.Count, targetMethodRenameMap.Count);

            // Persist & reload from disk so all metadata tables reflect the randomized names
            module.Write(obfPath);
            var reloaded = ModuleDefinition.FromFile(obfPath);

            var metrics = new V2Devirtualizer().Devirtualize(reloaded);

            // 100% handler discovery and 100% classification accuracy (0 Unknown)
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersDiscovered);
            Assert.Equal(0, metrics.UnknownHandlers);
            Assert.Equal(truth.OpcodeMap.Count, metrics.HandlersClassified);

            foreach (var (key, expectedOp) in truth.OpcodeMap) {
                Assert.True(metrics.Handlers.TryGetValue(key, out var resolved), $"Missing handler key 0x{key:X8}");
                Assert.Equal(expectedOp, resolved!.SemanticOp);
            }

            if (tier >= SyntheticTier.Tier3_CffAndOpaquePredicates) {
                Assert.True(metrics.CffSwitchesEliminated > 0, "Expected CFF switches eliminated on Tier 3+.");
            }

            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDiscovered);
            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDevirtualized);

            reloaded.Write(devirtPath);

            var alc = new CollectibleContext();
            try {
                var asm = alc.LoadFromAssemblyPath(devirtPath);
                var targetType = asm.GetType(randomizedTargetTypeFullName!, throwOnError: true)!;
                VerifyDifferentialEquivalenceWithRenameMap(targetType, targetMethodRenameMap, tier);
            }
            finally {
                alc.Unload();
            }
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    // =========================================================================
    // 2. Malformed Inputs & Negative Tests (Fail-Closed Guarantees)
    // =========================================================================

    [Fact]
    public void MalformedInput_CorruptedRandomResourceBytes_FailsClosedWithoutThrowing() {
        string workDir = CreateTempDir("malformed-random-res");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier2.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier2_CorruptedRes.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier2_32BitDictEncryptedPolymorphic, virtPath);
            var module = ModuleDefinition.FromFile(virtPath);

            var res = module.Resources.First(r => r.Name == "VmBytecode");
            byte[] original = res.GetData()!;
            byte[] garbage = new byte[original.Length];
            new Random(0xBAD_C0DE).NextBytes(garbage);

            module.Resources.Remove(res);
            module.Resources.Add(new ManifestResource("VmBytecode", ManifestResourceAttributes.Public, new DataSegment(garbage)));

            module.Write(modPath);
            var reloaded = ModuleDefinition.FromFile(modPath);

            var targetType = reloaded.TopLevelTypes.First(t => t.Name == "VirtualizedTargets");
            var beforeSnapshots = SnapshotMethodBodies(targetType.Methods);

            var metrics = new V2Devirtualizer().Devirtualize(reloaded);

            Assert.Equal(0, metrics.MethodsDevirtualized);
            Assert.NotEmpty(metrics.Diagnostics);

            // Original stubs must remain untouched when fail-closed
            var afterSnapshots = SnapshotMethodBodies(targetType.Methods);
            Assert.Equal(beforeSnapshots, afterSnapshots);
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void MalformedInput_InvalidMetadataToken0x06FFFFFF_FailsClosedWithoutThrowing() {
        string workDir = CreateTempDir("malformed-invalid-token");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier1.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier1_InvalidToken.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier1_Clean8BitTable, virtPath);
            byte ldcKey = (byte)truth.OpcodeMap.First(kv => kv.Value == SemanticOp.LdcI4).Key;
            byte callKey = (byte)truth.OpcodeMap.First(kv => kv.Value == SemanticOp.Call).Key;
            byte retKey = (byte)truth.OpcodeMap.First(kv => kv.Value == SemanticOp.Ret).Key;

            // Craft a syntactically valid 8-bit method stream containing invalid MethodDef token 0x06FFFFFF
            byte[] craftedBlob;
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms)) {
                bw.Write(0); // localCount
                bw.Write(3); // insnCount
                bw.Write(0); // ehCount
                bw.Write(ldcKey); bw.Write(42);
                bw.Write(callKey); bw.Write(0x06FFFFFF);
                bw.Write(retKey);
                craftedBlob = ms.ToArray();
            }

            var module = ModuleDefinition.FromFile(virtPath);
            ReplaceVmBytecodeAndPointAllCallSitesToOffset(module, craftedBlob, offset: 0);
            module.Write(modPath);

            var reloaded = ModuleDefinition.FromFile(modPath);
            var metrics = new V2Devirtualizer().Devirtualize(reloaded);

            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDiscovered);
            Assert.Equal(0, metrics.MethodsDevirtualized);
            Assert.Contains(metrics.Diagnostics, d => d.Contains("0x06FFFFFF", StringComparison.OrdinalIgnoreCase));
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void MalformedInput_OutOfRangeBranchTarget_FailsClosedWithoutThrowing() {
        string workDir = CreateTempDir("malformed-oob-branch");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier1.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier1_OobBranch.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier1_Clean8BitTable, virtPath);
            byte ldcKey = (byte)truth.OpcodeMap.First(kv => kv.Value == SemanticOp.LdcI4).Key;
            byte brKey = (byte)truth.OpcodeMap.First(kv => kv.Value == SemanticOp.Br).Key;
            byte retKey = (byte)truth.OpcodeMap.First(kv => kv.Value == SemanticOp.Ret).Key;

            // Craft two streams: one with branch target 9999, one with negative target -1
            byte[] craftedBlob;
            int secondOffset;
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms)) {
                // Stream 0: positive OOB branch
                bw.Write(0); // localCount
                bw.Write(3); // insnCount
                bw.Write(0); // ehCount
                bw.Write(ldcKey); bw.Write(1);
                bw.Write(brKey); bw.Write(9999);
                bw.Write(retKey);

                secondOffset = (int)ms.Position;
                // Stream 1: negative OOB branch
                bw.Write(0); // localCount
                bw.Write(3); // insnCount
                bw.Write(0); // ehCount
                bw.Write(ldcKey); bw.Write(2);
                bw.Write(brKey); bw.Write(-1);
                bw.Write(retKey);

                craftedBlob = ms.ToArray();
            }

            var module = ModuleDefinition.FromFile(virtPath);
            ReplaceVmBytecodeAndPointCallSitesAlternating(module, craftedBlob, 0, secondOffset);
            module.Write(modPath);

            var reloaded = ModuleDefinition.FromFile(modPath);
            var metrics = new V2Devirtualizer().Devirtualize(reloaded);

            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDiscovered);
            Assert.Equal(0, metrics.MethodsDevirtualized);
            Assert.Contains(metrics.Diagnostics, d => d.Contains("branch target", StringComparison.OrdinalIgnoreCase) &&
                                                      d.Contains("out of range", StringComparison.OrdinalIgnoreCase));
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void MalformedInput_OutOfRangeEhIndex_FailsClosedWithoutThrowing() {
        string workDir = CreateTempDir("malformed-oob-eh");
        try {
            string virtPath = Path.Combine(workDir, "Virt_Tier1.dll");
            string modPath = Path.Combine(workDir, "Virt_Tier1_OobEh.dll");

            var truth = new SyntheticVmCompiler().Generate(SyntheticTier.Tier1_Clean8BitTable, virtPath);
            byte ldcKey = (byte)truth.OpcodeMap.First(kv => kv.Value == SemanticOp.LdcI4).Key;
            byte retKey = (byte)truth.OpcodeMap.First(kv => kv.Value == SemanticOp.Ret).Key;

            // Craft valid 2-instruction method with 1 EH clause referencing out-of-range vIP indices [0..50) / [50..99)
            byte[] craftedBlob;
            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms)) {
                bw.Write(0); // localCount
                bw.Write(2); // insnCount
                bw.Write(1); // ehCount
                bw.Write(ldcKey); bw.Write(7);
                bw.Write(retKey);
                // EH clause: Kind, TryStart, TryEnd, HandlerStart, HandlerEnd, CatchTypeToken
                bw.Write(0);
                bw.Write(0);
                bw.Write(50);
                bw.Write(50);
                bw.Write(99);
                bw.Write(0);
                craftedBlob = ms.ToArray();
            }

            var module = ModuleDefinition.FromFile(virtPath);
            ReplaceVmBytecodeAndPointAllCallSitesToOffset(module, craftedBlob, offset: 0);
            module.Write(modPath);

            var reloaded = ModuleDefinition.FromFile(modPath);
            var metrics = new V2Devirtualizer().Devirtualize(reloaded);

            Assert.Equal(truth.VirtualizedMethods.Count, metrics.MethodsDiscovered);
            Assert.Equal(0, metrics.MethodsDevirtualized);
            Assert.Contains(metrics.Diagnostics, d => d.Contains("EH region out of range", StringComparison.OrdinalIgnoreCase));
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void NonVmAssembly_De4vmpV2Dll_ReturnsZeroAndLeavesAllMethodsUnmodified() {
        string v2DllPath = typeof(V2Devirtualizer).Assembly.Location;
        Assert.True(File.Exists(v2DllPath));

        var module = ModuleDefinition.FromFile(v2DllPath);
        var allMethods = module.GetAllTypes().SelectMany(t => t.Methods).ToList();
        var beforeSnapshots = SnapshotMethodBodies(allMethods);

        var metrics = new V2Devirtualizer().Devirtualize(module);

        Assert.Equal(0, metrics.MethodsDiscovered);
        Assert.Equal(0, metrics.MethodsDevirtualized);
        Assert.Equal(0, metrics.HandlersDiscovered);
        Assert.Equal(0, metrics.HandlersClassified);
        Assert.Equal(0, metrics.UnknownHandlers);
        Assert.Equal(0, metrics.CffSwitchesEliminated);

        var afterSnapshots = SnapshotMethodBodies(allMethods);
        Assert.Equal(beforeSnapshots, afterSnapshots);
    }

    // =========================================================================
    // 3. Pre- vs Post-Transformation Behavioral Equivalence (CLR-Executable!)
    // =========================================================================

    [Fact]
    public void PreVsPostTransformation_IndependentlyConstructedExecutableMiniVm_MatchesBitForBit() {
        string workDir = CreateTempDir("exec-mini-vm");
        try {
            string origPath = Path.Combine(workDir, "ExecutableMiniVm_Orig.dll");
            string devirtPath = Path.Combine(workDir, "ExecutableMiniVm_Devirt.dll");

            // Reference C# oracle for the two methods compiled into our independently built executable mini-VM
            static int OracleMixAccumulate(int n, int seed) {
                int acc = seed;
                int i = 0;
                while (i < n) {
                    acc = unchecked((acc + i) ^ (seed - i));
                    i = unchecked(i + 1);
                }
                return acc;
            }

            static int OraclePolyBlend(int a, int b) {
                int sum = unchecked(a + b);
                int diff = unchecked(a - b);
                if (sum < diff) {
                    return unchecked((sum * 5) ^ diff);
                }
                return unchecked((diff * 3) + sum);
            }

            // Build a genuinely CLR-executable mini-VM assembly (interpreter loop runs real bytecode!)
            BuildExecutableMiniVmAssembly(origPath);

            // Generate boundary + randomized inputs
            var rng = new Random(0x2026_CAFE);
            var mixInputs = new List<(int N, int Seed)> {
                (-5, 0), (0, 42), (1, -1), (2, 100), (10, -777), (25, 0x12345), (50, int.MaxValue / 4)
            };
            while (mixInputs.Count < 100) {
                mixInputs.Add((rng.Next(-2, 40), rng.Next(-100_000, 100_000)));
            }

            var blendInputs = new List<(int A, int B)> {
                (0, 0), (1, -1), (-1, 1), (0, 100), (100, 0), (-500, -500), (short.MaxValue, short.MinValue)
            };
            while (blendInputs.Count < 100) {
                blendInputs.Add((rng.Next(-50_000, 50_000), rng.Next(-50_000, 50_000)));
            }

            // 1. PRE-TRANSFORMATION: Actually execute the virtualized methods on the live CLR via our mini-VM interpreter!
            var preMixResults = new int[mixInputs.Count];
            var preBlendResults = new int[blendInputs.Count];

            var preAlc = new CollectibleContext();
            try {
                var origAsm = preAlc.LoadFromAssemblyPath(origPath);
                var origType = origAsm.GetType("AuditMiniVm.VirtualizedSuite", throwOnError: true)!;
                var origMix = origType.GetMethod("MixAccumulate", BindingFlags.Public | BindingFlags.Static)!;
                var origBlend = origType.GetMethod("PolyBlend", BindingFlags.Public | BindingFlags.Static)!;

                for (int i = 0; i < mixInputs.Count; i++) {
                    int actual = (int)origMix.Invoke(null, [mixInputs[i].N, mixInputs[i].Seed])!;
                    Assert.Equal(OracleMixAccumulate(mixInputs[i].N, mixInputs[i].Seed), actual);
                    preMixResults[i] = actual;
                }
                for (int i = 0; i < blendInputs.Count; i++) {
                    int actual = (int)origBlend.Invoke(null, [blendInputs[i].A, blendInputs[i].B])!;
                    Assert.Equal(OraclePolyBlend(blendInputs[i].A, blendInputs[i].B), actual);
                    preBlendResults[i] = actual;
                }
            }
            finally {
                preAlc.Unload();
            }

            // 2. RUN V2DEVIRTUALIZER on the executable mini-VM assembly
            var module = ModuleDefinition.FromFile(origPath);
            var metrics = new V2Devirtualizer().Devirtualize(module);

            Assert.Equal(12, metrics.HandlersDiscovered);
            Assert.Equal(12, metrics.HandlersClassified);
            Assert.Equal(0, metrics.UnknownHandlers);
            Assert.Equal(2, metrics.MethodsDiscovered);
            Assert.Equal(2, metrics.MethodsDevirtualized);

            // Verify devirtualized methods no longer call the VM interpreter!
            var devirtTargetType = module.TopLevelTypes.First(t => t.Name == "VirtualizedSuite");
            foreach (var m in devirtTargetType.Methods) {
                Assert.DoesNotContain(m.CilMethodBody!.Instructions,
                    i => i.OpCode.Code is CilCode.Call or CilCode.Callvirt &&
                         i.Operand is IMethodDescriptor md &&
                         md.DeclaringType?.Name == "LiveInterpreter");
            }

            module.Write(devirtPath);

            // 3. POST-TRANSFORMATION: Execute devirtualized native CIL on the CLR and compare bit-for-bit against pre-transformation!
            var postAlc = new CollectibleContext();
            try {
                var devirtAsm = postAlc.LoadFromAssemblyPath(devirtPath);
                var postType = devirtAsm.GetType("AuditMiniVm.VirtualizedSuite", throwOnError: true)!;
                var postMix = postType.GetMethod("MixAccumulate", BindingFlags.Public | BindingFlags.Static)!;
                var postBlend = postType.GetMethod("PolyBlend", BindingFlags.Public | BindingFlags.Static)!;

                for (int i = 0; i < mixInputs.Count; i++) {
                    int postActual = (int)postMix.Invoke(null, [mixInputs[i].N, mixInputs[i].Seed])!;
                    Assert.Equal(preMixResults[i], postActual);
                }
                for (int i = 0; i < blendInputs.Count; i++) {
                    int postActual = (int)postBlend.Invoke(null, [blendInputs[i].A, blendInputs[i].B])!;
                    Assert.Equal(preBlendResults[i], postActual);
                }
            }
            finally {
                postAlc.Unload();
            }
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    [Fact]
    public void PreVsPostTransformation_IndependentlyConstructedExecutableCffLoop_MatchesBitForBit() {
        string workDir = CreateTempDir("exec-cff-loop");
        try {
            string flatPath = Path.Combine(workDir, "CffLoop_Orig.dll");
            string unflatPath = Path.Combine(workDir, "CffLoop_Unflat.dll");

            // Reference oracle: loop + conditional branch
            static int OracleCffCompute(int n, int k) {
                int acc = k ^ 0x5A;
                int i = 0;
                while (i < n) {
                    if ((i & 1) == 0)
                        acc = unchecked(acc + (i * 3));
                    else
                        acc = unchecked(acc ^ (i + k));
                    i++;
                }
                return acc;
            }

            var (module, method) = BuildExecutableCffLoopModule();
            method.CilMethodBody!.ComputeMaxStack();
            module.Write(flatPath);

            // Build boundary + randomized inputs
            var rng = new Random(unchecked((int)0xCFFA_1234));
            var inputs = new List<(int N, int K)> {
                (-10, 0), (0, 0), (0, -1), (1, 7), (2, -99), (10, 12345), (30, -54321)
            };
            while (inputs.Count < 100) {
                inputs.Add((rng.Next(-3, 35), rng.Next(-100_000, 100_000)));
            }

            // 1. PRE-TRANSFORMATION: Execute the CFF-flattened method on the live CLR
            var preResults = new int[inputs.Count];
            var preAlc = new CollectibleContext();
            try {
                var flatMi = preAlc.LoadFromAssemblyPath(flatPath)
                    .GetType("AuditCff.LoopTarget", throwOnError: true)!
                    .GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;

                for (int i = 0; i < inputs.Count; i++) {
                    int actual = (int)flatMi.Invoke(null, [inputs[i].N, inputs[i].K])!;
                    Assert.Equal(OracleCffCompute(inputs[i].N, inputs[i].K), actual);
                    preResults[i] = actual;
                }
            }
            finally {
                preAlc.Unload();
            }

            // 2. UNFLATTEN via CffUnflattener
            var unflatModule = ModuleDefinition.FromFile(flatPath);
            var unflatMethod = unflatModule.TopLevelTypes.First(t => t.Name == "LoopTarget").Methods.First(m => m.Name == "Run");
            var cffResult = new CffUnflattener().Unflatten(unflatMethod.CilMethodBody!);

            Assert.True(cffResult.WasFlattened);
            Assert.True(cffResult.SwitchesEliminated >= 1);
            Assert.DoesNotContain(unflatMethod.CilMethodBody!.Instructions, i => i.OpCode.Code == CilCode.Switch);

            unflatMethod.CilMethodBody.ComputeMaxStack();
            unflatModule.Write(unflatPath);

            // 3. POST-TRANSFORMATION: Execute the unflattened method on the live CLR & compare bit-for-bit
            var postAlc = new CollectibleContext();
            try {
                var unflatMi = postAlc.LoadFromAssemblyPath(unflatPath)
                    .GetType("AuditCff.LoopTarget", throwOnError: true)!
                    .GetMethod("Run", BindingFlags.Public | BindingFlags.Static)!;

                for (int i = 0; i < inputs.Count; i++) {
                    int postActual = (int)unflatMi.Invoke(null, [inputs[i].N, inputs[i].K])!;
                    Assert.Equal(preResults[i], postActual);
                }
            }
            finally {
                postAlc.Unload();
            }
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    // =========================================================================
    // 4. CLI `--engine v2` End-to-End Test (Exit 0 on Tier 3, Exit 3 on Non-VM)
    // =========================================================================

    [Fact]
    public void CliEndToEnd_EngineV2_SucceedsOnTier3AndExits3OnNonVmDll() {
        string workDir = CreateTempDir("cli-e2e-v2");
        try {
            var (cliFileName, cliPrefixArgs) = ResolveOrBuildCli(workDir);

            // --- Case A: Synthetic Tier 3 DLL -> Exit 0 + valid working devirtualized DLL ---
            string tier3Input = Path.Combine(workDir, "Virt_Tier3.dll");
            string tier3Output = Path.Combine(workDir, "Devirt_Tier3.dll");
            new SyntheticVmCompiler().Generate(SyntheticTier.Tier3_CffAndOpaquePredicates, tier3Input);

            var okRun = RunProcess(cliFileName, [.. cliPrefixArgs, "--engine", "v2", "--ci", "--no-banner", "-i", tier3Input, "-o", tier3Output]);
            Assert.True(okRun.ExitCode == 0,
                $"Expected CLI exit code 0 on Tier 3 DLL, got {okRun.ExitCode}.\nSTDOUT:\n{okRun.StdOut}\nSTDERR:\n{okRun.StdErr}");
            Assert.True(File.Exists(tier3Output), $"Expected devirtualized output at {tier3Output}");

            // Load CLI-produced devirtualized DLL and verify full behavioral equivalence!
            var alc = new CollectibleContext();
            try {
                var asm = alc.LoadFromAssemblyPath(tier3Output);
                var targetType = asm.GetType("SyntheticFixture.VirtualizedTargets", throwOnError: true)!;
                var identityMap = new Dictionary<string, string>(StringComparer.Ordinal) {
                    [nameof(ReferenceSuite.AddSubMul)] = nameof(ReferenceSuite.AddSubMul),
                    [nameof(ReferenceSuite.XorShiftMix)] = nameof(ReferenceSuite.XorShiftMix),
                    [nameof(ReferenceSuite.Clamp)] = nameof(ReferenceSuite.Clamp),
                    [nameof(ReferenceSuite.SumRange)] = nameof(ReferenceSuite.SumRange),
                    [nameof(ReferenceSuite.Gcd)] = nameof(ReferenceSuite.Gcd),
                    [nameof(ReferenceSuite.ClassifyScore)] = nameof(ReferenceSuite.ClassifyScore),
                };
                VerifyDifferentialEquivalenceWithRenameMap(targetType, identityMap, SyntheticTier.Tier3_CffAndOpaquePredicates);
            }
            finally {
                alc.Unload();
            }

            // --- Case B: Non-VM .NET DLL (de4vmp.V2.dll) -> Exit 3 (DevirtualizationError) ---
            string nonVmInput = typeof(V2Devirtualizer).Assembly.Location;
            string nonVmOutput = Path.Combine(workDir, "ShouldNotExist.dll");

            var failRun = RunProcess(cliFileName, [.. cliPrefixArgs, "--engine", "v2", "--ci", "--no-banner", "-i", nonVmInput, "-o", nonVmOutput]);
            Assert.True(failRun.ExitCode == 3,
                $"Expected CLI exit code 3 on non-VM DLL, got {failRun.ExitCode}.\nSTDOUT:\n{failRun.StdOut}\nSTDERR:\n{failRun.StdErr}");
            Assert.False(File.Exists(nonVmOutput), "CLI should not write an output file when V2 devirtualizes 0 methods.");
        }
        finally {
            SafeDeleteDir(workDir);
        }
    }

    // =========================================================================
    // Helpers & Independent Synthetic Builders
    // =========================================================================

    private static void VerifyDifferentialEquivalenceWithRenameMap(
        Type targetType,
        Dictionary<string, string> renameMap,
        SyntheticTier tier) {
        MethodInfo GetMapped(string origName) =>
            targetType.GetMethod(renameMap[origName], BindingFlags.Public | BindingFlags.Static)
            ?? throw new InvalidOperationException($"Could not find mapped method '{origName}' -> '{renameMap[origName]}'");

        var rng = new Random(unchecked((int)0xA0D1_7777));

        var addSubMul = GetMapped(nameof(ReferenceSuite.AddSubMul));
        foreach (int a in new[] { 0, 1, -1, 42, -99, short.MaxValue, short.MinValue }) {
            foreach (int b in new[] { 0, 1, -1, 17, -1000 }) {
                Assert.Equal(ReferenceSuite.AddSubMul(a, b), (int)addSubMul.Invoke(null, [a, b])!);
            }
        }
        for (int i = 0; i < 40; i++) {
            int a = rng.Next(-100_000, 100_000), b = rng.Next(-100_000, 100_000);
            Assert.Equal(ReferenceSuite.AddSubMul(a, b), (int)addSubMul.Invoke(null, [a, b])!);
        }

        var xorShift = GetMapped(nameof(ReferenceSuite.XorShiftMix));
        for (int i = 0; i < 40; i++) {
            int x = rng.Next(int.MinValue, int.MaxValue), y = rng.Next(int.MinValue, int.MaxValue);
            Assert.Equal(ReferenceSuite.XorShiftMix(x, y), (int)xorShift.Invoke(null, [x, y])!);
        }

        var clamp = GetMapped(nameof(ReferenceSuite.Clamp));
        for (int i = 0; i < 40; i++) {
            int min = rng.Next(-500, 500), max = min + rng.Next(0, 500), v = rng.Next(-1000, 1000);
            Assert.Equal(ReferenceSuite.Clamp(v, min, max), (int)clamp.Invoke(null, [v, min, max])!);
        }

        var sumRange = GetMapped(nameof(ReferenceSuite.SumRange));
        foreach (int n in new[] { -5, 0, 1, 2, 10, 50, 100 }) {
            Assert.Equal(ReferenceSuite.SumRange(n), (int)sumRange.Invoke(null, [n])!);
        }

        var gcd = GetMapped(nameof(ReferenceSuite.Gcd));
        foreach (var (a, b) in new[] { (0, 0), (0, 15), (15, 0), (48, 18), (-48, 18), (1071, 462), (17, 13) }) {
            Assert.Equal(ReferenceSuite.Gcd(a, b), (int)gcd.Invoke(null, [a, b])!);
        }

        var classify = GetMapped(nameof(ReferenceSuite.ClassifyScore));
        foreach (int s in new[] { -10, -1, 0, 49, 50, 79, 80, 100 }) {
            Assert.Equal(ReferenceSuite.ClassifyScore(s), (int)classify.Invoke(null, [s])!);
        }

        if (tier >= SyntheticTier.Tier4_MultiEntryObjectsAndEh) {
            var sumArray = GetMapped(nameof(ReferenceSuite.SumArray));
            foreach (var arr in new[] { Array.Empty<int>(), [5], [1, -2, 3, 4, -5, 100] }) {
                Assert.Equal(ReferenceSuite.SumArray(arr), (int)sumArray.Invoke(null, [arr])!);
            }

            var counterInc = GetMapped(nameof(ReferenceSuite.CounterIncrement));
            var c1 = new ReferenceCounter(10);
            var c2 = new ReferenceCounter(10);
            Assert.Equal(ReferenceSuite.CounterIncrement(c1, 7), (int)counterInc.Invoke(null, [c2, 7])!);
            Assert.Equal(c1.Value, c2.Value);

            var makeCounter = GetMapped(nameof(ReferenceSuite.MakeCounter));
            var expectedCounter = ReferenceSuite.MakeCounter(25);
            var actualCounter = (ReferenceCounter)makeCounter.Invoke(null, [25])!;
            Assert.Equal(expectedCounter.Value, actualCounter.Value);

            var safeDivide = GetMapped(nameof(ReferenceSuite.SafeDivide));
            Assert.Equal(ReferenceSuite.SafeDivide(20, 4), (int)safeDivide.Invoke(null, [20, 4])!);
            Assert.Equal(ReferenceSuite.SafeDivide(20, 0), (int)safeDivide.Invoke(null, [20, 0])!);

            var tryFinally = GetMapped(nameof(ReferenceSuite.TryFinallyAccumulate));
            Assert.Equal(ReferenceSuite.TryFinallyAccumulate(10, 5), (int)tryFinally.Invoke(null, [10, 5])!);
            Assert.Equal(ReferenceSuite.TryFinallyAccumulate(-3, 8), (int)tryFinally.Invoke(null, [-3, 8])!);
        }
    }

    private static void ReplaceVmBytecodeAndPointAllCallSitesToOffset(ModuleDefinition module, byte[] newBlob, int offset) {
        ReplaceVmBytecodeAndPointCallSitesAlternating(module, newBlob, offset, offset);
    }

    private static void ReplaceVmBytecodeAndPointCallSitesAlternating(ModuleDefinition module, byte[] newBlob, int offsetA, int offsetB) {
        var res = module.Resources.First(r => r.Name == "VmBytecode");
        module.Resources.Remove(res);
        module.Resources.Add(new ManifestResource("VmBytecode", ManifestResourceAttributes.Public, new DataSegment(newBlob)));

        var targetType = module.TopLevelTypes.First(t => t.Name == "VirtualizedTargets");
        int idx = 0;
        foreach (var m in targetType.Methods) {
            var insns = m.CilMethodBody!.Instructions;
            insns.ExpandMacros();
            for (int i = 1; i < insns.Count; i++) {
                if (insns[i].OpCode.Code is CilCode.Call or CilCode.Callvirt &&
                    insns[i].Operand is MethodDefinition callee &&
                    callee.Name?.Value.StartsWith("Execute_") == true &&
                    insns[i - 1].IsLdcI4()) {
                    insns[i - 1].OpCode = CilOpCodes.Ldc_I4;
                    insns[i - 1].Operand = (idx % 2 == 0) ? offsetA : offsetB;
                    idx++;
                    break;
                }
            }
            m.CilMethodBody.ComputeMaxStack();
        }
    }

    private static Dictionary<string, string> SnapshotMethodBodies(IEnumerable<MethodDefinition> methods) {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var m in methods) {
            if (m.CilMethodBody is null)
                continue;
            string key = $"{m.DeclaringType?.FullName}::{m.Name}({m.Parameters.Count})@{m.MetadataToken}";
            string sig = string.Join(",", m.CilMethodBody.Instructions.Select(i => i.OpCode.Code.ToString()));
            result[key] = $"{m.CilMethodBody.Instructions.Count}:{sig}";
        }
        return result;
    }

    private static ModuleDefinition CreateFreshNet8Module(string name) {
        var refModule = ModuleDefinition.FromFile(typeof(ReferenceSuite).Assembly.Location);
        var module = new ModuleDefinition($"{name}.dll", refModule.CorLibTypeFactory.CorLibScope as AssemblyReference);
        var assembly = new AssemblyDefinition(name, new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        return module;
    }

    /// <summary>
    /// Independently builds a real, CLR-executable 8-bit stack-VM assembly whose Execute(object[], int)
    /// interpreter loop actually loads and executes the embedded bytecode on the live .NET 8 CLR.
    /// </summary>
    private static void BuildExecutableMiniVmAssembly(string outputPath) {
        var module = CreateFreshNet8Module("AuditMiniVm");
        var importer = module.DefaultImporter;
        var corlib = module.CorLibTypeFactory;

        var objType = corlib.Object;
        var voidType = corlib.Void;
        var int32Type = corlib.Int32;
        var boolType = corlib.Boolean;
        var byteArrayType = corlib.Byte.MakeSzArrayType();
        var intArrayType = int32Type.MakeSzArrayType();
        var objArrayType = objType.MakeSzArrayType();

        var objectCtor = importer.ImportMethod(typeof(object).GetConstructor(Type.EmptyTypes)!);
        var multicastDelegateRef = importer.ImportType(typeof(MulticastDelegate));
        var bitConvToInt32 = importer.ImportMethod(typeof(BitConverter).GetMethod(nameof(BitConverter.ToInt32), [typeof(byte[]), typeof(int)])!);
        var asmGetExec = importer.ImportMethod(typeof(Assembly).GetMethod(nameof(Assembly.GetExecutingAssembly), Type.EmptyTypes)!);
        var asmGetResStream = importer.ImportMethod(typeof(Assembly).GetMethod(nameof(Assembly.GetManifestResourceStream), [typeof(string)])!);
        var memStreamCtor = importer.ImportMethod(typeof(MemoryStream).GetConstructor(Type.EmptyTypes)!);
        var streamCopyTo = importer.ImportMethod(typeof(Stream).GetMethod(nameof(Stream.CopyTo), [typeof(Stream)])!);
        var memStreamToArray = importer.ImportMethod(typeof(MemoryStream).GetMethod(nameof(MemoryStream.ToArray), Type.EmptyTypes)!);

        // VM runtime type
        var vmType = new TypeDefinition("AuditMiniVm", "LiveInterpreter", TypeAttributes.Public | TypeAttributes.Class, importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(vmType);

        // Nested delegate: public delegate void VmOp();
        var delType = new TypeDefinition("", "VmOp", TypeAttributes.NestedPublic | TypeAttributes.Sealed | TypeAttributes.Class, multicastDelegateRef);
        vmType.NestedTypes.Add(delType);
        var delCtor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateInstance(voidType, [objType, corlib.IntPtr])) {
            ImplAttributes = MethodImplAttributes.Runtime | MethodImplAttributes.Managed
        };
        var delInvoke = new MethodDefinition("Invoke",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.NewSlot | MethodAttributes.Virtual,
            MethodSignature.CreateInstance(voidType)) {
            ImplAttributes = MethodImplAttributes.Runtime | MethodImplAttributes.Managed
        };
        delType.Methods.Add(delCtor);
        delType.Methods.Add(delInvoke);

        // VM state fields
        var codeField = new FieldDefinition("_code", FieldAttributes.Private, new FieldSignature(byteArrayType));
        var ipField = new FieldDefinition("_ip", FieldAttributes.Private, new FieldSignature(int32Type));
        var spField = new FieldDefinition("_sp", FieldAttributes.Private, new FieldSignature(int32Type));
        var stackField = new FieldDefinition("_stack", FieldAttributes.Private, new FieldSignature(intArrayType));
        var argsField = new FieldDefinition("_args", FieldAttributes.Private, new FieldSignature(objArrayType));
        var localsField = new FieldDefinition("_locals", FieldAttributes.Private, new FieldSignature(intArrayType));
        var haltedField = new FieldDefinition("_halted", FieldAttributes.Private, new FieldSignature(boolType));
        var dispatchField = new FieldDefinition("_dispatch", FieldAttributes.Private, new FieldSignature(delType.ToTypeSignature().MakeSzArrayType()));

        vmType.Fields.Add(codeField);
        vmType.Fields.Add(ipField);
        vmType.Fields.Add(spField);
        vmType.Fields.Add(stackField);
        vmType.Fields.Add(argsField);
        vmType.Fields.Add(localsField);
        vmType.Fields.Add(haltedField);
        vmType.Fields.Add(dispatchField);

        // Helpers (real, working stack-VM primitives)
        var readI4 = new MethodDefinition("R4", MethodAttributes.Private, MethodSignature.CreateInstance(int32Type));
        var push = new MethodDefinition("Pu", MethodAttributes.Private, MethodSignature.CreateInstance(voidType, [int32Type]));
        var pop = new MethodDefinition("Po", MethodAttributes.Private, MethodSignature.CreateInstance(int32Type));
        var getArg = new MethodDefinition("Ga", MethodAttributes.Private, MethodSignature.CreateInstance(int32Type));
        var getLoc = new MethodDefinition("Gl", MethodAttributes.Private, MethodSignature.CreateInstance(int32Type));
        var setLoc = new MethodDefinition("Sl", MethodAttributes.Private, MethodSignature.CreateInstance(voidType, [int32Type]));
        var jump = new MethodDefinition("Jp", MethodAttributes.Private, MethodSignature.CreateInstance(voidType));
        var jumpFalse = new MethodDefinition("Jf", MethodAttributes.Private, MethodSignature.CreateInstance(voidType));
        var halt = new MethodDefinition("Ht", MethodAttributes.Private, MethodSignature.CreateInstance(voidType));

        vmType.Methods.Add(readI4);
        vmType.Methods.Add(push);
        vmType.Methods.Add(pop);
        vmType.Methods.Add(getArg);
        vmType.Methods.Add(getLoc);
        vmType.Methods.Add(setLoc);
        vmType.Methods.Add(jump);
        vmType.Methods.Add(jumpFalse);
        vmType.Methods.Add(halt);

        // R4: int v = BitConverter.ToInt32(_code, _ip); _ip += 4; return v;
        {
            var b = new CilMethodBody { InitializeLocals = true };
            var v = new CilLocalVariable(int32Type);
            b.LocalVariables.Add(v);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, codeField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, ipField);
            b.Instructions.Add(CilOpCodes.Call, bitConvToInt32);
            b.Instructions.Add(CilOpCodes.Stloc, v);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, ipField);
            b.Instructions.Add(CilOpCodes.Ldc_I4_4); b.Instructions.Add(CilOpCodes.Add);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(CilOpCodes.Ldloc, v);
            b.Instructions.Add(CilOpCodes.Ret);
            readI4.CilMethodBody = b;
        }
        // Pu(int v): _stack[_sp] = v; _sp += 1;
        {
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, stackField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldarg_1); b.Instructions.Add(CilOpCodes.Stelem_I4);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1); b.Instructions.Add(CilOpCodes.Add);
            b.Instructions.Add(CilOpCodes.Stfld, spField);
            b.Instructions.Add(CilOpCodes.Ret);
            push.CilMethodBody = b;
        }
        // Po(): _sp -= 1; return _stack[_sp];
        {
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1); b.Instructions.Add(CilOpCodes.Sub);
            b.Instructions.Add(CilOpCodes.Stfld, spField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, stackField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldelem_I4);
            b.Instructions.Add(CilOpCodes.Ret);
            pop.CilMethodBody = b;
        }
        // Ga(): return (int)_args[R4()];
        {
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, argsField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, readI4);
            b.Instructions.Add(CilOpCodes.Ldelem_Ref);
            b.Instructions.Add(CilOpCodes.Unbox_Any, int32Type.ToTypeDefOrRef());
            b.Instructions.Add(CilOpCodes.Ret);
            getArg.CilMethodBody = b;
        }
        // Gl(): return _locals[R4()];
        {
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, localsField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, readI4);
            b.Instructions.Add(CilOpCodes.Ldelem_I4);
            b.Instructions.Add(CilOpCodes.Ret);
            getLoc.CilMethodBody = b;
        }
        // Sl(int v): _locals[R4()] = v;
        {
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, localsField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, readI4);
            b.Instructions.Add(CilOpCodes.Ldarg_1);
            b.Instructions.Add(CilOpCodes.Stelem_I4);
            b.Instructions.Add(CilOpCodes.Ret);
            setLoc.CilMethodBody = b;
        }
        // Jp(): _ip = R4(); (sets _ip to target vIP; Execute maps vIP < 128 -> byte offset)
        {
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, readI4);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(CilOpCodes.Ret);
            jump.CilMethodBody = b;
        }
        // Jf(): int t = R4(); if (Po() == 0) _ip = t;
        {
            var b = new CilMethodBody { InitializeLocals = true };
            var t = new CilLocalVariable(int32Type);
            b.LocalVariables.Add(t);
            var done = new CilInstruction(CilOpCodes.Ret);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, readI4);
            b.Instructions.Add(CilOpCodes.Stloc, t);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, pop);
            b.Instructions.Add(CilOpCodes.Brtrue_S, done.CreateLabel());
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldloc, t);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(done);
            jumpFalse.CilMethodBody = b;
        }
        // Ht(): _halted = true;
        {
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1);
            b.Instructions.Add(CilOpCodes.Stfld, haltedField);
            b.Instructions.Add(CilOpCodes.Ret);
            halt.CilMethodBody = b;
        }

        // Opcode table (1..12):
        // 1=LdcI4, 2=LdArg, 3=LdLoc, 4=StLoc, 5=Br, 6=BrFalse, 7=Ret,
        // 8=Add (polymorphic), 9=Sub, 10=Mul, 11=Xor (polymorphic), 12=Clt
        const byte OP_LDC = 1, OP_LDARG = 2, OP_LDLOC = 3, OP_STLOC = 4, OP_BR = 5, OP_BRFALSE = 6,
                   OP_RET = 7, OP_ADD = 8, OP_SUB = 9, OP_MUL = 10, OP_XOR = 11, OP_CLT = 12;

        MethodDefinition MakeBinaryHandler(string name, Action<CilMethodBody> emitCore) {
            var core = new MethodDefinition($"{name}_C", MethodAttributes.Private, MethodSignature.CreateInstance(int32Type, [int32Type, int32Type]));
            var cb = new CilMethodBody();
            emitCore(cb);
            core.CilMethodBody = cb;
            vmType.Methods.Add(core);

            // Real executable stack order: int rhs = Po(); int lhs = Po(); Pu(core(lhs, rhs));
            var h = new MethodDefinition(name, MethodAttributes.Private, MethodSignature.CreateInstance(voidType));
            var hb = new CilMethodBody { InitializeLocals = true };
            var rhs = new CilLocalVariable(int32Type);
            var lhs = new CilLocalVariable(int32Type);
            hb.LocalVariables.Add(rhs);
            hb.LocalVariables.Add(lhs);
            hb.Instructions.Add(CilOpCodes.Ldarg_0); hb.Instructions.Add(CilOpCodes.Call, pop); hb.Instructions.Add(CilOpCodes.Stloc, rhs);
            hb.Instructions.Add(CilOpCodes.Ldarg_0); hb.Instructions.Add(CilOpCodes.Call, pop); hb.Instructions.Add(CilOpCodes.Stloc, lhs);
            hb.Instructions.Add(CilOpCodes.Ldarg_0);
            hb.Instructions.Add(CilOpCodes.Ldarg_0);
            hb.Instructions.Add(CilOpCodes.Ldloc, lhs);
            hb.Instructions.Add(CilOpCodes.Ldloc, rhs);
            hb.Instructions.Add(CilOpCodes.Call, core);
            hb.Instructions.Add(CilOpCodes.Call, push);
            hb.Instructions.Add(CilOpCodes.Ret);
            h.CilMethodBody = hb;
            vmType.Methods.Add(h);
            return h;
        }

        MethodDefinition MakeSimpleHandler(string name, Action<CilMethodBody> emit) {
            var h = new MethodDefinition(name, MethodAttributes.Private, MethodSignature.CreateInstance(voidType));
            var hb = new CilMethodBody();
            emit(hb);
            hb.Instructions.Add(CilOpCodes.Ret);
            h.CilMethodBody = hb;
            vmType.Methods.Add(h);
            return h;
        }

        var handlers = new Dictionary<byte, MethodDefinition> {
            [OP_LDC] = MakeSimpleHandler("Op_1", b => {
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, readI4);
                b.Instructions.Add(CilOpCodes.Call, push);
            }),
            [OP_LDARG] = MakeSimpleHandler("Op_2", b => {
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, getArg);
                b.Instructions.Add(CilOpCodes.Call, push);
            }),
            [OP_LDLOC] = MakeSimpleHandler("Op_3", b => {
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, getLoc);
                b.Instructions.Add(CilOpCodes.Call, push);
            }),
            [OP_STLOC] = MakeSimpleHandler("Op_4", b => {
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, pop);
                b.Instructions.Add(CilOpCodes.Call, setLoc);
            }),
            [OP_BR] = MakeSimpleHandler("Op_5", b => {
                b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, jump);
            }),
            [OP_BRFALSE] = MakeSimpleHandler("Op_6", b => {
                b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, jumpFalse);
            }),
            [OP_RET] = MakeSimpleHandler("Op_7", b => {
                b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Call, halt);
            }),
            // Polymorphic Add: a - (-b)
            [OP_ADD] = MakeBinaryHandler("Op_8", cb => {
                cb.Instructions.Add(CilOpCodes.Ldarg_1);
                cb.Instructions.Add(CilOpCodes.Ldarg_2);
                cb.Instructions.Add(CilOpCodes.Neg);
                cb.Instructions.Add(CilOpCodes.Sub);
                cb.Instructions.Add(CilOpCodes.Ret);
            }),
            [OP_SUB] = MakeBinaryHandler("Op_9", cb => {
                cb.Instructions.Add(CilOpCodes.Ldarg_1); cb.Instructions.Add(CilOpCodes.Ldarg_2);
                cb.Instructions.Add(CilOpCodes.Sub); cb.Instructions.Add(CilOpCodes.Ret);
            }),
            [OP_MUL] = MakeBinaryHandler("Op_10", cb => {
                cb.Instructions.Add(CilOpCodes.Ldarg_1); cb.Instructions.Add(CilOpCodes.Ldarg_2);
                cb.Instructions.Add(CilOpCodes.Mul); cb.Instructions.Add(CilOpCodes.Ret);
            }),
            // Polymorphic Xor: (a | b) - (a & b)
            [OP_XOR] = MakeBinaryHandler("Op_11", cb => {
                cb.Instructions.Add(CilOpCodes.Ldarg_1); cb.Instructions.Add(CilOpCodes.Ldarg_2); cb.Instructions.Add(CilOpCodes.Or);
                cb.Instructions.Add(CilOpCodes.Ldarg_1); cb.Instructions.Add(CilOpCodes.Ldarg_2); cb.Instructions.Add(CilOpCodes.And);
                cb.Instructions.Add(CilOpCodes.Sub); cb.Instructions.Add(CilOpCodes.Ret);
            }),
            [OP_CLT] = MakeBinaryHandler("Op_12", cb => {
                cb.Instructions.Add(CilOpCodes.Ldarg_1); cb.Instructions.Add(CilOpCodes.Ldarg_2);
                cb.Instructions.Add(CilOpCodes.Clt); cb.Instructions.Add(CilOpCodes.Ret);
            })
        };

        // VM .ctor: registers all 12 handlers into _dispatch = new VmOp[16]
        var vmCtor = new MethodDefinition(".ctor",
            MethodAttributes.Public | MethodAttributes.HideBySig | MethodAttributes.SpecialName | MethodAttributes.RuntimeSpecialName,
            MethodSignature.CreateInstance(voidType));
        vmType.Methods.Add(vmCtor);
        {
            var b = new CilMethodBody();
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Call, objectCtor);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldc_I4, 16);
            b.Instructions.Add(CilOpCodes.Newarr, delType);
            b.Instructions.Add(CilOpCodes.Stfld, dispatchField);

            foreach (var (key, hm) in handlers) {
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldfld, dispatchField);
                b.Instructions.Add(CilOpCodes.Ldc_I4, (int)key);
                b.Instructions.Add(CilOpCodes.Ldarg_0);
                b.Instructions.Add(CilOpCodes.Ldftn, hm);
                b.Instructions.Add(CilOpCodes.Newobj, delCtor);
                b.Instructions.Add(CilOpCodes.Stelem_Ref);
            }
            b.Instructions.Add(CilOpCodes.Ret);
            vmCtor.CilMethodBody = b;
        }

        // Real executable VM entry method: public object Execute(object[] args, int offset)
        var execMethod = new MethodDefinition("Execute",
            MethodAttributes.Public | MethodAttributes.HideBySig,
            MethodSignature.CreateInstance(objType, [objArrayType, int32Type]));
        vmType.Methods.Add(execMethod);
        {
            var b = new CilMethodBody { InitializeLocals = true };
            var msLoc = new CilLocalVariable(importer.ImportTypeSignature(typeof(MemoryStream)));
            var localCountLoc = new CilLocalVariable(int32Type);
            var insnCountLoc = new CilLocalVariable(int32Type);
            var vIpOffsetsLoc = new CilLocalVariable(intArrayType);
            var posLoc = new CilLocalVariable(int32Type);
            var iLoc = new CilLocalVariable(int32Type);
            var opLoc = new CilLocalVariable(int32Type);
            b.LocalVariables.Add(msLoc);
            b.LocalVariables.Add(localCountLoc);
            b.LocalVariables.Add(insnCountLoc);
            b.LocalVariables.Add(vIpOffsetsLoc);
            b.LocalVariables.Add(posLoc);
            b.LocalVariables.Add(iLoc);
            b.LocalVariables.Add(opLoc);

            // Load embedded "VmBytecode" resource into _code
            b.Instructions.Add(CilOpCodes.Newobj, memStreamCtor);
            b.Instructions.Add(CilOpCodes.Stloc, msLoc);
            b.Instructions.Add(CilOpCodes.Call, asmGetExec);
            b.Instructions.Add(CilOpCodes.Ldstr, "VmBytecode");
            b.Instructions.Add(CilOpCodes.Callvirt, asmGetResStream);
            b.Instructions.Add(CilOpCodes.Ldloc, msLoc);
            b.Instructions.Add(CilOpCodes.Callvirt, streamCopyTo);
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldloc, msLoc);
            b.Instructions.Add(CilOpCodes.Callvirt, memStreamToArray);
            b.Instructions.Add(CilOpCodes.Stfld, codeField);

            // localCount = ToInt32(_code, offset); insnCount = ToInt32(_code, offset + 4);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, codeField);
            b.Instructions.Add(CilOpCodes.Ldarg_2);
            b.Instructions.Add(CilOpCodes.Call, bitConvToInt32);
            b.Instructions.Add(CilOpCodes.Stloc, localCountLoc);

            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, codeField);
            b.Instructions.Add(CilOpCodes.Ldarg_2); b.Instructions.Add(CilOpCodes.Ldc_I4_4); b.Instructions.Add(CilOpCodes.Add);
            b.Instructions.Add(CilOpCodes.Call, bitConvToInt32);
            b.Instructions.Add(CilOpCodes.Stloc, insnCountLoc);

            // Initialize _locals, _stack, _sp=0, _args=args, _halted=false
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldloc, localCountLoc); b.Instructions.Add(CilOpCodes.Newarr, int32Type.ToTypeDefOrRef()); b.Instructions.Add(CilOpCodes.Stfld, localsField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldc_I4, 64); b.Instructions.Add(CilOpCodes.Newarr, int32Type.ToTypeDefOrRef()); b.Instructions.Add(CilOpCodes.Stfld, stackField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldc_I4_0); b.Instructions.Add(CilOpCodes.Stfld, spField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldarg_1); b.Instructions.Add(CilOpCodes.Stfld, argsField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldc_I4_0); b.Instructions.Add(CilOpCodes.Stfld, haltedField);

            // Pre-scan vIpOffsets[0..insnCount-1]: opcodes 1..6 take a 4-byte operand (5 bytes total), 7..12 take 0 bytes (1 byte total)
            b.Instructions.Add(CilOpCodes.Ldloc, insnCountLoc);
            b.Instructions.Add(CilOpCodes.Newarr, int32Type.ToTypeDefOrRef());
            b.Instructions.Add(CilOpCodes.Stloc, vIpOffsetsLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_2); b.Instructions.Add(CilOpCodes.Ldc_I4, 12); b.Instructions.Add(CilOpCodes.Add); b.Instructions.Add(CilOpCodes.Stloc, posLoc);
            b.Instructions.Add(CilOpCodes.Ldc_I4_0); b.Instructions.Add(CilOpCodes.Stloc, iLoc);

            var scanCheck = new CilInstruction(CilOpCodes.Ldloc, iLoc);
            var scanBody = new CilInstruction(CilOpCodes.Ldloc, vIpOffsetsLoc);
            var scanNoOperand = new CilInstruction(CilOpCodes.Ldloc, posLoc);
            var scanNext = new CilInstruction(CilOpCodes.Ldloc, iLoc);

            b.Instructions.Add(CilOpCodes.Br, scanCheck.CreateLabel());
            b.Instructions.Add(scanBody);
            b.Instructions.Add(CilOpCodes.Ldloc, iLoc);
            b.Instructions.Add(CilOpCodes.Ldloc, posLoc);
            b.Instructions.Add(CilOpCodes.Stelem_I4);
            // op = _code[pos]
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, codeField);
            b.Instructions.Add(CilOpCodes.Ldloc, posLoc);
            b.Instructions.Add(CilOpCodes.Ldelem_U1);
            b.Instructions.Add(CilOpCodes.Stloc, opLoc);
            // if (op > 6) pos += 1 else pos += 5
            b.Instructions.Add(CilOpCodes.Ldloc, opLoc);
            b.Instructions.Add(CilOpCodes.Ldc_I4_6);
            b.Instructions.Add(CilOpCodes.Bgt, scanNoOperand.CreateLabel());
            b.Instructions.Add(CilOpCodes.Ldloc, posLoc); b.Instructions.Add(CilOpCodes.Ldc_I4_5); b.Instructions.Add(CilOpCodes.Add); b.Instructions.Add(CilOpCodes.Stloc, posLoc);
            b.Instructions.Add(CilOpCodes.Br, scanNext.CreateLabel());
            b.Instructions.Add(scanNoOperand);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1); b.Instructions.Add(CilOpCodes.Add); b.Instructions.Add(CilOpCodes.Stloc, posLoc);
            b.Instructions.Add(scanNext);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1); b.Instructions.Add(CilOpCodes.Add); b.Instructions.Add(CilOpCodes.Stloc, iLoc);
            b.Instructions.Add(scanCheck);
            b.Instructions.Add(CilOpCodes.Ldloc, insnCountLoc);
            b.Instructions.Add(CilOpCodes.Blt, scanBody.CreateLabel());

            // _ip = offset + 12
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_2); b.Instructions.Add(CilOpCodes.Ldc_I4, 12); b.Instructions.Add(CilOpCodes.Add);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);

            // Interpreter loop: while (!_halted) { op = _code[_ip++]; _dispatch[op](); if (_ip < 128) _ip = vIpOffsets[_ip]; }
            var loopCheck = new CilInstruction(CilOpCodes.Ldarg_0);
            var loopBody = new CilInstruction(CilOpCodes.Ldarg_0);
            var afterJumpMap = new CilInstruction(CilOpCodes.Nop);

            b.Instructions.Add(CilOpCodes.Br, loopCheck.CreateLabel());
            b.Instructions.Add(loopBody);
            b.Instructions.Add(CilOpCodes.Ldfld, codeField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, ipField);
            b.Instructions.Add(CilOpCodes.Ldelem_U1);
            b.Instructions.Add(CilOpCodes.Stloc, opLoc);

            // _ip += 1
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, ipField);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1); b.Instructions.Add(CilOpCodes.Add);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);

            // _dispatch[op].Invoke()
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, dispatchField);
            b.Instructions.Add(CilOpCodes.Ldloc, opLoc);
            b.Instructions.Add(CilOpCodes.Ldelem_Ref);
            b.Instructions.Add(CilOpCodes.Callvirt, delInvoke);

            // If a jump handler wrote a vIP (< 128), translate _ip = vIpOffsets[_ip]
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, ipField);
            b.Instructions.Add(CilOpCodes.Ldc_I4, 128);
            b.Instructions.Add(CilOpCodes.Bge, afterJumpMap.CreateLabel());
            b.Instructions.Add(CilOpCodes.Ldarg_0);
            b.Instructions.Add(CilOpCodes.Ldloc, vIpOffsetsLoc);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, ipField);
            b.Instructions.Add(CilOpCodes.Ldelem_I4);
            b.Instructions.Add(CilOpCodes.Stfld, ipField);
            b.Instructions.Add(afterJumpMap);

            b.Instructions.Add(loopCheck);
            b.Instructions.Add(CilOpCodes.Ldfld, haltedField);
            b.Instructions.Add(CilOpCodes.Brfalse, loopBody.CreateLabel());

            // return (object)_stack[_sp - 1]
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, stackField);
            b.Instructions.Add(CilOpCodes.Ldarg_0); b.Instructions.Add(CilOpCodes.Ldfld, spField);
            b.Instructions.Add(CilOpCodes.Ldc_I4_1); b.Instructions.Add(CilOpCodes.Sub);
            b.Instructions.Add(CilOpCodes.Ldelem_I4);
            b.Instructions.Add(CilOpCodes.Box, int32Type.ToTypeDefOrRef());
            b.Instructions.Add(CilOpCodes.Ret);

            execMethod.CilMethodBody = b;
        }

        // Encode bytecode starting at offset 128 (so all live byte offsets are >= 140 while vIPs are < 128)
        using var blobMs = new MemoryStream();
        using var bw = new BinaryWriter(blobMs);
        bw.Write(new byte[128]);

        // Method 1: MixAccumulate(int n, int seed)
        // locals: 0=acc, 1=i
        int mixOffset = (int)blobMs.Position;
        (byte Op, int? Arg)[] mixOps = [
            (OP_LDARG, 1),    // 0: seed
            (OP_STLOC, 0),    // 1: acc = seed
            (OP_LDC, 0),      // 2: 0
            (OP_STLOC, 1),    // 3: i = 0
            (OP_LDLOC, 1),    // 4: loop: i
            (OP_LDARG, 0),    // 5: n
            (OP_CLT, null),   // 6: i < n
            (OP_BRFALSE, 20), // 7: if !(i < n) goto 20
            (OP_LDLOC, 0),    // 8: acc
            (OP_LDLOC, 1),    // 9: i
            (OP_ADD, null),   // 10: acc + i
            (OP_LDARG, 1),    // 11: seed
            (OP_LDLOC, 1),    // 12: i
            (OP_SUB, null),   // 13: seed - i
            (OP_XOR, null),   // 14: (acc + i) ^ (seed - i)
            (OP_STLOC, 0),    // 15: acc = ...
            (OP_LDLOC, 1),    // 16: i
            (OP_LDC, 1),      // 17: 1
            (OP_ADD, null),   // 18: i + 1
            (OP_STLOC, 1),    // 19: i = i + 1 -- wait, need BR 4! Let's fix indices below!
        ];
        // Clean exact indices for MixAccumulate:
        mixOps = [
            (OP_LDARG, 1),    // 0
            (OP_STLOC, 0),    // 1
            (OP_LDC, 0),      // 2
            (OP_STLOC, 1),    // 3
            (OP_LDLOC, 1),    // 4: loop
            (OP_LDARG, 0),    // 5
            (OP_CLT, null),   // 6
            (OP_BRFALSE, 21), // 7: exit -> 21
            (OP_LDLOC, 0),    // 8
            (OP_LDLOC, 1),    // 9
            (OP_ADD, null),   // 10
            (OP_LDARG, 1),    // 11
            (OP_LDLOC, 1),    // 12
            (OP_SUB, null),   // 13
            (OP_XOR, null),   // 14
            (OP_STLOC, 0),    // 15
            (OP_LDLOC, 1),    // 16
            (OP_LDC, 1),      // 17
            (OP_ADD, null),   // 18
            (OP_STLOC, 1),    // 19
            (OP_BR, 4),       // 20: loop back
            (OP_LDLOC, 0),    // 21: return acc
            (OP_RET, null),   // 22
        ];
        WriteMethodBytecode(bw, localCount: 2, mixOps);

        // Method 2: PolyBlend(int a, int b)
        // locals: 0=sum, 1=diff
        int blendOffset = (int)blobMs.Position;
        (byte Op, int? Arg)[] blendOps = [
            (OP_LDARG, 0),    // 0: a
            (OP_LDARG, 1),    // 1: b
            (OP_ADD, null),   // 2: a + b
            (OP_STLOC, 0),    // 3: sum
            (OP_LDARG, 0),    // 4: a
            (OP_LDARG, 1),    // 5: b
            (OP_SUB, null),   // 6: a - b
            (OP_STLOC, 1),    // 7: diff
            (OP_LDLOC, 0),    // 8: sum
            (OP_LDLOC, 1),    // 9: diff
            (OP_CLT, null),   // 10: sum < diff
            (OP_BRFALSE, 18), // 11: else -> 18
            (OP_LDLOC, 0),    // 12: sum
            (OP_LDC, 5),      // 13: 5
            (OP_MUL, null),   // 14: sum * 5
            (OP_LDLOC, 1),    // 15: diff
            (OP_XOR, null),   // 16: (sum * 5) ^ diff
            (OP_RET, null),   // 17
            (OP_LDLOC, 1),    // 18: diff
            (OP_LDC, 3),      // 19: 3
            (OP_MUL, null),   // 20: diff * 3
            (OP_LDLOC, 0),    // 21: sum
            (OP_ADD, null),   // 22: (diff * 3) + sum
            (OP_RET, null),   // 23
        ];
        WriteMethodBytecode(bw, localCount: 2, blendOps);

        module.Resources.Add(new ManifestResource("VmBytecode", ManifestResourceAttributes.Public, new DataSegment(blobMs.ToArray())));

        // Virtualized target methods
        var targetType = new TypeDefinition("AuditMiniVm", "VirtualizedSuite",
            TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed, importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(targetType);

        void EmitStub(string name, int bytecodeOffset) {
            var m = new MethodDefinition(name, MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
                MethodSignature.CreateStatic(int32Type, [int32Type, int32Type]));
            targetType.Methods.Add(m);

            var sb = new CilMethodBody { InitializeLocals = true };
            var arrLoc = new CilLocalVariable(objArrayType);
            sb.LocalVariables.Add(arrLoc);

            sb.Instructions.Add(CilOpCodes.Ldc_I4_2);
            sb.Instructions.Add(CilOpCodes.Newarr, objType.ToTypeDefOrRef());
            sb.Instructions.Add(CilOpCodes.Stloc, arrLoc);

            sb.Instructions.Add(CilOpCodes.Ldloc, arrLoc);
            sb.Instructions.Add(CilOpCodes.Ldc_I4_0);
            sb.Instructions.Add(CilOpCodes.Ldarg_0);
            sb.Instructions.Add(CilOpCodes.Box, int32Type.ToTypeDefOrRef());
            sb.Instructions.Add(CilOpCodes.Stelem_Ref);

            sb.Instructions.Add(CilOpCodes.Ldloc, arrLoc);
            sb.Instructions.Add(CilOpCodes.Ldc_I4_1);
            sb.Instructions.Add(CilOpCodes.Ldarg_1);
            sb.Instructions.Add(CilOpCodes.Box, int32Type.ToTypeDefOrRef());
            sb.Instructions.Add(CilOpCodes.Stelem_Ref);

            sb.Instructions.Add(CilOpCodes.Newobj, vmCtor);
            sb.Instructions.Add(CilOpCodes.Ldloc, arrLoc);
            sb.Instructions.Add(CilOpCodes.Ldc_I4, bytecodeOffset);
            sb.Instructions.Add(CilOpCodes.Callvirt, execMethod);
            sb.Instructions.Add(CilOpCodes.Unbox_Any, int32Type.ToTypeDefOrRef());
            sb.Instructions.Add(CilOpCodes.Ret);

            m.CilMethodBody = sb;
            sb.ComputeMaxStack();
        }

        EmitStub("MixAccumulate", mixOffset);
        EmitStub("PolyBlend", blendOffset);

        foreach (var t in module.GetAllTypes()) {
            foreach (var m in t.Methods) {
                m.CilMethodBody?.ComputeMaxStack();
            }
        }

        module.Write(outputPath);
    }

    private static void WriteMethodBytecode(BinaryWriter bw, int localCount, (byte Op, int? Arg)[] ops) {
        bw.Write(localCount);
        bw.Write(ops.Length);
        bw.Write(0); // ehCount
        foreach (var (op, arg) in ops) {
            bw.Write(op);
            if (arg.HasValue)
                bw.Write(arg.Value);
        }
    }

    /// <summary>
    /// Independently builds a CLR-executable CFF-flattened method with a loop, conditional branch, and algebraic opaque predicate.
    /// </summary>
    private static (ModuleDefinition Module, MethodDefinition Method) BuildExecutableCffLoopModule() {
        var module = CreateFreshNet8Module("AuditCff");
        var importer = module.DefaultImporter;
        var int32 = module.CorLibTypeFactory.Int32;

        var type = new TypeDefinition("AuditCff", "LoopTarget",
            TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed, importer.ImportType(typeof(object)));
        module.TopLevelTypes.Add(type);

        var method = new MethodDefinition("Run",
            MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig,
            MethodSignature.CreateStatic(int32, [int32, int32]));
        type.Methods.Add(method);

        const int xorKey = 0x5A17_9C31;
        var body = new CilMethodBody { InitializeLocals = true };
        var stateVar = new CilLocalVariable(int32);
        var accVar = new CilLocalVariable(int32);
        var iVar = new CilLocalVariable(int32);
        body.LocalVariables.Add(stateVar);
        body.LocalVariables.Add(accVar);
        body.LocalVariables.Add(iVar);

        var dispatch = new CilInstruction(CilOpCodes.Ldloc, stateVar);
        var s0Init = new CilInstruction(CilOpCodes.Nop);
        var s1LoopCond = new CilInstruction(CilOpCodes.Nop);
        var s2Even = new CilInstruction(CilOpCodes.Nop);
        var s3Odd = new CilInstruction(CilOpCodes.Nop);
        var s4Inc = new CilInstruction(CilOpCodes.Nop);
        var s5Ret = new CilInstruction(CilOpCodes.Nop);

        // Initial state -> case 0
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0 ^ xorKey);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);

        // Dispatcher: switch (state ^ xorKey)
        body.Instructions.Add(dispatch);
        body.Instructions.Add(CilOpCodes.Ldc_I4, xorKey);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Switch, new List<ICilLabel> {
            s0Init.CreateLabel(), s1LoopCond.CreateLabel(), s2Even.CreateLabel(),
            s3Odd.CreateLabel(), s4Inc.CreateLabel(), s5Ret.CreateLabel()
        });
        body.Instructions.Add(CilOpCodes.Ldc_I4_M1);
        body.Instructions.Add(CilOpCodes.Ret);

        // Case 0: acc = k ^ 0x5A; i = 0; state = 1 ^ xorKey; br dispatch
        body.Instructions.Add(s0Init);
        body.Instructions.Add(CilOpCodes.Ldarg_1);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 0x5A);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Stloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_0);
        body.Instructions.Add(CilOpCodes.Stloc, iVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 1 ^ xorKey);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatch.CreateLabel());

        // Case 1: if (i < n) { if ((i & 1) == 0) state = 2 else state = 3 } else state = 5
        var gotoExit = new CilInstruction(CilOpCodes.Ldc_I4, 5 ^ xorKey);
        var gotoOdd = new CilInstruction(CilOpCodes.Ldc_I4, 3 ^ xorKey);
        body.Instructions.Add(s1LoopCond);
        body.Instructions.Add(CilOpCodes.Ldloc, iVar);
        body.Instructions.Add(CilOpCodes.Ldarg_0);
        body.Instructions.Add(CilOpCodes.Bge, gotoExit.CreateLabel());
        body.Instructions.Add(CilOpCodes.Ldloc, iVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_1);
        body.Instructions.Add(CilOpCodes.And);
        body.Instructions.Add(CilOpCodes.Brtrue, gotoOdd.CreateLabel());
        body.Instructions.Add(CilOpCodes.Ldc_I4, 2 ^ xorKey);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatch.CreateLabel());
        body.Instructions.Add(gotoOdd);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatch.CreateLabel());
        body.Instructions.Add(gotoExit);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatch.CreateLabel());

        // Case 2: acc = acc + (i * 3); state = 4 ^ xorKey; br dispatch
        body.Instructions.Add(s2Even);
        body.Instructions.Add(CilOpCodes.Ldloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldloc, iVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_3);
        body.Instructions.Add(CilOpCodes.Mul);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Stloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 4 ^ xorKey);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatch.CreateLabel());

        // Case 3: acc = acc ^ (i + k); state = 4 ^ xorKey; br dispatch
        body.Instructions.Add(s3Odd);
        body.Instructions.Add(CilOpCodes.Ldloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldloc, iVar);
        body.Instructions.Add(CilOpCodes.Ldarg_1);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Xor);
        body.Instructions.Add(CilOpCodes.Stloc, accVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 4 ^ xorKey);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatch.CreateLabel());

        // Case 4: i = i + 1; state = 1 ^ xorKey; br dispatch
        body.Instructions.Add(s4Inc);
        body.Instructions.Add(CilOpCodes.Ldloc, iVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4_1);
        body.Instructions.Add(CilOpCodes.Add);
        body.Instructions.Add(CilOpCodes.Stloc, iVar);
        body.Instructions.Add(CilOpCodes.Ldc_I4, 1 ^ xorKey);
        body.Instructions.Add(CilOpCodes.Stloc, stateVar);
        body.Instructions.Add(CilOpCodes.Br, dispatch.CreateLabel());

        // Case 5: return acc
        body.Instructions.Add(s5Ret);
        body.Instructions.Add(CilOpCodes.Ldloc, accVar);
        body.Instructions.Add(CilOpCodes.Ret);

        method.CilMethodBody = body;
        return (module, method);
    }

    private static (string FileName, string[] PrefixArgs) ResolveOrBuildCli(string workDir) {
        string repoRoot = FindRepoRoot();
        string cliProj = Path.Combine(repoRoot, "de4vmp", "de4vmp.csproj");
        Assert.True(File.Exists(cliProj), $"Could not locate CLI project at {cliProj}");

        string exeName = OperatingSystem.IsWindows() ? "de4vmp.exe" : "de4vmp";
        string prebuiltExe = Path.Combine(repoRoot, "de4vmp", "bin", "Release", "net8.0", exeName);
        if (File.Exists(prebuiltExe)) {
            return (prebuiltExe, []);
        }

        string prebuiltDll = Path.Combine(repoRoot, "de4vmp", "bin", "Release", "net8.0", "de4vmp.dll");
        if (File.Exists(prebuiltDll)) {
            return ("dotnet", [prebuiltDll]);
        }

        // Build CLI into an isolated temp output directory if not already built
        string cliOutDir = Path.Combine(workDir, "cli-build");
        var buildRes = RunProcess("dotnet", ["build", cliProj, "-c", "Release", "-o", cliOutDir, "--nologo"]);
        Assert.True(buildRes.ExitCode == 0, $"Failed to build CLI:\nSTDOUT:\n{buildRes.StdOut}\nSTDERR:\n{buildRes.StdErr}");

        string builtExe = Path.Combine(cliOutDir, exeName);
        if (File.Exists(builtExe))
            return (builtExe, []);

        return ("dotnet", [Path.Combine(cliOutDir, "de4vmp.dll")]);
    }

    private static string FindRepoRoot() {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null) {
            if (File.Exists(Path.Combine(dir.FullName, "de4vmp.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate repository root containing de4vmp.sln");
    }

    private static (int ExitCode, string StdOut, string StdErr) RunProcess(string fileName, string[] args) {
        var psi = new ProcessStartInfo {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (string a in args)
            psi.ArgumentList.Add(a);

        using var proc = Process.Start(psi)!;
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        Assert.True(proc.WaitForExit(60_000), $"Process '{fileName}' timed out.");
        return (proc.ExitCode, stdout, stderr);
    }

    private static string CreateTempDir(string tag) {
        string dir = Path.Combine(Path.GetTempPath(), "de4vmp-v2-indep-audit", $"{tag}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void SafeDeleteDir(string dir) {
        try { Directory.Delete(dir, recursive: true); } catch { }
    }
}
